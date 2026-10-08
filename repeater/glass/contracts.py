"""Offline stdlib mirror of Glass app/contracts/v2; no transport or dispatch.

Validate through constructors or model_validate. The small model_validate/dump
API supports cross-repository parity without implementing Pydantic or JSON Schema.
Opaque JSON is data, not authority. Context helpers do not authenticate or persist.
"""

import json
import math
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any
from uuid import UUID

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_DETAIL_BYTES = 64 * 1024
MAX_DEPTH = 16
MAX_NODES = 4096
ACTION_VERSIONS = MappingProxyType({"diagnostic.read": 1, "config.read": 1, "set_mode": 1})


def checked_json(value, *, byte_limit=MAX_ENVELOPE_BYTES, json_only=False):
    """Bound traversal before encoding; count values/containers, not keys."""
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("JSON depth/node budget exceeded")
        if isinstance(item, Contract) and not json_only:
            item = item.model_dump(mode="json")
        if isinstance(item, (UUID, datetime)) and not json_only:
            return str(item) if isinstance(item, UUID) else item.isoformat()
        if item is None or type(item) in (bool, int, str):
            if isinstance(item, str) and len(item) > byte_limit:
                raise ValueError("JSON byte budget exceeded")
            return item
        if type(item) is float and math.isfinite(item):
            return item
        if type(item) is list or (type(item) is tuple and not json_only):
            return [visit(child, depth + 1) for child in item]
        if type(item) is dict or (isinstance(item, MappingProxyType) and not json_only):
            if not all(type(key) is str for key in item):
                raise ValueError("JSON object keys must be strings")
            return {key: visit(child, depth + 1) for key, child in item.items()}
        raise ValueError("not a finite JSON value")

    normalized = visit(value, 0)
    try:
        size = len(
            json.dumps(
                normalized, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
        )
    except (ValueError, OverflowError, UnicodeError) as exc:
        raise ValueError("invalid JSON encoding") from exc
    if size > byte_limit:
        raise ValueError("JSON byte budget exceeded")
    return value


def uuid_value(value):
    if isinstance(value, UUID):
        return value
    if type(value) is not str:
        raise ValueError("UUID must be a canonical string")
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("UUID must use lowercase canonical hyphenated form")
    return parsed


def utc_value(value):
    if type(value) is str:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("timestamp must be UTC aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must have UTC offset zero")
    return value


def text(value, minimum=1, maximum=64):
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise ValueError("invalid string type/length")
    return value


def resource_id(value):
    text(value)
    if re.fullmatch(r"[A-Za-z0-9_.:-]+", value) is None:
        raise ValueError("invalid ASCII resource ID")
    return value


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid integer type/range")
    return value


def positive_version(value):
    return integer(value, 1, 65535)


def boolean(value):
    if type(value) is not bool:
        raise ValueError("expected strict boolean")
    return value


def literal(*values):
    def validate(value):
        if type(value) is not type(values[0]) or value not in values:
            raise ValueError("unknown literal/version/action")
        return value

    return validate


def nullable(validate):
    return lambda value: None if value is None else validate(value)


def pubkey(value):
    if type(value) is not str or re.fullmatch(r"0x[0-9a-f]{64}", value) is None:
        raise ValueError("invalid public key metadata")
    return value


def json_object(value, *, byte_limit=MAX_ENVELOPE_BYTES):
    if type(value) is not dict:
        raise ValueError("expected JSON object")
    checked_json(value, byte_limit=byte_limit, json_only=True)
    return deepcopy(value)


def details(value):
    return json_object(value, byte_limit=MAX_DETAIL_BYTES)


def capabilities(value):
    if type(value) is not dict or len(value) > 128:
        raise ValueError("expected bounded capabilities object")
    return MappingProxyType({resource_id(key): positive_version(ver) for key, ver in value.items()})


def array(model, maximum):
    def validate(value):
        if type(value) not in (list, tuple) or len(value) > maximum:
            raise ValueError("expected bounded array")
        return tuple(model.model_validate(entry) for entry in value)

    return validate


def unique(values):
    if len(set(values)) != len(values):
        raise ValueError("duplicate resource/request identity")


def _validate_fields(raw, validators):
    """Explicit per-record field validators, never inferred from type annotations."""
    return {key: validators[key](value) for key, value in raw.items()}


@dataclass(frozen=True)
class Contract:
    def __post_init__(self):
        raw = {f.name: getattr(self, f.name) for f in fields(self)}
        checked_json(raw)
        normalized = self._validate(raw)
        for key, value in normalized.items():
            object.__setattr__(self, key, value)
        checked_json(self.model_dump(mode="json"))

    @classmethod
    def model_validate(cls, raw):
        if type(raw) is cls:
            return raw
        if type(raw) is not dict:
            raise ValueError("contract must be an object")
        checked_json(raw)
        names = {f.name for f in fields(cls)}
        if raw.keys() - names:
            raise ValueError("unknown contract field")
        try:
            return cls(**raw)
        except TypeError as exc:
            raise ValueError("missing/invalid contract field") from exc

    def model_dump(self, *, mode="python"):
        if mode not in {"python", "json"}:
            raise ValueError("unsupported dump mode")

        def dump(value):
            if isinstance(value, Contract):
                return {f.name: dump(getattr(value, f.name)) for f in fields(value)}
            if isinstance(value, Mapping):
                return {k: dump(v) for k, v in value.items()}
            if type(value) in (tuple, list):
                items = [dump(v) for v in value]
                return tuple(items) if mode == "python" and type(value) is tuple else items
            if mode == "json" and isinstance(value, UUID):
                return str(value)
            if mode == "json" and isinstance(value, datetime):
                return value.isoformat().replace("+00:00", "Z")
            return value

        return dump(self)

    def model_dump_json(self):
        return json.dumps(
            self.model_dump(mode="json"), ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )


@dataclass(frozen=True)
class DeviceIdentityV2(Contract):
    device_id: UUID
    node_name: str
    pubkey: str | None = None

    def _validate(self, raw):
        return _validate_fields(
            raw, {"device_id": uuid_value, "node_name": text, "pubkey": nullable(pubkey)}
        )


@dataclass(frozen=True)
class RadioV2(Contract):
    id: str
    enabled: bool
    radio_type: str | None = None

    def _validate(self, raw):
        return _validate_fields(
            raw, {"id": resource_id, "enabled": boolean, "radio_type": nullable(resource_id)}
        )


@dataclass(frozen=True)
class IdentityV2(Contract):
    id: str
    kind: str

    def _validate(self, raw):
        return _validate_fields(
            raw, {"id": resource_id, "kind": literal("repeater", "room", "companion")}
        )


@dataclass(frozen=True)
class SensorV2(Contract):
    id: str
    sensor_type: str
    plugin_id: str | None = None

    def _validate(self, raw):
        return _validate_fields(
            raw, {"id": resource_id, "sensor_type": resource_id, "plugin_id": nullable(resource_id)}
        )


@dataclass(frozen=True)
class PluginV2(Contract):
    id: str
    version: str

    def _validate(self, raw):
        return _validate_fields(raw, {"id": resource_id, "version": text})


@dataclass(frozen=True)
class InventoryV2(Contract):
    radios: tuple[RadioV2, ...]
    identities: tuple[IdentityV2, ...]
    sensors: tuple[SensorV2, ...]
    plugins: tuple[PluginV2, ...]

    def _validate(self, raw):
        result = _validate_fields(
            raw,
            {
                "radios": array(RadioV2, 32),
                "identities": array(IdentityV2, 128),
                "sensors": array(SensorV2, 128),
                "plugins": array(PluginV2, 128),
            },
        )
        for entries in result.values():
            unique([entry.id for entry in entries])
        plugin_ids = {entry.id for entry in result["plugins"]}
        if any(
            s.plugin_id is not None and s.plugin_id not in plugin_ids for s in result["sensors"]
        ):
            raise ValueError("sensor plugin_id must reference an inventoried plugin")
        return result


_ENVELOPE = {"version": literal(2), "device_id": uuid_value}
_REQUEST = {
    **_ENVELOPE,
    "request_id": uuid_value,
    "capability_version": positive_version,
    "created_at": utc_value,
    "expires_at": utc_value,
    "params": details,
    "expected_revision": nullable(text),
}


@dataclass(frozen=True)
class RequestV2(Contract):
    type: str
    version: int
    device_id: UUID
    request_id: UUID
    action: str
    capability_version: int
    created_at: datetime
    expires_at: datetime
    params: dict[str, Any]
    expected_revision: str | None = field(default=None, kw_only=True)

    def _request(self, raw, validators):
        result = _validate_fields(raw, validators)
        if result["expires_at"] <= result["created_at"]:
            raise ValueError("expires_at must be after created_at")
        if result["capability_version"] != ACTION_VERSIONS[result["action"]]:
            raise ValueError("incompatible action capability version")
        params = result["params"]
        if result["action"] == "set_mode":
            if set(params) != {"mode"}:
                raise ValueError("set_mode requires exactly mode")
            literal("forward", "monitor", "no_tx")(params["mode"])
        elif params:
            raise ValueError("read actions have no params")
        return result

    def check_acceptance(self, *, device_id, capabilities, now):
        now = utc_value(now)
        if uuid_value(device_id) != self.device_id:
            raise ValueError("device identity mismatch")
        version = capabilities.get(self.action)
        if type(version) is not int or version != self.capability_version:
            raise ValueError("required capability absent or incompatible")
        if not self.created_at <= now < self.expires_at:
            raise ValueError("request is not currently valid")


@dataclass(frozen=True)
class QueryV2(RequestV2):
    def _validate(self, raw):
        return self._request(
            raw,
            {
                **_REQUEST,
                "type": literal("query"),
                "action": literal("diagnostic.read", "config.read"),
            },
        )


@dataclass(frozen=True)
class JobV2(RequestV2):
    execution_id: UUID
    idempotency_key: str

    def _validate(self, raw):
        return self._request(
            raw,
            {
                **_REQUEST,
                "type": literal("job"),
                "action": literal("set_mode"),
                "execution_id": uuid_value,
                "idempotency_key": resource_id,
            },
        )

    def check_replay(self, prior):
        """Compare stored jobs only; not durable deduplication or execution."""
        if (self.device_id, self.idempotency_key) != (prior.device_id, prior.idempotency_key):
            return False
        if self.model_dump(mode="json") != prior.model_dump(mode="json"):
            raise ValueError("idempotency key reused with a different job")
        return True


@dataclass(frozen=True)
class ResultV2(Contract):
    type: str
    version: int
    device_id: UUID
    boot_id: UUID
    sent_at: datetime
    request_id: UUID
    execution_id: UUID | None
    status: str
    persisted: bool | None = None
    applied: bool | None = None
    restart_required: bool | None = None
    error_code: str | None = None
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    completed_at: datetime | None = None

    def _validate(self, raw):
        result = _validate_fields(
            raw,
            {
                **_ENVELOPE,
                "type": literal("result"),
                "boot_id": uuid_value,
                "sent_at": utc_value,
                "request_id": uuid_value,
                "execution_id": nullable(uuid_value),
                "status": literal(
                    "accepted",
                    "running",
                    "succeeded",
                    "failed",
                    "unsupported",
                    "conflict",
                    "unknown",
                ),
                "persisted": nullable(boolean),
                "applied": nullable(boolean),
                "restart_required": nullable(boolean),
                "error_code": nullable(resource_id),
                "message": nullable(lambda v: text(v, 0, 1024)),
                "details": details,
                "completed_at": nullable(utc_value),
            },
        )
        terminal = result["status"] in {"succeeded", "failed", "unsupported", "conflict"}
        completion = result["completed_at"]
        if terminal != (completion is not None):
            raise ValueError("terminal outcomes require completion; nonterminal outcomes forbid it")
        if completion is not None and completion > result["sent_at"]:
            raise ValueError("completion cannot be after sent_at")
        return result

    def check_request(self, request):
        if (
            self.device_id != request.device_id
            or self.request_id != request.request_id
            or self.execution_id != getattr(request, "execution_id", None)
        ):
            raise ValueError("result does not match request identity")
        if self.sent_at < request.created_at or (
            self.completed_at is not None and self.completed_at < request.created_at
        ):
            raise ValueError("result predates request")
        # Late outcomes remain observable; expiry is checked before execution.


@dataclass(frozen=True)
class ResultAcceptanceV2(Contract):
    request_id: UUID
    execution_id: UUID | None

    def _validate(self, raw):
        return _validate_fields(
            raw, {"request_id": uuid_value, "execution_id": nullable(uuid_value)}
        )


@dataclass(frozen=True)
class InformV2(Contract):
    type: str
    version: int
    device_id: UUID
    boot_id: UUID
    sent_at: datetime
    node_name: str
    software_version: str
    capabilities: Mapping[str, int]
    inventory: InventoryV2
    telemetry: dict[str, Any]
    results: tuple[ResultV2, ...]
    pubkey: str | None = None

    def _validate(self, raw):
        result = _validate_fields(
            raw,
            {
                **_ENVELOPE,
                "type": literal("inform"),
                "boot_id": uuid_value,
                "sent_at": utc_value,
                "node_name": text,
                "pubkey": nullable(pubkey),
                "software_version": text,
                "capabilities": capabilities,
                "inventory": InventoryV2.model_validate,
                "telemetry": json_object,
                "results": array(ResultV2, 64),
            },
        )
        keys = []
        for entry in result["results"]:
            if entry.device_id != result["device_id"] or entry.sent_at > result["sent_at"]:
                raise ValueError("result device/timestamp does not match inform")
            keys.append((entry.request_id, entry.execution_id))
        unique(keys)
        return result


@dataclass(frozen=True)
class ResponseV2(Contract):
    type: str
    version: int
    device_id: UUID
    boot_id: UUID
    sent_at: datetime
    interval_seconds: int
    accepted_results: tuple[ResultAcceptanceV2, ...]
    queries: tuple[QueryV2, ...]
    jobs: tuple[JobV2, ...]

    def _validate(self, raw):
        result = _validate_fields(
            raw,
            {
                **_ENVELOPE,
                "type": literal("response"),
                "boot_id": uuid_value,
                "sent_at": utc_value,
                "interval_seconds": lambda v: integer(v, 5, 3600),
                "accepted_results": array(ResultAcceptanceV2, 64),
                "queries": array(QueryV2, 64),
                "jobs": array(JobV2, 64),
            },
        )
        unique([(r.request_id, r.execution_id) for r in result["accepted_results"]])
        requests = (*result["queries"], *result["jobs"])
        unique([r.request_id for r in requests])
        unique([r.execution_id for r in result["jobs"]])
        if any(r.device_id != result["device_id"] for r in requests):
            raise ValueError("request device mismatch")
        return result

    def check_inform(self, inform):
        if self.device_id != inform.device_id or self.boot_id != inform.boot_id:
            raise ValueError("response identity mismatch")
        offered = {(r.request_id, r.execution_id) for r in inform.results}
        if any((r.request_id, r.execution_id) not in offered for r in self.accepted_results):
            raise ValueError("acceptance references an unoffered result")
        if self.sent_at < inform.sent_at:
            raise ValueError("response predates inform")


@dataclass(frozen=True)
class LegacyObservation(Contract):
    observations: dict[str, Any]
    protocol: int = 1
    device_id: None = None
    boot_id: None = None
    capabilities: Mapping[str, int] = field(default_factory=dict)
    control_allowed: bool = False

    def _validate(self, raw):
        result = _validate_fields(
            raw,
            {
                "observations": json_object,
                "protocol": literal(1),
                "device_id": literal(None),
                "boot_id": literal(None),
                "capabilities": capabilities,
                "control_allowed": literal(False),
            },
        )
        if result["capabilities"]:
            raise ValueError("legacy observations have no capabilities")
        return result


def adapt_legacy_observation(raw):
    """Retain diagnostics including zero/null RF, without inferring authority."""
    checked_json(raw, json_only=True)
    if type(raw) is not dict or raw.get("type") != "inform":
        raise ValueError("expected legacy inform")
    if type(raw.get("version")) is not int or raw["version"] != 1:
        raise ValueError("expected explicit protocol1")
    return LegacyObservation(observations=raw)


def negotiate_protocol(*, device_id, operational_credentials):
    """Eligibility only; does not authenticate credentials or activate a route."""
    if type(operational_credentials) is not bool:
        raise ValueError("operational_credentials must be an explicit boolean")
    if device_id is not None:
        uuid_value(device_id)
    return 2 if device_id is not None and operational_credentials else 1


def decode_json(payload):
    try:
        encoded = payload.encode("utf-8") if isinstance(payload, str) else payload
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise ValueError("JSON byte budget exceeded")

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate JSON field")
                result[key] = value
            return result

        def reject_constant(value):
            raise ValueError(f"nonfinite JSON constant: {value}")

        raw = json.loads(encoded, object_pairs_hook=pairs, parse_constant=reject_constant)
        if type(raw) is not dict:
            raise ValueError("envelope must be an object")
        return checked_json(raw)
    except (RecursionError, UnicodeError, TypeError) as exc:
        raise ValueError("invalid JSON envelope") from exc


def parse_envelope(payload):
    raw = decode_json(payload)
    models = {
        "inform": InformV2,
        "query": QueryV2,
        "job": JobV2,
        "result": ResultV2,
        "response": ResponseV2,
    }
    try:
        model = models[raw.get("type")]
    except (KeyError, TypeError) as exc:
        raise ValueError("unknown envelope type") from exc
    return model.model_validate(raw)
