"""Canonical protocol2 contracts, independent of application startup."""

import copy
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

import pytest

from repeater.glass import (
    InformV2,
    JobV2,
    QueryV2,
    ResponseV2,
    ResultV2,
    adapt_legacy_observation,
    negotiate_protocol,
    parse_envelope,
)

ValidationError = (ValueError, FrozenInstanceError)

FIXTURES = Path(__file__).parent / "fixtures" / "glass"
DEVICE = "00000000-0000-4000-8000-000000000001"
BOOT = "00000000-0000-4000-8000-000000000002"
REQUEST = "00000000-0000-4000-8000-000000000003"
EXECUTION = "00000000-0000-4000-8000-000000000004"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def query(**changes):
    return dict(
        type="query",
        version=2,
        device_id=DEVICE,
        request_id=REQUEST,
        action="diagnostic.read",
        capability_version=1,
        created_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T00:05:00Z",
        params={},
        **changes,
    )


def job():
    raw = query()
    raw.update(
        type="job",
        action="set_mode",
        execution_id=EXECUTION,
        idempotency_key="fixture-mode-01",
        params={"mode": "monitor"},
    )
    return raw


@pytest.mark.parametrize(
    "name,model",
    [
        ("proposed_v2_inform.json", InformV2),
        ("proposed_v2_result.json", ResultV2),
        ("proposed_v2_query.json", QueryV2),
        ("proposed_v2_job.json", JobV2),
        ("proposed_v2_response.json", ResponseV2),
    ],
)
def test_canonical_fixtures_round_trip(name, model):
    raw = fixture(name)
    parsed = model.model_validate(raw)
    assert json.loads(parsed.model_dump_json()) == raw
    assert parse_envelope(json.dumps(raw)) == parsed


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", "2"),
        ("version", 3),
        ("version", 2.0),
        ("capabilities", None),
        ("capabilities", {"diagnostic.read": True}),
        ("capabilities", {"diagnostic.read": 0}),
        ("capabilities", {"diagnostic.read": "1"}),
        ("capabilities", {str(i): 1 for i in range(129)}),
        ("sent_at", "2026-01-01T00:00:00"),
        ("sent_at", "2026-01-01T01:00:00+01:00"),
        ("device_id", "not-a-uuid"),
        ("unexpected", 1),
    ],
)
def test_inform_fail_closed(field, value):
    raw = fixture("proposed_v2_inform.json")
    raw[field] = value
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


@pytest.mark.parametrize("field", ["capabilities", "device_id", "boot_id", "sent_at", "version"])
def test_missing_required_inform_fields(field):
    raw = fixture("proposed_v2_inform.json")
    del raw[field]
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


def test_stable_inventory_ids_not_enumeration_and_unique():
    raw = fixture("proposed_v2_inform.json")
    original = InformV2.model_validate(raw)
    raw["inventory"]["radios"].reverse()
    assert {r.id for r in InformV2.model_validate(raw).inventory.radios} == {
        r.id for r in original.inventory.radios
    }
    raw["inventory"]["radios"].append(raw["inventory"]["radios"][0])
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)
    raw["inventory"]["radios"] = [{"id": f"rf-{i}", "enabled": False} for i in range(33)]
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


def corrected_inventory():
    return {
        "radios": [],
        "identities": [
            {"id": "repeater-main", "kind": "repeater"},
            {"id": "room-main", "kind": "room"},
            {"id": "companion-main", "kind": "companion"},
        ],
        "sensors": [{"id": "battery-main", "sensor_type": "battery"}],
        "plugins": [],
    }


def test_builtin_sensors_and_explicit_identity_ids_without_plugins():
    raw = fixture("proposed_v2_inform.json")
    raw["inventory"] = corrected_inventory()
    parsed = InformV2.model_validate(raw)
    assert parsed.inventory.sensors[0].sensor_type == "battery"
    assert parsed.inventory.sensors[0].plugin_id is None
    assert {entry.kind for entry in parsed.inventory.identities} == {
        "repeater",
        "room",
        "companion",
    }
    raw["inventory"]["identities"].reverse()
    assert {entry.id for entry in InformV2.model_validate(raw).inventory.identities} == {
        entry.id for entry in parsed.inventory.identities
    }
    with pytest.raises(ValidationError):
        parsed.inventory.identities[0].id = "renamed"


@pytest.mark.parametrize("field", ["radios", "identities", "sensors", "plugins"])
def test_all_inventory_arrays_required(field):
    raw = fixture("proposed_v2_inform.json")
    raw["inventory"] = corrected_inventory()
    del raw["inventory"][field]
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


@pytest.mark.parametrize(
    "identities",
    [
        [{"id": "same", "kind": "repeater"}, {"id": "same", "kind": "room"}],
        [{"id": "same", "kind": "room"}] * 2,
        [{"kind": "room"}],
        [{"id": "room-main"}],
        [{"id": "room-main", "kind": "unknown"}],
        [{"id": "room-main", "kind": 1}],
        [{"id": "room main", "kind": "room"}],
        [{"id": "x" * 65, "kind": "room"}],
        [{"id": "room-main", "kind": "room", "extra": 1}],
        [{"id": f"room-{i}", "kind": "room"} for i in range(129)],
    ],
)
def test_identity_inventory_rejections(identities):
    raw = fixture("proposed_v2_inform.json")
    raw["inventory"] = corrected_inventory()
    raw["inventory"]["identities"] = identities
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


def test_identity_inventory_limit_and_empty_arrays():
    raw = fixture("proposed_v2_inform.json")
    raw["inventory"] = corrected_inventory()
    raw["inventory"]["identities"] = [{"id": f"room-{i}", "kind": "room"} for i in range(128)]
    assert len(InformV2.model_validate(raw).inventory.identities) == 128
    raw["inventory"] = {"radios": [], "identities": [], "sensors": [], "plugins": []}
    InformV2.model_validate(raw)


def test_plugin_sensors_require_reference_only_when_present():
    raw = fixture("proposed_v2_inform.json")
    raw["inventory"] = corrected_inventory()
    sensor = raw["inventory"]["sensors"][0]
    sensor["plugin_id"] = None
    InformV2.model_validate(raw)
    sensor["plugin_id"] = "power"
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)
    raw["inventory"]["plugins"] = [{"id": "power", "version": "1"}]
    InformV2.model_validate(raw)
    del sensor["sensor_type"]
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


@pytest.mark.parametrize("sensor_type", [None, 1, "", "bad type", "x" * 65])
def test_sensor_type_resource_id_validation(sensor_type):
    raw = fixture("proposed_v2_inform.json")
    raw["inventory"] = corrected_inventory()
    raw["inventory"]["sensors"][0]["sensor_type"] = sensor_type
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


def test_nested_fields_types_and_boolean_are_strict():
    raw = fixture("proposed_v2_inform.json")
    for mutation in [
        {"id": "x", "enabled": 1},
        {"id": "x", "unknown": 1},
        {"id": "x" * 65, "enabled": False},
    ]:
        raw["inventory"]["radios"] = [mutation]
        with pytest.raises(ValidationError):
            InformV2.model_validate(raw)


@pytest.mark.parametrize(
    "mutation",
    [
        {"action": "reboot"},
        {"action": "set_mode"},
        {"capability_version": True},
        {"capability_version": 2},
        {"params": {"unknown": True}},
        {"expires_at": "2025-01-01T00:00:00Z"},
        {"params": []},
    ],
)
def test_query_rejections(mutation):
    raw = query()
    raw.update(mutation)
    with pytest.raises(ValidationError):
        QueryV2.model_validate(raw)


def test_job_requires_idempotency_execution_and_typed_mode():
    for field in ["idempotency_key", "execution_id"]:
        raw = job()
        del raw[field]
        with pytest.raises(ValidationError):
            JobV2.model_validate(raw)
    for params in [{"mode": "bad"}, {"mode": "monitor", "x": 1}, {}]:
        raw = job()
        raw["params"] = params
        with pytest.raises(ValidationError):
            JobV2.model_validate(raw)


def test_job_idempotency_contract_detects_conflicting_replays():
    parsed = JobV2.model_validate(job())
    assert parsed.check_replay(parsed) is True
    different_key = job()
    different_key["idempotency_key"] = "another-key"
    assert parsed.check_replay(JobV2.model_validate(different_key)) is False
    for changes in [{"params": {"mode": "no_tx"}}, {"execution_id": BOOT}]:
        changed = job()
        changed.update(changes)
        with pytest.raises(ValueError):
            parsed.check_replay(JobV2.model_validate(changed))


def test_context_acceptance_checks_expiry_device_and_capability():
    parsed = JobV2.model_validate(job())
    now = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)
    parsed.check_acceptance(device_id=DEVICE, capabilities={"set_mode": 1}, now=now)
    for changes in [
        {"device_id": BOOT},
        {"capabilities": {}},
        {"capabilities": {"set_mode": 2}},
        {"now": datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc)},
        {"now": datetime(2025, 1, 1, tzinfo=timezone.utc)},
    ]:
        args = {"device_id": DEVICE, "capabilities": {"set_mode": 1}, "now": now}
        args.update(changes)
        with pytest.raises(ValueError):
            parsed.check_acceptance(**args)


def test_result_outcomes_and_response_acceptance():
    raw = fixture("proposed_v2_result.json")
    for status in [
        "accepted",
        "running",
        "succeeded",
        "failed",
        "unsupported",
        "conflict",
        "unknown",
    ]:
        changed = copy.deepcopy(raw)
        changed["status"] = status
        changed["completed_at"] = (
            None if status in {"accepted", "running", "unknown"} else raw["completed_at"]
        )
        ResultV2.model_validate(changed)
    for changes in [
        {"status": "success"},
        {"persisted": 1},
        {"message": "x" * 1025},
        {"completed_at": None},
        {"status": "running"},
    ]:
        changed = copy.deepcopy(raw)
        changed.update(changes)
        with pytest.raises(ValidationError):
            ResultV2.model_validate(changed)
    response = ResponseV2.model_validate(fixture("proposed_v2_response.json"))
    assert str(response.accepted_results[0].execution_id) == EXECUTION


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object(), {1: "bad"}, "x" * 65537])
def test_details_json_and_size_bounds(value):
    raw = fixture("proposed_v2_result.json")
    raw["details"] = {"value": value}
    with pytest.raises(ValidationError):
        ResultV2.model_validate(raw)


def test_global_bounds_and_json_parser():
    raw = fixture("proposed_v2_inform.json")
    nested = {}
    for _ in range(17):
        nested = {"child": nested}
    for telemetry in [nested, {"items": [0] * 4097}, {"blob": "x" * 262145}]:
        raw["telemetry"] = telemetry
        with pytest.raises(ValidationError):
            InformV2.model_validate(raw)
    for text in ['{"type":"inform","type":"job"}', "[]", '{"x":NaN}', "x" * 262145]:
        with pytest.raises(ValueError):
            parse_envelope(text)
    raw = fixture("proposed_v2_inform.json")
    raw["results"] = [fixture("proposed_v2_result.json")] * 65
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


def test_identity_frozen():
    parsed = InformV2.model_validate(fixture("proposed_v2_inform.json"))
    with pytest.raises(ValidationError):
        parsed.device_id = BOOT
    with pytest.raises(TypeError):
        parsed.capabilities["set_mode"] = 1
    with pytest.raises((TypeError, AttributeError)):
        parsed.capabilities.clear()
    with pytest.raises(ValidationError):
        parsed.inventory.radios[0].id = "new-id"
    with pytest.raises(ValidationError):
        parsed.inventory.radios += (parsed.inventory.radios[0],)


def test_result_and_response_context_binding():
    result = ResultV2.model_validate(fixture("proposed_v2_result.json"))
    request = JobV2.model_validate(job())
    result.check_request(request)
    wrong = job()
    wrong["execution_id"] = BOOT
    with pytest.raises(ValueError):
        result.check_request(JobV2.model_validate(wrong))
    raw = fixture("proposed_v2_inform.json")
    raw["results"] = [fixture("proposed_v2_result.json")]
    inform = InformV2.model_validate(raw)
    response = ResponseV2.model_validate(fixture("proposed_v2_response.json"))
    response.check_inform(inform)
    with pytest.raises(ValueError):
        response.check_inform(InformV2.model_validate(fixture("proposed_v2_inform.json")))
    wrong = fixture("proposed_v2_response.json")
    wrong["boot_id"] = DEVICE
    with pytest.raises(ValueError):
        ResponseV2.model_validate(wrong).check_inform(inform)
    raw["results"][0]["device_id"] = BOOT
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


@pytest.mark.parametrize(
    "field,values",
    [
        ("capabilities", [{"x" * 65: 1}, {"set_mode": 1.0}]),
        ("telemetry", [{"value": datetime(2026, 1, 1, tzinfo=timezone.utc)}, {"value": (1, 2)}]),
    ],
)
def test_strict_json_metadata(field, values):
    for value in values:
        raw = fixture("proposed_v2_inform.json")
        raw[field] = value
        with pytest.raises(ValidationError):
            InformV2.model_validate(raw)


def test_empty_capabilities_read_only_and_inventory_reference_validation():
    raw = fixture("proposed_v2_inform.json")
    raw["capabilities"] = {}
    assert InformV2.model_validate(raw).capabilities == {}
    raw["inventory"]["sensors"][0]["plugin_id"] = "absent"
    with pytest.raises(ValidationError):
        InformV2.model_validate(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"accepted_results": [{"request_id": REQUEST, "execution_id": EXECUTION}] * 2},
        {"interval_seconds": True},
        {"interval_seconds": "30"},
        {"jobs": [job(), job()]},
        {"jobs": [{**job(), "device_id": BOOT}]},
    ],
)
def test_response_fails_closed(changes):
    raw = fixture("proposed_v2_response.json")
    raw.update(changes)
    with pytest.raises(ValidationError):
        ResponseV2.model_validate(raw)


@pytest.mark.parametrize(
    "name",
    [
        "legacy_inform.json",
        "null_radio_inform.json",
        "multi_radio_inform.json",
        "sensor_edge_inform.json",
    ],
)
def test_legacy_observations_never_infer_identity_or_control(name):
    raw = fixture(name)
    adapted = adapt_legacy_observation(raw)
    assert adapted.protocol == 1 and adapted.capabilities == {} and not adapted.control_allowed
    assert adapted.device_id is None and adapted.boot_id is None
    assert adapted.observations == raw
    if name == "null_radio_inform.json":
        assert adapted.observations["radio"]["frequency"] == 0
    raw["radio"] = None
    assert adapt_legacy_observation(raw).observations["radio"] is None


def test_negotiation_is_explicit_not_software():
    assert negotiate_protocol(device_id=None, operational_credentials=True) == 1
    assert negotiate_protocol(device_id=DEVICE, operational_credentials=False) == 1
    assert negotiate_protocol(device_id=DEVICE, operational_credentials=True) == 2
    with pytest.raises(ValueError):
        negotiate_protocol(device_id="bad", operational_credentials=True)


@pytest.mark.parametrize("value", [1, "true", None])
def test_negotiation_requires_explicit_boolean(value):
    with pytest.raises(ValueError):
        negotiate_protocol(device_id=DEVICE, operational_credentials=value)


def test_typed_inputs_and_constructor_validation():
    from uuid import UUID

    raw = fixture("proposed_v2_inform.json")
    raw["device_id"] = UUID(DEVICE)
    raw["sent_at"] = datetime(2026, 1, 1, tzinfo=timezone.utc)
    parsed = InformV2(**raw)
    assert parsed.device_id == UUID(DEVICE)
    assert parse_envelope(parsed.model_dump_json().encode()) == parsed
    assert InformV2.model_validate(parsed.model_dump()) == parsed
    raw["version"] = True
    with pytest.raises(ValueError):
        InformV2(**raw)


@pytest.mark.parametrize("value", [0, 65536, True, 1.0, "1"])
def test_capability_version_bounds(value):
    raw = fixture("proposed_v2_inform.json")
    raw["capabilities"] = {"custom.read": value}
    with pytest.raises(ValueError):
        InformV2.model_validate(raw)


def test_max_capability_version_and_late_result_observation():
    raw = fixture("proposed_v2_inform.json")
    raw["capabilities"] = {"custom.read": 65535}
    InformV2.model_validate(raw)
    result = fixture("proposed_v2_result.json")
    result["sent_at"] = result["completed_at"] = "2026-01-02T00:00:00Z"
    ResultV2.model_validate(result).check_request(JobV2.model_validate(job()))


def test_legacy_adapter_is_detached_and_bounded():
    raw = fixture("sensor_edge_inform.json")
    parsed = adapt_legacy_observation(raw)
    raw["sensors"]["readings"].clear()
    assert parsed.observations["sensors"]["readings"]
    for invalid in [
        {"type": "inform", "version": True},
        {"type": "inform", "version": 2},
        {"type": "inform", "version": 1, "bad": float("nan")},
    ]:
        with pytest.raises(ValueError):
            adapt_legacy_observation(invalid)
