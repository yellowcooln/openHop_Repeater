from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class OIDCFlowRecord:
    state: str
    nonce: str
    code_verifier: str
    return_to: str
    client_id: str
    expires_at: float

    def __repr__(self) -> str:
        return "OIDCFlowRecord(state=[REDACTED], nonce=[REDACTED], code_verifier=[REDACTED])"


@dataclass(frozen=True)
class OIDCExchangeRecord:
    code: str
    client_id: str
    identity: dict[str, Any] = field(repr=False)
    expires_at: float

    def __repr__(self) -> str:
        return "OIDCExchangeRecord(code=[REDACTED], client_id=[REDACTED])"


class OneTimeOIDCStore:
    def __init__(
        self,
        ttl_seconds: int = 300,
        exchange_ttl_seconds: int | None = None,
        max_entries: int = 256,
        time_fn: Callable[[], float] | None = None,
    ):
        self.ttl_seconds = ttl_seconds
        self.exchange_ttl_seconds = exchange_ttl_seconds or ttl_seconds
        self.max_entries = max_entries
        self._time_fn = time_fn or time.time
        self._lock = Lock()
        self._flows: dict[str, OIDCFlowRecord] = {}
        self._exchanges: dict[str, OIDCExchangeRecord] = {}

    def create_flow(
        self, code_factory: Callable[[], str], record: OIDCFlowRecord
    ) -> OIDCFlowRecord | None:
        with self._lock:
            self._cleanup_locked()
            if len(self._flows) >= self.max_entries:
                return None
            state = code_factory()
            stored = OIDCFlowRecord(
                state=state,
                nonce=record.nonce,
                code_verifier=record.code_verifier,
                return_to=record.return_to,
                client_id=record.client_id,
                expires_at=self._time_fn() + self.ttl_seconds,
            )
            self._flows[state] = stored
            return stored

    def consume_flow(self, state: str) -> OIDCFlowRecord | None:
        with self._lock:
            self._cleanup_locked()
            record = self._flows.pop(state, None)
            if record and record.expires_at >= self._time_fn():
                return record
            return None

    def create_exchange(
        self, code_factory: Callable[[], str], record: OIDCExchangeRecord
    ) -> OIDCExchangeRecord | None:
        with self._lock:
            self._cleanup_locked()
            if len(self._exchanges) >= self.max_entries:
                return None
            code = code_factory()
            stored = OIDCExchangeRecord(
                code=code,
                client_id=record.client_id,
                identity=dict(record.identity),
                expires_at=self._time_fn() + self.exchange_ttl_seconds,
            )
            self._exchanges[code] = stored
            return stored

    def consume_exchange(self, code: str, client_id: str) -> OIDCExchangeRecord | None:
        with self._lock:
            self._cleanup_locked()
            record = self._exchanges.get(code)
            if not record or record.client_id != client_id:
                return None
            self._exchanges.pop(code, None)
            if record.expires_at >= self._time_fn():
                return record
            return None

    def _cleanup_locked(self) -> None:
        now = self._time_fn()
        self._flows = {
            key: record for key, record in self._flows.items() if record.expires_at >= now
        }
        self._exchanges = {
            key: record for key, record in self._exchanges.items() if record.expires_at >= now
        }
