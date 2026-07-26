"""Short-lived, one-time credentials for browser stream handshakes."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_ALLOWED_PATHS = frozenset(
    {
        "/api/cad_calibration_stream",
        "/api/companion/events",
        "/api/discover_neighbors_stream",
        "/api/gps_stream",
        "/api/logs_stream",
        "/api/update/progress",
        "/ws/companion_frame",
        "/ws/packets",
    }
)


def normalize_stream_path(path: str) -> str:
    """Return the canonical endpoint key used to bind a ticket."""
    value = str(path or "").split("?", 1)[0].strip()
    if not value.startswith("/") or value.startswith("//"):
        raise ValueError("Unsupported stream path")
    normalized = "/".join(part.replace("-", "_") for part in value.split("/"))
    if normalized not in _ALLOWED_PATHS:
        raise ValueError("Unsupported stream path")
    return normalized


@dataclass(frozen=True, slots=True)
class _TicketRecord:
    identity: dict[str, Any]
    path: str
    expires_at: float


class StreamTicketManager:
    """Issue and atomically consume short-lived endpoint-bound tickets."""

    def __init__(
        self,
        ttl_seconds: int = 30,
        max_tickets: int = 1024,
        time_fn: Callable[[], float] | None = None,
    ) -> None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        if max_tickets < 1:
            raise ValueError("max_tickets must be positive")
        self.ttl_seconds = int(ttl_seconds)
        self.max_tickets = int(max_tickets)
        self._time_fn = time_fn or time.monotonic
        self._lock = threading.Lock()
        self._tickets: OrderedDict[str, _TicketRecord] = OrderedDict()

    @staticmethod
    def _digest(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("utf-8")).hexdigest()

    def _prune_locked(self, now: float) -> None:
        expired = [digest for digest, record in self._tickets.items() if record.expires_at <= now]
        for digest in expired:
            self._tickets.pop(digest, None)
        while len(self._tickets) >= self.max_tickets:
            self._tickets.popitem(last=False)

    def issue(self, identity: dict[str, Any], path: str) -> dict[str, Any]:
        """Issue a new ticket for one supported stream endpoint."""
        canonical_path = normalize_stream_path(path)
        now = self._time_fn()
        ticket = secrets.token_urlsafe(32)
        record = _TicketRecord(
            identity=dict(identity or {}),
            path=canonical_path,
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._prune_locked(now)
            self._tickets[self._digest(ticket)] = record
        return {
            "ticket": ticket,
            "path": canonical_path,
            "expires_in": self.ttl_seconds,
        }

    def consume(self, ticket: str, path: str) -> dict[str, Any] | None:
        """Consume a ticket once and return its authenticated identity."""
        try:
            canonical_path = normalize_stream_path(path)
        except ValueError:
            return None
        now = self._time_fn()
        digest = self._digest(str(ticket or ""))
        with self._lock:
            self._prune_locked(now)
            record = self._tickets.pop(digest, None)
        if record is None or record.expires_at <= now or record.path != canonical_path:
            return None
        return dict(record.identity)
