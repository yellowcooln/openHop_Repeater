"""Helpers for invalidating JWT sessions after authentication-boundary changes."""

from __future__ import annotations

from typing import Any

SECURITY_EPOCH_KEY = "security_epoch"


def get_security_epoch(config: dict[str, Any]) -> int:
    """Return the persisted non-negative JWT security epoch."""
    raw = config.get("repeater", {}).get("security", {}).get(SECURITY_EPOCH_KEY, 0)
    try:
        epoch = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, epoch)


def next_security_epoch(config: dict[str, Any]) -> int:
    """Return the epoch that should be persisted for the next security boundary."""
    return get_security_epoch(config) + 1


def set_security_epoch(config: dict[str, Any], epoch: int) -> None:
    """Set the persisted epoch in an in-memory config mapping."""
    security = config.setdefault("repeater", {}).setdefault("security", {})
    security[SECURITY_EPOCH_KEY] = max(0, int(epoch))


def sync_jwt_handler_epoch(jwt_handler: Any, epoch: int) -> None:
    """Apply a persisted epoch to a live JWT handler when supported."""
    setter = getattr(jwt_handler, "set_security_epoch", None)
    if callable(setter):
        setter(epoch)
