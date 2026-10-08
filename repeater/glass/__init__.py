"""Offline protocol2 contracts; importing this package activates no live control."""

from .contracts import (
    DeviceIdentityV2,
    IdentityV2,
    InformV2,
    InventoryV2,
    JobV2,
    LegacyObservation,
    QueryV2,
    ResponseV2,
    ResultAcceptanceV2,
    ResultV2,
    adapt_legacy_observation,
    negotiate_protocol,
    parse_envelope,
)

__all__ = [
    "DeviceIdentityV2",
    "IdentityV2",
    "InformV2",
    "InventoryV2",
    "JobV2",
    "LegacyObservation",
    "QueryV2",
    "ResponseV2",
    "ResultAcceptanceV2",
    "ResultV2",
    "adapt_legacy_observation",
    "negotiate_protocol",
    "parse_envelope",
]
