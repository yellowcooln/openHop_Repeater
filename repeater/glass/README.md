# Offline Glass protocol2 mirror

`contracts.py` mirrors the canonical Glass `backend/app/contracts/v2` runtime
rules using only Python's standard library. Constructors and `model_validate`
validate strict scalars, known structural fields, required arrays, identities,
references, action params and bounded JSON. Use `parse_envelope(str_or_bytes)`
for untrusted wire JSON: it also rejects duplicate keys and oversized raw bytes.
`model_dump(mode="json")` and `model_dump_json()` produce the canonical layout.

The frozen dataclasses, inventory tuples and read-only capability maps preserve
validated identity. Opaque telemetry/details remain detached JSON dictionaries,
not a deep security sandbox. Validate new envelopes rather than mutate opaque
maps. `ValueError` reports invalid contracts; assigning frozen fields raises
`dataclasses.FrozenInstanceError`. Capability maps use `MappingProxyType`, so
unsupported mutation methods may raise `AttributeError` instead of `TypeError`.
There is deliberately no Pydantic dependency or `model_json_schema` clone.

Context helpers (`check_acceptance`, `check_replay`, `check_request`,
`check_inform`) model device/capability/expiry, replay, outcome and explicit
acceptance correlation. They do not authenticate, persist, reserve idempotency
keys, enforce revisions or execute actions. The catalog is diagnostic.read and
config.read queries, and a **modelled, inactive** set_mode job.

`adapt_legacy_observation` keeps useful diagnostics, zero/null radio values and
missing sensor units without inventing identity/capabilities/control authority.
Its `control_allowed:false` is an offline adapter property, **not a repair of
existing v1 mutation routes**.

`GlassHandler.protocol_eligibility(operational_credentials=bool)` is an unused
future integration seam: configured `glass.device_id` plus explicit caller
credential readiness may indicate v2 eligibility. It does not authenticate or
switch transport. The live producer still emits v1 and `/inform` explicitly
rejects non-v1 outbound payloads before any network operation. Enrollment and
an authenticated v2 route/dispatcher belong to later Tasks4/6.

## Parity and provenance

All 13 files in `tests/fixtures/glass` (12 JSON envelopes/producer examples plus
the canonical provenance README) were copied or verified byte-identical against
Glass `backend/tests/fixtures/repeater`. Existing legacy producer JSON is
unchanged. Historical `proposed_v2_*.json` names now hold canonical Task3 data,
not live producer output. `tests/test_glass_contracts.py` mirrors canonical
runtime tests, replacing Pydantic-specific exception expectations with stdlib
errors and omitting JSON Schema assertions. Handler tests retain real legacy
builder diagnostics and assert eligibility never changes live v1 emission.
