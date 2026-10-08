# Sanitized Repeater contract fixtures

All values are deterministic synthetic examples, not captures from a deployed node.
Identity is bytes 0..31 rendered as hex (not a generated private/public key pair).
`config_hash` is a real SHA-256 of the synthetic input config's canonical JSON.
Settings contain only `<redacted>` placeholders. `.invalid` is a reserved hostname;
no IPs, real host metrics, certificates, tokens or production config are included.
Copies in Glass `backend/tests/fixtures/repeater` and Repeater
`tests/fixtures/glass` are intentionally byte-identical and usable independently.

## Source provenance at the Task2 baseline

- Repeater `3c4bf3a`, `repeater/data_acquisition/glass_handler.py:272-330`:
  v1 payload, aggregate counters, single top-level radio, sanitized settings,
  optional unmodified sensor summary and command_results.
- Same file `:350-375`, `:1311-1316`: export redaction and canonical config hash.
- Same file `:545-569`, `:658`, `:1087-1104`: unknown actions become failed
  legacy results; absent details stay absent; completion timestamp is UTC.
- Repeater `repeater/config.py:877-936`, `:1566-1613`: radios[] entries have
  id/radio_type/radio overlays; fabric chooses a default radio.
- Repeater `repeater/config.py:1213-1216`: radio_type=None disables radio.
- Repeater `repeater/sensors/manager.py:120-131`, `:186-206` and
  `repeater/sensors/base.py:68-89`: summary shape, unavailable readings,
  data/error envelope and optional metrics. Older plugins omit unit metadata.
- Glass `55c3ca2`, `backend/app/contracts/v1/inform.py:9-59`, `:75-79`
  and `common.py:22-24`: actual Pydantic fields, bounds, status and identifiers.

## Examples and known gaps

- `producer_inputs.json`: synthetic inputs for the actual Repeater builder tests.
- `legacy_inform.json`: current single-radio inform, no sensor manager.
- `null_radio_inform.json`: current output for disabled radio and empty radio
  config, **not** top-level `radio:null`. Frequency/bandwidth are zero because
  the producer currently defaults them to zero. Glass v1 rejects both (`gt=0`).
  This known mismatch is asserted, not hidden by clamping or fake RF values.
- `multi_radio_inform.json`: current producer keeps radios/fabric in settings
  but still sends only the top-level radio telemetry. No per-radio support claim.
- `sensor_edge_inform.json`: an unavailable reading (empty data, null timestamp)
  plus a legacy reading without unit/metrics. Do not infer units or fill zeros.
- `unsupported_command.json` and `legacy_result.json`: v1 command and failed
  result for an unknown action. Backend tests use actual command/result models;
  producer tests exercise dispatch, queue and the next inform payload.
- `proposed_v2_inform.json`, `proposed_v2_result.json`, `proposed_v2_query.json`,
  `proposed_v2_job.json`, `proposed_v2_response.json`: historical filenames retained,
  but contents replaced by canonical **Task3 protocol2** envelopes validated by
  `backend/app/contracts/v2` and `test_protocol_v2.py`. They are synthetic examples,
  not current live producer output; protocol2 transport and control are inactive.
  The inform advertises read capabilities only and stable node-managed inventory
  IDs, including explicit repeater/room/companion identity IDs. Builtin sensors
  declare sensor_type independently of runtime plugins; plugin_id is null and
  plugins is empty. Disabled radio observations remain null. The modelled set_mode job is not
  dispatched; the unsupported result explicitly reports no mutation. The response
  accepts that result's IDs only when it is offered in an inform batch. Current
  v1 tests still require rejection. See `docs/revamp/protocol-v2.md` for exact
  bounds, timestamp/identity correlation, params and idempotency semantics.

Baseline backend tests validate actual Pydantic contracts and negative mutations;
Repeater tests compare actual builder/command behavior against legacy examples.
Task3 tests add offline v2 parsing/negotiation and safe legacy observation adapters;
no services or radio hardware are started. The parent owns copying the replacement
v2 fixtures to Repeater and verifying cross-repository parity before publication.
The byte-identical claim above describes the Task2 baseline, not an unverified
Task3 mirror. No enrollment, persistence, live dispatch or security repair is
claimed by accepting these offline examples.
