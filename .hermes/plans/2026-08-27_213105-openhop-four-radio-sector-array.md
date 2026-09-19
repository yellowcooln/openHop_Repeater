# openHop Four-Radio Sector Array Implementation Plan

> Local planning artifact only. Do not post, push, open PRs/issues, comment, or contact anyone while executing this plan unless the user separately asks.

**Goal:** Build a reliable four-radio openHop repeater node using four independently networked openHop Modems, with one logical radio presented to openHop Repeater, cross-radio RX deduplication, direction-aware TX selection, safe serialized TX, per-sector health, and honest failure reporting.

**Recommended architecture:** Create a separate Linux service, working name **openHop Array**, derived from the useful controller ideas in `itk80/py_HydraCore`. It connects outward to four ordinary openHop Modems and presents one conservative, standard openHop Modem TCP endpoint inward to Repeater. Keep the topology-specific array scheduler out of generic openHop Core for v1. Repeater can initially connect through its existing `modem_tcp` path without changing packet-routing behavior. Add an explicit `array_tcp`/management integration only after transparent compatibility is proven.

**Why this shape:** openHop Core and Repeater already have RF Fabric/multi-radio plumbing, but that implementation selects one endpoint (`default`, `sticky`, or two-radio `bridge`) and explicitly does not perform automatic TX fan-out. A same-channel four-sector array needs a different semantic unit: receive coalescing, sector observations, direction cache, serialized/subset TX, sibling lockout, aggregate airtime accounting, and transaction-level health. Hiding that behind a virtual modem keeps Repeater's mesh state machine single-radio and makes rollback straightforward.

**Tech stack:** Python 3.11+, asyncio, FastAPI only for the management plane, SQLite, the existing openHop Modem framed TCP protocol, pytest/pytest-asyncio, Ruff, systemd, four Ethernet- or Wi-Fi-attached openHop Modems.

---

## Evidence and current state

Inspected locally on 2026-08-27. No external state was changed.

- `py_HydraCore`: upstream/fork HEAD `54ec51c1a8c7cd7122b727056b4ed914287bc3d5`; one initial commit, v0.3.0.
- openHop Repeater fetched `origin/dev`: `e28be27a7795b410cc92f1189c68eeef9111b9e8`.
- openHop Core fetched `origin/dev`: `77f116a8dab097642d04a16c8aaf097c0dd33cc3`.
- openHop Modem `origin/dev`: `50804c647e0f49b8835b15c993d7b6c88641ac12`.
- RepeaterUI fetched `origin/dev`: `43a480ed639cec516396005b7413b0baaf6afe37`.

Verified locally:

- `py_HydraCore`: 25 pytest tests pass in a fresh ignored `.venv`; Ruff reports 52 findings, so it is not lint-clean.
- openHop Core focused RF Fabric/CAD tests pass (`39 passed` in the broader audit run).
- openHop Repeater focused multi-radio/policy/TX-lock tests pass (`16 passed` in the broader audit run).
- No physical radios or RF path were tested. Nothing here is hardware validation.

Useful HydraCore implementation:

- one async reconnecting TCP client per sector: `py_hydracore/sector.py`;
- orchestration, first-response gating, DOA, and command fan-out: `py_hydracore/orchestrator.py`;
- sequential/selected TX state machine: `py_hydracore/tx_state.py`;
- one-client virtual-modem endpoint: `py_hydracore/upstream_tcp.py`;
- persisted sectors/settings/DOA: `py_hydracore/store.py`;
- four-radio management API/dashboard: `py_hydracore/api/app.py` and templates.

Important gaps found during review:

1. The README says the best-RSSI copy is forwarded, but `_handle_rx_packet()` forwards the **first** copy immediately. Later stronger duplicates only update DOA and are suppressed. There is no coalescing hold window, so this is first-arrival diversity, not best-copy selection.
2. `CMD_RX_PACKET_V2` reports only the first sector's bit at forwarding time; it cannot report the eventual full sector mask.
3. Hydra's frame parser/builder rejects payloads over 255 bytes. Real modem RX events include six metadata bytes plus the LoRa bytes, and openHop Modem allocates for that larger frame. Large valid RX packets can therefore be rejected.
4. Hydra adds `CMD_RX_PACKET_V2=0x05` and `CMD_TX_REQUEST_DIRECTED=0x06`, but those commands are absent from current openHop Modem and openHop Core. Core's `TCPLoRaRadio` only dispatches `CMD_RX_PACKET=0x04`.
5. Early `TX_DONE` is sent after the first sector succeeds while the remaining sectors continue. The upstream driver can then submit another packet while the array is still busy; Hydra rejects a busy submission instead of queueing it. That can turn normal mesh bursts into avoidable `TX_FAIL`s.
6. Sibling `STANDBY`/`RESUME` writes are not acknowledged as a barrier before TX advances. A slow link can leave a sibling receiving while a nearby PA starts.
7. First-response-wins can hide partial configuration failure or configuration drift. One good sector response is not proof that all four applied the command.
8. The management HTTP API binds to `0.0.0.0` in the supplied unit and has no application authentication. The virtual upstream TCP endpoint also has no independent authentication.
9. The source repository has no LICENSE file. The quoted author permission asks for co-author credit, but redistribution terms should be made explicit before copying code into a public openHop repository.
10. Tests are mostly unit tests. There is no four-fake-modem end-to-end test covering command fan-out, reconnect during TX, queueing, large RX frames, mixed success, or upstream compatibility.
11. Hydra's `active` flag is not a clean TX-only gate: `_broadcast_to_sectors()` skips inactive sectors for ordinary upstream commands, so a receiver left connected/inactive can miss later config and `RX_START` updates.
12. DOA storage is allocated for 64 slots but indexed by persistent SQLite sector ID. Repeated add/remove cycles can eventually produce IDs outside the cache even with only four live sectors.
13. After Hydra's early `TX_DONE`, current Core sends `RX_START` as part of its normal send completion path. Hydra broadcasts that command while its remaining sector TX plan may still be running, creating another control/TX race.
14. In the native RF Fabric path, Repeater can begin several physical radios while constructing the stack but only close the default radio during ordinary shutdown; partial construction and normal teardown need all-radio rollback/cleanup before that path is production-safe.
15. Hydra's first-response gate can remain populated forever after an unanswered query. That permanently suppresses heartbeat and noise sampling until restart because expired entries are not swept independently.
16. `TxOrchestrator` creates a transition lock but does not use it. A timeout and `TX_DONE` arriving together can both advance the plan. Eligibility is also recalculated during a cycle, so it is not an immutable TX plan, and SMART fallback can skip earlier sectors in the ordering.
17. Hydra does not negotiate per-sector protocol capabilities. Recording a version string is not enough to safely broadcast standby, OTA, auto-CAD, or future commands across mixed firmware.
18. Current openHop Modem has a fixed firmware TX timeout around 4.5 seconds even though supported long-airtime combinations can exceed that. A four-sector sequential plan compounds the timing problem and must be measured rather than hidden behind larger host timeouts.
19. Modem reconnect does not prove desired radio/CAD state still matches. The coordinator must replay and verify the complete authoritative tuples after every reconnect or reboot.

Current openHop capabilities:

- Repeater already accepts `radios[]`, constructs `FabricRadio`, exposes multi-radio config/status, supports per-radio editing, and records RX/TX radio IDs.
- Core's `RFFabric` registers N radios and chooses one radio for TX. It does not coalesce duplicate receptions or fan TX out.
- Repeater's `fabric.tx_mode` supports only `default`, `sticky`, and `bridge`; `bridge` is explicitly a two-radio-oriented policy.
- The current callback path can race per-packet identity/metrics: TCP radio callbacks can provide only raw data, while Dispatcher later reads mutable global `last_rx_radio_id` and last RSSI/SNR. That must be fixed before treating native RF Fabric as a trustworthy four-radio array.
- openHop Modem already has the required per-radio primitives: TCP auth, config, CAD/auto-CAD, RX events, `RADIO_STANDBY`, `RADIO_RESUME`, reconnectable single-client operation, and RAK4631 + RAK13800/W5100S Ethernet support. No four-radio coordinator belongs in each modem.

---

## Product and compatibility contract

1. Use four normal openHop Modems, one radio per modem. Do not make a "four radios in one modem" firmware target.
2. The array service is the sole TCP client of each modem. Repeater is the sole client of the array service.
3. V1 upstream compatibility uses only the standard modem commands current `TCPLoRaRadio` understands. `CMD_RX_PACKET_V2` and directed-TX extensions stay disabled until negotiated capability support exists in Core.
4. All four sectors must use one RF profile for a same-channel directional array: frequency, bandwidth, SF, CR, sync word, preamble, and policy-approved power. Reject mixed profiles in array mode.
5. RX is coalesced for a small bounded window and emitted once with the strongest valid observation. The management plane retains every sector observation.
6. TX policy is explicit, never accidental:
   - direct traffic with a confident fresh direction may use one sector;
   - flood/unknown traffic uses a configured subset or sequential all-sector policy;
   - simultaneous TX is forbidden by default;
   - sibling standby is an acknowledged barrier when lockout is enabled.
7. The array has a bounded TX queue. It must not acknowledge upstream completion and then reject the next ordinary request merely because background fan-out is still running.
8. A command broadcast is a transaction with per-sector results. Upstream gets a success only according to the command's documented quorum rule; the management API exposes partial failures.
9. Repeater startup and ordinary routing still work when one or more sectors are offline, subject to a configurable minimum-online threshold.
10. Secrets never appear in API responses, logs, exports, or generated config snippets.
11. Rollback is: stop array service and point Repeater's existing `modem_tcp` host back to one physical modem.
12. Repeater retains the one `LocalIdentity`, one Dispatcher, ACK correlation, routing, encryption, contacts/channels, and logical packet deduplication. The array service is an RF controller, not a second MeshCore node. It may parse the minimum packet header needed for sector policy, but it must not create another mesh identity or independently forward/decrypt application traffic.

---

## Phase 0: Permission, attribution, and local source setup

**Objective:** Preserve the original developer's ownership before adapting code.

1. Keep all work local until explicitly told otherwise.
2. Record `itk80` as the design/source author in a local `NOTICE.md` and project metadata.
3. For commits that actually carry adapted source, use the original repository identity (`itk80 <i.t.keny@gmail.com>`) as co-author if that is still the requested form of credit. Do not add agent attribution.
4. Before any public distribution, obtain or record an explicit software license from the author. The quoted permission is evidence of intent, but the repository currently has no LICENSE.
5. Create the implementation in a new local repository/worktree, not by editing the inspected HydraCore checkout or any current feature branch.
6. Base all coordinated openHop changes on freshly fetched `origin/dev` worktrees; do not reuse the currently checked-out Repeater/Core/UI feature branches.

**Gate:** No copied source is published until attribution and redistribution permission are unambiguous.

---

## Phase 1: Build a protocol-accurate virtual-modem test harness

**Objective:** Prove the architecture without radios before touching openHop repos.

**New project files (working names):**

- `src/openhop_array/protocol.py`
- `src/openhop_array/sector.py`
- `src/openhop_array/controller.py`
- `src/openhop_array/gateway.py`
- `tests/fakes/modem_server.py`
- `tests/test_protocol_parity.py`
- `tests/test_gateway_compatibility.py`
- `tests/test_four_sector_end_to_end.py`

**Work:**

1. Import protocol constants from a generated/parity-checked table based on openHop Modem `firmware/include/protocol.h`; do not maintain an unverified hand copy.
2. Separate maximum raw LoRa length from maximum framed command payload. Accept RX metadata plus a full legal LoRa payload.
3. Implement four fake modem TCP servers with auth, command replies, asynchronous RX, delayed responses, disconnect/reconnect, injected `TX_FAIL`, and per-sector RSSI/SNR.
4. Run the real openHop Core `TCPLoRaRadio` against the virtual gateway in tests. Prove PING/AUTH, SET_CONFIG, RX_START, CAD, TX, reconnect, and asynchronous RX.
5. Default to standard `CMD_RX_PACKET`; reject/ignore unnegotiated extension commands.
6. Test 0-, 1-, 2-, 4-sector online cases and one sector dropping during every transaction type.
7. Add fuzz/property cases for fragmented/coalesced TCP reads, bad CRC, oversized LEN, stale responses, and command interleaving.
8. Include long RX frames, W5100S bounded-write/queue contention, unanswered query expiry, and an incoming unnegotiated RX-v2 frame. None may wedge the gateway, bypass deduplication, or leave heartbeat disabled.

**Verification:**

```bash
python -m pytest -q tests/test_protocol_parity.py tests/test_gateway_compatibility.py
python -m pytest -q tests/test_four_sector_end_to_end.py
ruff check src tests
ruff format --check src tests
```

**Gate:** Current `TCPLoRaRadio` completes the full compatibility test without production Core changes.

---

## Phase 2: Correct RX diversity and direction tracking

**Objective:** Emit one genuinely selected packet while retaining all observations.

**Files:**

- `src/openhop_array/rx_coalescer.py`
- `src/openhop_array/doa.py`
- `src/openhop_array/controller.py`
- `tests/test_rx_coalescer.py`
- `tests/test_doa.py`

**Work:**

1. Key duplicate observations by a collision-resistant digest of the raw MeshCore packet, not RSSI metadata.
2. Hold the first observation for a configurable bounded coalescing window (start around 40-100 ms; derive the final value from measured wired-LAN jitter).
3. Collect sector ID, monotonic receive time, RSSI, SNR, signal RSSI, and packet bytes immutably per observation.
4. At window expiry, choose the strongest valid observation using a documented tie-breaker and emit exactly one standard RX frame upstream.
5. Track the complete heard-sector mask and observation set in management telemetry, even though the standard upstream frame cannot carry it.
6. Keep self-TX echo suppression separate from normal duplicate expiry.
7. Keep DOA observations by stable radio ID, not array index or database row order. Never index a fixed-size array by a persistent SQLite primary key.
8. Treat one-byte peer hashes as hints with collision/confidence/TTL handling, never certainty.
9. Add bounded memory and monotonic-clock tests.

**Acceptance:** a weaker first arrival followed by a stronger arrival inside the window emits the stronger metrics and packet once; a late duplicate is suppressed but still recorded according to the telemetry policy.

---

## Phase 3: Replace the TX path with a queued, acknowledged array scheduler

**Objective:** Make four-sector TX deterministic and loss-resistant.

**Files:**

- `src/openhop_array/tx_scheduler.py`
- `src/openhop_array/policy.py`
- `src/openhop_array/controller.py`
- `tests/test_tx_scheduler.py`
- `tests/test_tx_policy.py`
- `tests/test_lockout_barrier.py`

**Work:**

1. Add a bounded FIFO with explicit overflow behavior and metrics.
2. Protect every TX state transition with one actually used async lock and snapshot an immutable ordered sector plan at admission time. A timeout and completion callback must never advance the same request twice.
3. Parse only enough MeshCore header data for policy selection; malformed/unknown traffic takes the conservative configured fallback.
4. Support policies:
   - `best_sector`: one confident DOA sector, fallback configured;
   - `sequential_subset`: ordered selected sectors;
   - `sequential_all`: all online/active sectors;
   - `primary_only`: safe rollback/degraded mode.
5. Default direct packets to best-sector-with-fallback and flood packets to the operator-selected sequential policy.
6. For lockout, send STANDBY to online siblings and wait for their matching acknowledgements or a bounded timeout before TX. Resume them and verify acknowledgements after each TX attempt.
7. Never transmit from multiple sectors simultaneously unless a future explicitly tested policy says otherwise.
8. Define upstream completion semantics. Recommended v1: return `TX_DONE` only after the selected plan reaches its success criterion; keep processing time within Core's existing timeout. If a long four-sector plan cannot fit, extend the upstream transaction timeout deliberately rather than lying with an early ACK.
9. Do not allow Core's post-send `RX_START`, or any later upstream command, to interleave with an unfinished sector TX plan. Queue or transaction-gate commands according to an explicit safe ordering rule.
10. If early ACK is retained later, the queue must accept subsequent requests while background work continues and preserve ordered outcomes.
11. Record per-sector airtime and aggregate site airtime. Repeater's single-radio duty-cycle estimate is not enough for four actual transmissions.
12. On disconnect/failure, continue or abort according to an explicit quorum policy and expose the partial result. SMART fallback must try every eligible sector in the immutable fallback plan, including sectors that sort before the failed preferred sector.

**Acceptance:** bursts do not create busy-state packet loss; no sibling TX begins before lockout barrier completion; every accepted request ends in exactly one upstream outcome.

---

## Phase 4: Make command fan-out transactional

**Objective:** Prevent one healthy sector from hiding three broken or misconfigured sectors.

**Files:**

- `src/openhop_array/transactions.py`
- `src/openhop_array/controller.py`
- `tests/test_command_transactions.py`

**Work:**

1. Give each command a response type, timeout, quorum, and aggregation rule.
2. `SET_CONFIG`, RX start, CAD policy, standby/resume, and other mutating commands require all active sectors unless degraded mode is explicitly enabled.
3. Read-only status/version/noise queries return one standard upstream reply but capture every per-sector response for management telemetry.
4. Correlate responses by sector and transaction generation, not only command byte, so stale replies cannot satisfy a newer request.
5. Sweep expired transactions independently. An unanswered query must time out, clear its gate, and allow heartbeat/noise work to resume without a restart.
6. Negotiate or derive a conservative per-sector capability set before using optional v0.7+ commands. Mixed firmware enters a visible degraded state rather than receiving blind broadcasts.
7. Detect RF-config drift at connect/reconnect and reapply and verify the complete authoritative radio and CAD tuples before marking that sector ready.
8. Do not forward arbitrary sector errors without enough context to determine which upstream transaction they belong to.

**Acceptance:** an injected failure on sector 3 is visible and cannot be reported as an all-sector configuration success.

---

## Phase 5: Harden and package the new service

**Objective:** Produce an installable, recoverable service rather than a demo dashboard.

**Files:**

- `src/openhop_array/api.py`
- `src/openhop_array/config.py`
- `src/openhop_array/store.py`
- `deploy/openhop-array.service`
- `config.yaml.example`
- `README.md`, `NOTICE.md`, `SECURITY.md`
- packaging and CI files

**Work:**

1. Use a versioned YAML schema for stable array settings and SQLite only for runtime observations/history where appropriate.
2. Store sector auth tokens with restrictive file permissions; redact them from every API/log/export path.
3. Bind the virtual modem endpoint to loopback by default when co-located with Repeater. If LAN binding is selected, support standard `CMD_AUTH` at the gateway and require an explicit token.
4. Bind management API to loopback by default. Add proper authentication before any LAN exposure; do not ship Hydra's unauthenticated `0.0.0.0` management default.
5. Validate sector host/port/name/azimuth, unique IDs, minimum/maximum sector count, and same-profile requirements.
6. Add `/healthz`, `/readyz`, structured logs, Prometheus metrics, config backup/restore, and explicit degraded-state reasons.
7. Use a dedicated non-root systemd user, `StateDirectory`, `ConfigurationDirectory`, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted address families, and only required write paths.
8. Package with a locked dependency set and documented install/upgrade/rollback commands.
9. Preserve a manual `primary_only` override that works even when DOA/policy data is bad.

**Verification:** install into an isolated local VM/container or temporary systemd-capable environment; start, stop, restart, crash-recover, upgrade, and rollback while the four fake modems run.

---

## Phase 6: Repeater integration

**Objective:** Make the array manageable from openHop without coupling mesh routing to sector internals.

### 6A. Baseline integration (required)

Use the existing Repeater config path:

```yaml
radio_type: modem_tcp
modem_tcp:
  host: 127.0.0.1
  port: 5056
  token: "<array-gateway-token>"
```

No Core or Repeater behavior change is allowed until this path passes the real-driver test harness and a local Repeater smoke test.

### 6B. Product-aware integration (after baseline)

**Repeater files likely changed:**

- `repeater/config.py`
- `repeater/web/api_endpoints.py`
- `repeater/config_manager.py`
- `repeater/sensors/openhop_array.py` (new)
- `radio-settings.json`
- `config.yaml.example`
- OpenAPI and focused tests

**Work:**

1. Decide whether `array_tcp` is a first-class Repeater radio type or whether the transport remains `modem_tcp` plus an `array:` management section. Prefer the latter unless the wire behavior actually differs.
2. Add an optional management client/sensor for array health, per-sector online state, RF config drift, RX observations, TX queue depth, partial failures, and policy state.
3. Do not expose sector tokens.
4. Add validation and backup/import redaction for nested sector settings.
5. Keep single-modem and existing `radios[]` behavior unchanged.
6. Add explicit UI/manual controls for primary-only/degraded mode and sector active/standby state.
7. Update OpenAPI from source and regenerate UI clients; never hand-edit generated backend assets.

**Repeater tests:**

- existing `tests/test_multi_radio_stack.py` remains green;
- new virtual-array config/API/redaction tests;
- service unavailable at startup does not prevent HTTP/UI from coming up;
- reconnect restores config and RX without restarting Repeater;
- one array RX becomes one Repeater packet with correct selected RSSI/SNR.

---

## Phase 7: Core scope and decision gate

**V1 recommendation:** no topology-specific array scheduler in openHop Core. Keep Core talking to the array as one standard `TCPLoRaRadio`.

**Core work that is still worth doing independently:**

1. Fix the RF Fabric RX metadata race by carrying immutable `RadioReception` data, RSSI, SNR, and `radio_id` through Dispatcher instead of reading mutable `last_*` state later.
2. Add concurrency tests where two physical radio callbacks fire before either async Dispatcher task runs.
3. Add all-radio lifecycle ownership: atomic stack construction, rollback of already-started radios on failure, and shutdown/close of every registered endpoint rather than only the default radio.
4. Keep explicit endpoint TX selection, but do not turn generic `FabricRadio.send()` into implicit all-radio fan-out.
5. If sector-aware upstream extensions are later needed, add a negotiated capability/version command first. Do not silently teach Core proprietary `0x05/0x06` semantics without protocol ownership and fallback rules.

**Native-array alternative (not v1):** If operating a second daemon proves unacceptable, implement a dedicated `SectorArrayRadio` adapter in Core on top of `RFFabric`, then move the coalescer, scheduler, lockout barriers, and transaction aggregation there. Repeater would add `fabric.tx_mode: sector_array`. This is more invasive because Repeater's duty-cycle, send timeout, status, live config, and UI all need to understand that one logical send may create several physical transmissions. Do not attempt this until the separate-service reference behavior and tests exist.

---

## Phase 8: Modem scope

**Expected production change:** none for the four-radio topology.

Current openHop Modem already provides the required one-radio endpoint and supports appropriate wired hardware, including RAK4631 + RAK13800/W5100S.

Only change Modem if tests reveal a concrete missing primitive:

1. Verify `RADIO_STANDBY` and `RADIO_RESUME` acknowledgements and state transitions on every selected board target.
2. Verify reconnect/auth/config reapply and asynchronous RX under sustained TCP traffic.
3. Add a capabilities/version query only if the array needs to distinguish command support safely.
4. Keep one-client semantics. The array is the client; allowing multiple competing host controllers would make radio ownership ambiguous.
5. Do not add Hydra's controller-only RX-v2/directed-TX commands to every modem merely to mirror its source tree.
6. Explicitly test the modem's approximately 4.5-second TX timeout against every supported RF profile intended for array use. If a legal packet can exceed it, fix that bounded firmware timeout in a separate scoped Modem change; do not paper over a modem-side abort with host retries.

Run full native/host protocol tests and build every affected firmware environment. Real board/RF claims require actual hardware verification.

---

## Phase 9: RepeaterUI and documentation

**UI work (separate source worktree):**

- array summary card: online/active sectors, degraded reason, queue state;
- per-sector table: stable ID, name, address, azimuth, board/version, link state, last RX/noise, config drift;
- policy selector with plain descriptions;
- manual primary-only and sector active/standby controls;
- warning before sequential-all because it multiplies airtime;
- no token hydration or display.

Do not overload the current `default/sticky/bridge` selector with `sector_array` until backend semantics exist. Build and test the Vue source, then integrate the exact artifact through the established UI → Core → Repeater order.

**Docs:** topology diagram, supported hardware, four unique addresses/tokens, array/repeater port separation, DHCP reservations, switch/PoE requirements, RF isolation, regulatory airtime, install/rollback, failure modes, and an attribution section for itk80/HydraCore.

---

## Phase 10: Hardware and live verification

**No hardware verification has been done yet.** Use an explicitly selected lab node; do not deploy to the existing production/dev repeater as part of implementation by default.

1. Start with four fake modems, then four real modems at minimum legal/safe power into attenuated/shielded test paths where possible.
2. Confirm unique IPs, tokens, board IDs, firmware versions, and identical RF settings.
3. Verify four simultaneous RX observations of one injected packet become one selected upstream RX.
4. Measure the coalescing window on the actual Ethernet switch and choose a bounded value from evidence.
5. Verify with timestamps/logic analysis that sector TX is serialized and standby barriers complete before RF starts.
6. Exercise direct best-sector, flood sequential policy, offline sector, reconnect during RX, disconnect during TX, stale DOA, queue saturation, and service restart.
7. Verify self-TX echoes never re-enter Repeater as fresh RX.
8. Measure per-sector and aggregate airtime; confirm configured policy stays within the applicable regional rules.
9. Verify management/API authentication and that no token appears in logs, browser responses, metrics, backups, or support bundles.
10. Run a soak test long enough to cover reconnect backoff, DOA persistence/expiry, queue pressure, and SQLite rotation.
11. Roll back to one direct modem and verify Repeater resumes without config reconstruction.
12. Perform the critical desense test: while one sector transmits, inject controlled signals into the other three receivers and measure loss/overload. Validate antenna spacing, polarization, shielding, coax routing, filtering, intermodulation, aggregate peak current, and thermal behavior before considering any parallel TX policy.

---

## Final acceptance criteria

- Repeater sees one stable logical radio and processes each over-the-air packet once.
- Best-copy claims are backed by a real bounded observation window, not first-arrival behavior.
- Direct and flood TX policies are explicit, testable, and serialized by default.
- Accepted TX requests are queued and receive exactly one honest result.
- Partial sector failures cannot masquerade as full success.
- All sector config remains synchronized or the array reports degraded/not-ready.
- Standard current Core works in baseline mode; extensions are negotiated rather than assumed.
- Existing single-radio and generic RF Fabric behavior remain unchanged.
- openHop Modem remains a one-radio device; four-radio coordination lives in the new service.
- Service install, restart, upgrade, rollback, metrics, authentication, and secret redaction are verified.
- Local tests, lint, package build, and fake-modem integration pass.
- Physical behavior is claimed only after the four-radio hardware matrix passes.
- Attribution to itk80 is preserved, and public redistribution waits for explicit licensing clarity.
