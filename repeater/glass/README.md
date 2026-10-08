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
switch HTTP transport. The live HTTP producer still emits v1 and `/inform` explicitly
rejects non-v1 outbound payloads before any network operation. An authenticated
v2 HTTP route/dispatcher belongs to later work; enrolled MQTT telemetry below
uses its own v2 stable-identity envelope.

## Enrolled MQTT credentials and telemetry

Explicit enrollment stores a private, node-owned key/certificate/token JSON
bundle. When `managed.json` enables MQTT for that enrolled node, the handler
requires `mqtt_tls_enabled: true`, `glass.verify_tls: true`, the exact managed
prefix `glass`, and no MQTT username/password override. The actual client leaf
CN is validated as `device:<canonical UUID>` before Paho receives it.
Ordinary Repeater `mqtt_brokers` settings are not changed.

`mqtt_credentials.materialize_credentials` loads and validates the enrollment
bundle (origin, identity, signature, validity, key match, serial and expiry),
then stages `ca.pem`, `client.pem`, and `client.key` in a private mode-0700
`cert_store_dir/mqtt-credentials/<SHA256 leaf fingerprint>` directory. Every
file is owned by the runtime user and mode 0600; inherited ACLs are removed.
Symlinked directory components/files and non-private existing files or ACLs
fail closed. All files are fsynced and read back/cryptographically validated
before the complete directory is atomically renamed, followed by parent fsync.
Existing fingerprint directories are verified, never overwritten. Failed
staging preserves previously published directories; there is no mutable
"current" pointer, automatic old-credential deletion or rotation endpoint.

Because Paho reopens these filenames, **every component from `/` through the
store directory** must be root/runtime-owned and not group/world-writable.
Root/runtime-owned sticky directories are permitted only with trusted-owned
next components: sticky semantics prevent other users from renaming those
entries. Access POSIX ACLs are rejected conservatively, including masked named
writers; default ACLs alone are permitted and stripped from new private
children. Symlinks in any component and `..` traversal are rejected before
normalization. Existing ancestry is never chmod'ed or otherwise repaired.
Previously materialized directories/files must remain root/runtime-owned,
private and ACL-free. This protects against other local users, **not compromise
of root or the runtime UID**, which can replace trusted-owned paths or alter
permissions after validation.

Runtime reloads parse and validate a detached candidate before committing any
settings or identity. Any reload failure closes and invalidates MQTT, retains
the prior consistent settings, and emits only a generic safe exception. MQTT
cannot restart or publish until a later reload succeeds. A successful identity
or TLS-settings change also invalidates the old publisher before committing;
reconnection and its successful callback are still required for publishing.

These MQTT-specific paths never replace `glass.ca_cert_path`: that remains the
administrator-provisioned HTTPS trust root (or system roots when unset).
The returned device CA is **not HTTPS trust**. Paho receives the dedicated
MQTT CA/client/key paths and `CERT_REQUIRED` with hostname verification.

Enrolled records publish on `glass/device:<UUID>/packet`, `/advert`, or
`/event/<name>`. Their version-2 envelopes include `device_id`, the identical
`topic`, and display-only `node_name`; renaming the node does not change its
topic. Unenrolled observation publishers retain their legacy v1/name topics,
but the new identity-scoped broker does **not** authorize them: reenrollment
is required, not a permissive catch-all ACL.

The MQTT runtime signature includes the validated leaf fingerprint, so a new
bundle at the same enrollment JSON path closes/reinitializes Paho. Staging or
issuance alone is not a verified installation/reconnection: `cert_expires_at`
is populated from the actual connection's validated leaf only after Paho's
successful connect callback. Failed/stale callbacks cannot acknowledge a new
certificate. CSR rotation, installation-report semantics and real-broker
renewal/ACL proof are separate follow-up work, not implemented here.

## Inactive durable pending CSR helper (Task5(c1) only)

`rotation_state.prepare_rotation(credentials, *, store_dir)` accepts an already
loaded enrollment bundle and revalidates its HTTPS origin, stable device ID,
operational token and currently valid key/certificate/CA using the enrollment
helpers **before touching state**. It performs no network requests and is not
called by the handler. Expired-certificate recovery requires a future explicit
loader; it is not silently enabled here.

The administrator-provisioned store uses the same strict ancestry checks as
MQTT materialization. Its runtime-owned, ACL-free `rotation-state` directory
must be mode 0700; the fixed `.lock` and `pending.json` must be regular,
runtime-owned, ACL-free mode-0600 files. Existing unsafe paths fail rather than
being repaired. New private entries have inherited POSIX ACLs stripped.
A no-follow directory-FD lock with exclusive `flock` serializes preparation
across threads and processes.

The bounded (32768-byte) version-1 pending JSON contains only `version`,
`base_url`, `device_id`, `generation_sha256`, `request_id`, `private_key` and
`csr_pem`. The enrollment generation is SHA256 of the ASCII operational token,
**not the current certificate serial**. No token, current certificate or
installation report is persisted here. A new RSA-2048 key and SHA256 CSR with
CN `device:<UUID>` are generated once; subsequent calls/restarts reuse the
exact persisted request UUID, key and CSR. Invalid state, different origin,
identity or generation fails closed without overwriting; recovery is future
work. The private key is canonical PKCS8 PEM and the CSR signature, identity
and public-key match are checked on readback.

Under the lock, preparation stages a private file, flushes/fsyncs it, atomically
replaces `pending.json`, fsyncs the directory and reads back/validates before
returning **only** `device_id`, `request_id` and `csr_pem`. Pre-replace failures
remove staging; post-replace failures return no result and do not fake a
rollback. A retry reuses the published state. Issuance, installation, MQTT
activation, installation acknowledgements and real-broker authorization proof
are **not** implemented by this helper or claimed as Task5 completion.

## Parity and provenance

All 13 files in `tests/fixtures/glass` (12 JSON envelopes/producer examples plus
the canonical provenance README) were copied or verified byte-identical against
Glass `backend/tests/fixtures/repeater`. Existing legacy producer JSON is
unchanged. Historical `proposed_v2_*.json` names now hold canonical Task3 data,
not live producer output. `tests/test_glass_contracts.py` mirrors canonical
runtime tests, replacing Pydantic-specific exception expectations with stdlib
errors and omitting JSON Schema assertions. Handler tests retain real legacy
builder diagnostics and assert eligibility never changes live v1 emission.

## Inactive offline renewal candidate validation (Task5(c2) only)

`rotation_state.validate_renewal_candidate(credentials, response, *, store_dir)`
returns an **internal, secret-bearing replacement enrollment bundle**, not a
public response or installation acknowledgement. Never log or expose it.
The helper is not called by the handler and performs no HTTP/MQTT operations,
credential installation, configuration changes or activation.

The current enrollment is revalidated first, including current certificate
validity: expired-current recovery remains unsupported. The helper opens only
an **existing** private `rotation-state`, fixed `.lock` and `pending.json` using
c1's ancestry, ownership, ACL, no-follow and exclusive-flock policy. Missing or
invalid state fails without generating a request/key, creating directories or
files, repairing permissions, deleting pending state or writing credential data.
All opened descriptors (including the lock) are closed on success or failure.

The response must contain exactly `device_id`, `request_id`, `client_cert`,
`ca_cert`, `cert_serial`, `expires_at`, `fingerprint_sha256` and `state`, all
strict strings. Device and request must match validated persisted pending state;
state must be `issued`. Serial is positive lowercase hex (at most 40 characters),
fingerprint is 64 lowercase hex characters, each PEM is ASCII and at most 14000
characters, expiry is a timezone-aware ISO timestamp of at most 64 characters,
and compact JSON is bounded to 65536 bytes. Leaf and CA must each be a single
canonical PEM certificate; tolerated prefixes, suffixes and chains are rejected.
Returned CA DER must match the current pinned issuing CA DER exactly: CA rotation
and HTTPS trust provisioning are not supported here.

The explicitly constructed candidate preserves `base_url`, `device_id`,
`pubkey` and the existing HTTP `operational_token`, uses the **persisted pending
private key** (never the old enrollment key), and carries the issued certificates,
serial, expiry, `rotation_request_id` and `fingerprint_sha256`. Enrollment's
certificate validation checks identity, signature, validity, client usage, key
match and serial/expiry metadata; the leaf DER SHA256 fingerprint must also match
the response. Failures raise sanitized `EnrollmentError` without secret detail.

Returning a candidate is **not installation or Task5 completion**. Pending state
and the current credential file remain unchanged. Atomic installation, completed
request retirement, MQTT reconnect/report lifecycle and real-broker renewal,
revocation and ownership proof remain separate gated slices.

## Inactive offline atomic bundle installation (Task5(c3) only)

`rotation_state.install_renewal_candidate(credentials, response, *, store_dir,
credential_file)` is a trusted **internal offline** API, not a handler or HTTP
file-write endpoint. The explicit filename must be absolute, without parent
traversal or symlink ancestry, under an existing safe provisioned directory.
The existing target must be runtime-owned, regular, ACL-free and mode 0600;
missing, corrupt, oversized or unsafe files fail without creation or repair.
Rotation-state filenames and its directory are not valid credential targets.

The existing fixed rotation lock covers pending state, journal/current reads,
candidate certificate validation, replacement and final readback. The pure c2
candidate builder is shared without nested flock acquisition. Current enrollment
validity remains required; expired-current recovery and issuing-CA rotation are
not enabled. No HTTPS trust settings or immutable MQTT TLS directories change.

Before changing the bundle, the helper durably publishes one private
`rotation-state/install.json` journal, bounded to 131072 bytes. It contains
exactly version 1, origin/device/token-generation binding, request ID, the exact
absolute lexical credential filename, the last-good `previous_bundle`, and
`previous_sha256`/`candidate_sha256`. Both bundles are bounded to 65536 canonical
JSON bytes; digests use SHA256 of compact UTF-8 JSON with sorted keys. Candidate
secrets are derived from pending state plus the response, not duplicated in the
journal. **The journal is secret-bearing backup material: never expose or log it.**
Existing journal bytes are validated and reused, never repaired or replaced.
A different request, generation, path, candidate or foreign current file fails
closed. The journal and pending CSR remain intact for explicit future retirement
and recovery; this bounds one uncertain rotation, not multiple renewal cycles.

The candidate is staged privately beside the existing credential file,
flushed/fsynced, privately read back and cryptographically validated before
atomic dirfd replacement. An immediate reread checks the current file has not
changed since the initial snapshot; this is a cooperating-writer guard, not an
administrator cross-process merge guarantee. The parent is fsynced and the
installed bundle validated again before success. Pre-replace failures preserve
old credential bytes and clean only this call's staging files. Postpublication
or post-replace failures return sanitized errors **without pretending rollback**.
Retries accept only the validated original or exact candidate caller/current
bundle, preserve journal/pending bytes, fsync uncertain directories, and do not
rewrite an already installed candidate. Descriptors and the lock are released
also when cleanup fails.

The public receipt contains only `device_id`, `request_id`, `cert_serial`,
`fingerprint_sha256`, `expires_at`, and `state: "bundle_installed"`. This means
**offline bundle installation/readback**, not MQTT materialization, successful
connection callback, server installation acknowledgment, delivery or broker
proof. There are no handler calls, network operations, activation, reporting or
pending/journal retirement in this slice; those remain separate gated work.

## Verified HTTPS renewal and handler cutover (Task5(c4))

This section supersedes the historical inactivity statements above only for
transport orchestration and handler activation. `rotation_transport.renew_credentials`
loads valid current credentials, durably prepares/reuses the exact pending CSR,
then posts only device ID, request ID and CSR to the verified HTTPS origin's
`/device/certificates/renew` using the current operational bearer. The existing
bounded, no-redirect transport preserves configured HTTPS CA trust; returned
MQTT CA material is never added to HTTPS trust. The c3 installer validates and
atomically installs the response and returns only its public installation receipt.
If the current bundle already carries the pending rotation request ID, retry
reconstructs the issued response from that bundle and reconciles installation
without another HTTP request. All failures are sanitized; pending and backup
state survive uncertain responses/installations.

`rotation_pending` is an existing-only, no-follow, runtime-owned, ACL-free,
locked read-only probe. Missing store/state/pending returns false; unsafe state,
missing fixed lock, duplicate fields, non-object or oversized JSON fails closed.
Actual CSR/context validation occurs during renewal preparation.

After successful inform response handling, enrolled enabled handlers serialize
maintenance with an async lock. A validated leaf expiring within 24 hours or
existing pending state triggers reconciliation. Probe, transport, cryptography
and post-install materialization run on a detached snapshot in a worker thread.
A configuration/binding change while working invalidates the old publisher and
cannot activate the stale snapshot. Otherwise existing fingerprint-aware reload
and MQTT synchronization replace the client, retaining current-client callback
checks and requiring a fresh successful connect callback for readiness.
Maintenance failures emit a fixed warning without failing a successful inform;
poll-loop runtime reload failures are contained and enrolled errors sanitized.

Only one pending renewal cycle is supported until explicit future completed
request/journal retirement. No expired-current recovery, legacy enrollment
fallback, new command/capability, reports, exact acknowledgment, retirement or
real broker/HTTPS proof is implemented here. Tests use real synthetic PKI and
mocked HTTPS/Paho, not a live broker or HTTPS server.
