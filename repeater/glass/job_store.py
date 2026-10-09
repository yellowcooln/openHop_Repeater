"""Private bounded execution ledger; trusted internal callbacks, never wire dispatch.

One runtime UID is trusted. All operations open the fixed flock; execute holds it
through the callback and outcome commit. A surviving START is uncertainty, not
permission to repeat an effect. SQLite FULL + explicit file/directory fsync fences
receipt, start, outcome and exact acceptance. No operational secrets are stored.
"""

import fcntl
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from repeater.glass import mqtt_credentials as m
from repeater.glass.contracts import (
    JobV2,
    QueryV2,
    ResultAcceptanceV2,
    ResultV2,
    canonical_json,
    checked_json,
    digest_value,
    result_sha256,
    utc_value,
    uuid_value,
)
from repeater.glass.enrollment import validate_https_url
from repeater.glass.rotation_state import _check_private

MAX_ROWS = 256
MAX_PENDING = 64
MAX_PHASES = 8
MAX_BYTES = 32 * 1024 * 1024
_fsync = os.fsync
_TERMINAL = {"succeeded", "failed", "unsupported", "conflict"}


def ledger_context(credentials, credential_file):
    """Generation excludes the rotating leaf; caller has loaded valid credentials."""
    path = os.fspath(credential_file)
    if not os.path.isabs(path) or os.path.normpath(path) != path or ".." in path.split("/"):
        raise ValueError("Invalid credential filename")
    return {
        "device_id": str(uuid_value(credentials["device_id"])),
        "base_url": validate_https_url(credentials["base_url"]),
        "credential_file": path,
        "generation_sha256": hashlib.sha256(
            credentials["operational_token"].encode("ascii")
        ).hexdigest(),
    }


def _clock(now=None):
    return utc_value(now) if now is not None else datetime.now(timezone.utc)


def _json(value):
    checked_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class JobStore:
    def __init__(self, context, store_dir):
        if type(context) is not dict or set(context) != {
            "device_id",
            "base_url",
            "credential_file",
            "generation_sha256",
        }:
            raise ValueError("Invalid ledger context")
        uuid_value(context["device_id"])
        digest_value(context["generation_sha256"])
        if validate_https_url(context["base_url"]) != context["base_url"]:
            raise ValueError("Noncanonical ledger origin")
        path = context["credential_file"]
        if type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path:
            raise ValueError("Invalid credential filename")
        self.context = dict(context)
        self.store_dir = os.fspath(store_dir)
        with self._locked() as (db, directory):
            self._recover(db, directory, _clock())

    @contextmanager
    def _locked(self):
        store = directory = lock = db = None
        try:
            store = m._open_directory(self.store_dir)
            try:
                os.mkdir("execution-ledger", 0o700, dir_fd=store)
                new = True
            except FileExistsError:
                new = False
            directory = os.open("execution-ledger", m._DIR_FLAGS, dir_fd=store)
            if new:
                os.fchmod(directory, 0o700)
                m._strip_acls(directory)
            _check_private(directory, directory=True)
            lock = self._private_file(directory, ".lock")
            fcntl.flock(lock, fcntl.LOCK_EX)
            _check_private(directory, directory=True)
            _check_private(lock)
            # Reject every unexpected entry and unsafe side file before SQLite
            # can interpret a hot journal. Never chmod an existing file.
            self._check_files(directory)
            fd = self._private_file(directory, "ledger.sqlite")
            os.close(fd)
            _fsync(directory)
            _fsync(store)
            db = sqlite3.connect(f"/proc/self/fd/{directory}/ledger.sqlite", timeout=30)
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA page_size=4096")
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            if page_size != 4096:
                raise ValueError("Unexpected ledger page size")
            db.execute(f"PRAGMA max_page_count={MAX_BYTES // page_size}")
            if db.execute("PRAGMA page_count").fetchone()[0] * page_size > MAX_BYTES:
                raise ValueError("Ledger page budget exceeded")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unknown ledger schema")
            db.execute(
                "CREATE TABLE IF NOT EXISTS context (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, request_id TEXT NOT NULL, execution_id TEXT, body TEXT NOT NULL)"
            )
            saved = db.execute("SELECT body FROM context WHERE id=1").fetchone()
            if saved is None:
                if db.execute("SELECT count(*) FROM records").fetchone()[0]:
                    raise ValueError("Missing ledger context")
                db.execute("INSERT INTO context VALUES (1,?)", (_json(self.context),))
                db.execute("PRAGMA user_version=1")
                self._commit(db, directory)
            elif saved[0] != _json(self.context):
                raise ValueError("Ledger enrollment context changed")
            self._check_files(directory)
            yield db, directory
        finally:
            if db is not None:
                db.close()
            for fd in (lock, directory, store):
                if fd is not None:
                    os.close(fd)

    @staticmethod
    def _private_file(directory, name):
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            new = True
        except FileExistsError:
            fd = os.open(name, flags, dir_fd=directory)
            new = False
        try:
            if new:
                os.fchmod(fd, 0o600)
                m._strip_acls(fd)
            _check_private(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _check_files(directory):
        for name in os.listdir(directory):
            if name not in {".lock", "ledger.sqlite", "ledger.sqlite-journal"}:
                raise ValueError("Unexpected ledger file")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                _check_private(fd)
                if os.fstat(fd).st_nlink != 1:
                    raise ValueError("Ledger hardlinks forbidden")
            finally:
                os.close(fd)

    def _commit(self, db, directory):
        self._check_files(directory)
        db.commit()
        fd = os.open("ledger.sqlite", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            _check_private(fd)
            _fsync(fd)
        finally:
            os.close(fd)
        _fsync(directory)
        self._check_files(directory)

    def _records(self, db):
        rows = db.execute("SELECT key, body FROM records ORDER BY rowid").fetchall()
        if len(rows) > MAX_ROWS:
            raise ValueError("Ledger row budget exceeded")
        records = []
        for key, body in rows:
            if len(body.encode()) > 256 * 1024:
                raise ValueError("Ledger record budget exceeded")
            record = json.loads(body)
            checked_json(record)
            if set(record) != {
                "immutable",
                "offer",
                "state",
                "boot_id",
                "received_at",
                "phases",
                "result",
                "digest",
                "ack",
                "acked_at",
                "evidence",
                "verification_decision",
            }:
                raise ValueError("Invalid ledger record")
            request = self._request(record["offer"])
            expected_key, immutable, _ = self._identity(request)
            if (
                expected_key != key
                or _json(immutable) != _json(record["immutable"])
                or str(request.device_id) != self.context["device_id"]
            ):
                raise ValueError("Invalid ledger request binding")
            uuid_value(record["boot_id"])
            utc_value(record["received_at"])
            if type(record["phases"]) is not list or not 1 <= len(record["phases"]) <= MAX_PHASES:
                raise ValueError("Invalid phase budget")
            for phase in record["phases"]:
                if set(phase) not in (
                    {"state", "at", "boot_id"},
                    {"state", "at", "boot_id", "result", "digest", "ack", "acked_at"},
                ):
                    raise ValueError("Invalid persisted phase")
                utc_value(phase["at"])
                uuid_value(phase["boot_id"])
                if "result" in phase:
                    historical = ResultV2.model_validate(phase["result"])
                    historical.check_request(request)
                    receipt = ResultAcceptanceV2.model_validate(phase["ack"])
                    if (
                        historical.status != phase["state"]
                        or historical.boot_id != uuid_value(phase["boot_id"])
                        or result_sha256(historical) != phase["digest"]
                        or receipt.result_sha256 != phase["digest"]
                        or receipt.acceptance_id is None
                        or receipt.request_id != historical.request_id
                        or receipt.execution_id != historical.execution_id
                    ):
                        raise ValueError("Invalid historical phase acceptance")
                    utc_value(phase["acked_at"])
            if record["state"] not in _TERMINAL | {
                "received",
                "running",
                "unknown",
                "awaiting_verification",
            }:
                raise ValueError("Invalid execution state")
            if record["result"] is not None:
                result = ResultV2.model_validate(record["result"])
                result.check_request(request)
                if (
                    result_sha256(result) != record["digest"]
                    or result.status != record["state"]
                    or result.boot_id != uuid_value(record["boot_id"])
                    or result.lease_id != request.lease_id
                    or result.attempt != request.attempt
                    or len(canonical_json(result).encode()) > 65536
                ):
                    raise ValueError("Invalid saved outcome")
            elif record["state"] not in {"received", "running"}:
                raise ValueError("Missing saved outcome")
            if record["ack"] is not None:
                ack = ResultAcceptanceV2.model_validate(record["ack"])
                if (
                    ack.acceptance_id is None
                    or ack.result_sha256 != record["digest"]
                    or str(ack.request_id) != str(request.request_id)
                    or ack.execution_id != getattr(request, "execution_id", None)
                ):
                    raise ValueError("Invalid saved acceptance")
                utc_value(record["acked_at"])
            if record["verification_decision"] is not None:
                decision = ResultV2.model_validate(record["verification_decision"])
                decision.check_request(request)
                if (
                    record["state"] != "awaiting_verification"
                    or decision.status not in {"succeeded", "unknown"}
                    or decision.lease_id != request.lease_id
                    or decision.attempt != request.attempt
                ):
                    raise ValueError("Invalid verification decision")
            if record["evidence"] is not None:
                self._verification(record["evidence"])
            records.append((key, record))
        if sum(self._reserved(r) for _, r in records) > MAX_PENDING:
            raise ValueError("Ledger pending/reserved capacity exceeded")
        return records

    @staticmethod
    def _reserved(record):
        # ACKing an interim phase does not resolve its future outbox obligation.
        # UNKNOWN has no further transition in this ledger; a saved decision or
        # awaiting-verification timer/proof always retains its reservation.
        return (
            record["ack"] is None
            or record["state"] == "awaiting_verification"
            or record["verification_decision"] is not None
        )

    @staticmethod
    def _clamp(record, now):
        """Durable per-execution floor; never rewrite any prior wire body."""
        times = [now, utc_value(record["offer"]["created_at"]), utc_value(record["received_at"])]
        for phase in record["phases"]:
            times.append(utc_value(phase["at"]))
        bodies = [record["result"], record["verification_decision"]]
        bodies.extend(phase.get("result") for phase in record["phases"])
        for body in bodies:
            if body is not None:
                times.append(utc_value(body["sent_at"]))
                if body.get("completed_at") is not None:
                    times.append(utc_value(body["completed_at"]))
        return max(times)

    @staticmethod
    def _save(db, key, record):
        checked_json(record, byte_limit=256 * 1024)
        db.execute("UPDATE records SET body=? WHERE key=?", (_json(record), key))

    @staticmethod
    def _request(request):
        cls = JobV2 if (getattr(request, "type", None) or request.get("type")) == "job" else QueryV2
        # Revalidate even an existing Contract: its opaque params are mutable.
        value = request.model_dump(mode="json") if hasattr(request, "model_dump") else request
        result = cls.model_validate(value)
        if result.lease_id is None:
            raise ValueError("Delivery requires a lease")
        return result

    @staticmethod
    def _identity(request):
        offer = request.model_dump(mode="json")
        immutable = {
            k: v for k, v in offer.items() if k not in {"lease_id", "attempt", "lease_expires_at"}
        }
        key = (
            ("job:" + str(request.execution_id))
            if isinstance(request, JobV2)
            else (f"query:{request.request_id}:{request.lease_id}:{request.attempt}")
        )
        return key, immutable, offer

    def _outcome(self, record, status, now, **values):
        request = self._request(record["offer"])
        now = self._clamp(record, now)
        result = ResultV2(
            type="result",
            version=2,
            device_id=request.device_id,
            boot_id=record["boot_id"],
            sent_at=now,
            request_id=request.request_id,
            execution_id=getattr(request, "execution_id", None),
            status=status,
            completed_at=now if status in _TERMINAL else None,
            lease_id=request.lease_id,
            attempt=request.attempt,
            **values,
        )
        result.check_request(request)
        if len(canonical_json(result).encode()) > 65536:
            raise ValueError("Result byte budget exceeded")
        # Preserve the exact acknowledged prior phase before publishing another
        # outcome. Current unacknowledged wire bodies may never be overwritten.
        if record["result"] is not None:
            if record["ack"] is None:
                raise ValueError("Unacknowledged outcome cannot be replaced")
            record["phases"][-1].update(
                result=record["result"],
                digest=record["digest"],
                ack=record["ack"],
                acked_at=record["acked_at"],
            )
        record.update(
            state=status,
            result=result.model_dump(mode="json"),
            digest=result_sha256(result),
            ack=None,
            acked_at=None,
        )
        record["phases"].append(
            {"state": status, "at": now.isoformat(), "boot_id": record["boot_id"]}
        )
        if len(record["phases"]) > MAX_PHASES:
            raise ValueError("Ledger phase budget exceeded")
        return result

    def _publish_decision(self, record):
        decision = record["verification_decision"]
        if decision is None or record["ack"] is None:
            return False
        result = ResultV2.model_validate(decision)
        if record["state"] != "awaiting_verification" or not self._reserved(record):
            raise ValueError("Verification publication has no reserved slot")
        if result.sent_at < self._clamp(record, result.sent_at):
            raise ValueError("Verification decision predates durable phase")
        if len(record["phases"]) >= MAX_PHASES:
            raise ValueError("Ledger phase budget exceeded")
        record["phases"][-1].update(
            result=record["result"],
            digest=record["digest"],
            ack=record["ack"],
            acked_at=record["acked_at"],
        )
        record.update(
            state=result.status,
            boot_id=str(result.boot_id),
            result=decision,
            digest=result_sha256(result),
            ack=None,
            acked_at=None,
            verification_decision=None,
        )
        record["phases"].append(
            {
                "state": result.status,
                "at": result.sent_at.isoformat(),
                "boot_id": str(result.boot_id),
            }
        )
        return True

    def _recover(self, db, directory, now):
        changed = False
        for key, record in self._records(db):
            if record["state"] == "received":
                request = self._request(record["offer"])
                if now < min(request.expires_at, request.lease_expires_at):
                    continue
                # Receipt without START proves no callback was admitted. Resolve
                # only the original authority, never a retry lease or boot, and
                # retain its reserved outbox slot until exact Glass acceptance.
                self._outcome(
                    record, "failed", now, applied=False, error_code="expired_before_start"
                )
                self._save(db, key, record)
                changed = True
            elif record["state"] == "running":
                self._outcome(
                    record,
                    "unknown",
                    now,
                    error_code="interrupted",
                    message="Execution outcome unavailable",
                )
                self._save(db, key, record)
                changed = True
        if changed:
            self._commit(db, directory)

    def _receive(self, db, directory, request, boot_id, capabilities, now):
        uuid_value(boot_id)
        if str(request.device_id) != self.context["device_id"]:
            raise ValueError("Ledger device mismatch")
        key, immutable, offer = self._identity(request)
        records = self._records(db)
        for prior_key, prior in records:
            a, b = immutable, prior["immutable"]
            same_identity = (
                a["request_id"] == b["request_id"]
                or (isinstance(request, JobV2) and b.get("execution_id") == a["execution_id"])
                or (isinstance(request, JobV2) and b.get("idempotency_key") == a["idempotency_key"])
            )
            if same_identity and _json(a) != _json(b):
                raise ValueError("Conflicting immutable request identity")
            if prior_key == key:
                if isinstance(request, QueryV2) and _json(prior["offer"]) != _json(offer):
                    raise ValueError("Conflicting delivery lease")
                return key, prior
        if not request.created_at <= now < min(request.expires_at, request.lease_expires_at):
            raise ValueError("Delivery lease or request expired")
        # Keep job tombstones for seven days. Acknowledged safe reads need only
        # survive their request window; retaining every poll for a week would
        # exhaust the bounded ledger. Never evict unknown/active/unacked work.
        for prior_key, prior in records:
            if (
                prior["state"] in _TERMINAL
                and prior["acked_at"]
                and (
                    now - utc_value(prior["acked_at"]) >= timedelta(days=7)
                    or (
                        prior["offer"]["type"] == "query"
                        and now >= utc_value(prior["offer"]["expires_at"])
                    )
                )
            ):
                db.execute("DELETE FROM records WHERE key=?", (prior_key,))
        records = self._records(db)
        if len(records) >= MAX_ROWS or sum(self._reserved(r) for _, r in records) >= MAX_PENDING:
            raise ValueError("Ledger capacity exhausted")
        record = {
            "immutable": immutable,
            "offer": offer,
            "state": "received",
            "boot_id": str(uuid_value(boot_id)),
            "received_at": now.isoformat(),
            "phases": [
                {"state": "received", "at": now.isoformat(), "boot_id": str(uuid_value(boot_id))}
            ],
            "result": None,
            "digest": None,
            "ack": None,
            "acked_at": None,
            "evidence": None,
            "verification_decision": None,
        }
        version = capabilities.get(request.action)
        if type(version) is not int or version != request.capability_version:
            self._outcome(record, "unsupported", now, applied=False, error_code="unsupported")
        db.execute(
            "INSERT INTO records VALUES (?,?,?,?)",
            (
                key,
                str(request.request_id),
                str(request.execution_id) if isinstance(request, JobV2) else None,
                _json(record),
            ),
        )
        self._commit(db, directory)
        return key, record

    def receive(self, request, boot_id, capabilities, now=None):
        """Persist receipt; return detached state or the exact existing result."""
        request = self._request(request)
        with self._locked() as (db, directory):
            self._recover(db, directory, _clock(now))
            _, record = self._receive(db, directory, request, boot_id, capabilities, _clock(now))
            return record["result"] or {"state": record["state"]}

    def execute(self, request, boot_id, executor, capabilities, now=None, commit_guard=None):
        """Return ResultV2 dict. executor(request) returns bounded outcome kwargs.

        Optional internal `verification` is persisted expected evidence, not wire
        params. Exceptions after START become UNKNOWN without leaking exceptions.
        START admission guard runs under flock. After admission no fake rollback.
        """
        request = self._request(request)
        with self._locked() as (db, directory):
            self._recover(db, directory, _clock(now))
            key, record = self._receive(db, directory, request, boot_id, capabilities, _clock(now))
            if record["result"] is not None:
                return record["result"]
            # A receipt fixes job authority to its original delivery lease.
            # Retry leases never renew it: validate and execute the same saved
            # offer that _outcome binds into the result, before durable START.
            request = self._request(record["offer"])
            # Reserve bounded outcome/page split headroom before START. An
            # executor must not be admitted into an already exhausted page cap.
            used_bytes = db.execute("PRAGMA page_count").fetchone()[0] * 4096
            if used_bytes + 128 * 1024 > MAX_BYTES:
                raise ValueError("Ledger outcome page capacity exhausted")
            if commit_guard is not None:
                commit_guard()
            # The runtime guard can block on credential/configuration ownership.
            # Sample authority time after that wait, immediately before START.
            current = _clock(now)
            request.check_acceptance(
                device_id=self.context["device_id"], capabilities=capabilities, now=current
            )
            if current >= request.lease_expires_at:
                raise ValueError("Delivery lease expired")
            current = self._clamp(record, current)
            record["boot_id"] = str(uuid_value(boot_id))
            record["state"] = "running"
            record["phases"].append(
                {"state": "running", "at": current.isoformat(), "boot_id": record["boot_id"]}
            )
            self._save(db, key, record)
            self._commit(db, directory)  # Fence BEFORE the only callback invocation.
            try:
                outcome = dict(executor(request))
                verification = outcome.pop("verification", None)
                status = outcome.pop("status")
                if status not in _TERMINAL | {"awaiting_verification", "unknown"}:
                    raise ValueError("Invalid executor outcome")
                if status == "awaiting_verification":
                    self._verification(verification)
                    record["evidence"] = verification
                self._outcome(record, status, _clock(now), **outcome)
            except Exception:  # noqa: BLE001 - an effect may have happened; sanitize uncertainty
                self._outcome(record, "unknown", _clock(now), error_code="outcome_unavailable")
            self._save(db, key, record)
            self._commit(db, directory)
            return record["result"]

    def pending_results(self, limit=64):
        if type(limit) is not int or not 1 <= limit <= MAX_PENDING:
            raise ValueError("Invalid result limit")
        with self._locked() as (db, directory):
            self._recover(db, directory, _clock())
            results, identities = [], set()
            for _, record in self._records(db):
                if record["result"] is not None and record["ack"] is None:
                    result = ResultV2.model_validate(record["result"])
                    identity = (result.request_id, result.execution_id)
                    if identity not in identities:
                        identities.add(identity)
                        results.append(result.model_dump(mode="json"))
            return results[:limit]

    def acknowledge(self, acceptances, offered_results, *, commit_guard=None):
        """Atomic exact offered-body ACK; return number newly acknowledged."""
        receipts = [
            ResultAcceptanceV2.model_validate(
                a.model_dump(mode="json") if hasattr(a, "model_dump") else a
            )
            for a in acceptances
        ]
        offered = [
            ResultV2.model_validate(r.model_dump(mode="json") if hasattr(r, "model_dump") else r)
            for r in offered_results
        ]
        if len(receipts) > 64 or len(offered) > 64:
            raise ValueError("ACK budget exceeded")
        if len({(a.request_id, a.execution_id) for a in receipts}) != len(receipts) or len(
            {(r.request_id, r.execution_id) for r in offered}
        ) != len(offered):
            raise ValueError("Duplicate acceptance/offer identity")
        with self._locked() as (db, directory):
            changes = []
            records = self._records(db)
            for ack in receipts:
                if ack.acceptance_id is None or ack.result_sha256 is None:
                    raise ValueError("Explicit exact acceptance required")
                matches = [
                    r
                    for r in offered
                    if (r.request_id, r.execution_id) == (ack.request_id, ack.execution_id)
                    and result_sha256(r) == ack.result_sha256
                ]
                if len(matches) != 1:
                    raise ValueError("Acceptance not exactly offered")
                offered_body = matches[0].model_dump(mode="json")
                matches = [
                    (k, r)
                    for k, r in records
                    if r["digest"] == ack.result_sha256 and r["result"] == offered_body
                ]
                if not matches:
                    historical = [
                        phase
                        for _, r in records
                        for phase in r["phases"]
                        if phase.get("digest") == ack.result_sha256
                        and phase.get("result") == offered_body
                        and phase.get("ack") == ack.model_dump(mode="json")
                    ]
                    if len(historical) == 1:
                        continue  # Old exact ACK retry never clears the next phase.
                if len(matches) != 1:
                    raise ValueError("Acceptance not in current outbox")
                key, record = matches[0]
                body = ack.model_dump(mode="json")
                if record["ack"] is not None and record["ack"] != body:
                    raise ValueError("Acceptance changed")
                if record["ack"] is None:
                    record.update(ack=body, acked_at=_clock().isoformat())
                    changes.append((key, record))
            if commit_guard is not None:
                commit_guard()  # Exact ACK admission under the fixed durable lock.
            for key, record in changes:
                self._publish_decision(record)
                self._save(db, key, record)
            if changes:
                self._commit(db, directory)
            return len(changes)

    @staticmethod
    def _verification(value):
        if type(value) is not dict or set(value) != {
            "expected_boot_id",
            "expected_version",
            "expected_revision",
            "ready_deadline",
        }:
            raise ValueError("Incomplete trusted verification expectation")
        uuid_value(value["expected_boot_id"])
        if any(
            type(value[k]) is not str or not 1 <= len(value[k]) <= 128
            for k in ("expected_version", "expected_revision")
        ):
            raise ValueError("Invalid verification expectation")
        digest_value(value["expected_revision"])
        utc_value(value["ready_deadline"])
        checked_json(value)

    def reconcile(self, boot_id, evidence, now=None):
        """Evidence is trusted LOCAL observation keyed by execution UUID, not HTTP.

        Require exact boot/version/canonical effective revision, readiness and
        nonnegative measured uptime. No proof by boot change or desired hash echo.
        """
        uuid_value(boot_id)
        with self._locked() as (db, directory):
            current = _clock(now)  # Implicit time must be sampled AFTER flock.
            self._recover(db, directory, current)
            changed, dirty = [], False
            for key, record in self._records(db):
                if (
                    record["state"] != "awaiting_verification"
                    or record["verification_decision"] is not None
                ):
                    continue
                expected = record["evidence"]
                self._verification(expected)
                actual = evidence.get(record["offer"].get("execution_id"), {})
                proven = (
                    str(boot_id) == expected["expected_boot_id"]
                    and actual.get("boot_id") == expected["expected_boot_id"]
                    and actual.get("software_version") == expected["expected_version"]
                    and actual.get("effective_revision") == expected["expected_revision"]
                    and actual.get("ready") is True
                    and type(actual.get("uptime_seconds")) is int
                    and actual["uptime_seconds"] >= 0
                )
                if proven and current <= utc_value(expected["ready_deadline"]):
                    status, values = (
                        "succeeded",
                        {"applied": True, "persisted": True, "restart_required": False},
                    )
                elif current >= utc_value(expected["ready_deadline"]):
                    status, values = "unknown", {"error_code": "verification_timeout"}
                else:
                    continue
                # Record the trusted observation/timeout now, even while an
                # older wire phase awaits ACK. Publication waits, evidence does
                # not: a lost ACK cannot erase valid predeadline local proof.
                candidate = dict(
                    record,
                    result=None,
                    digest=None,
                    ack=None,
                    acked_at=None,
                    phases=[],
                    boot_id=str(uuid_value(boot_id)),
                )
                self._outcome(candidate, status, self._clamp(record, current), **values)
                record["verification_decision"] = candidate["result"]
                if self._publish_decision(record):
                    changed.append(record["result"])
                self._save(db, key, record)
                dirty = True
            if dirty:
                self._commit(db, directory)
            return changed

    def cancel(self, execution_id):
        execution_id = str(uuid_value(execution_id))
        with self._locked() as (db, directory):
            rows = [
                (k, r)
                for k, r in self._records(db)
                if r["offer"].get("execution_id") == execution_id
            ]
            if not rows:
                return "not_found"
            key, record = rows[0]
            if record["state"] != "received":
                return "too_late"
            self._outcome(
                record,
                "failed",
                _clock(),
                applied=False,
                error_code="cancelled",
                message="Cancelled before execution",
            )
            self._save(db, key, record)
            self._commit(db, directory)
            return "cancelled"
