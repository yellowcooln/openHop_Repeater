"""Real SIGKILL/reopen durability probes. Synthetic file effects only, no RF."""

import copy
import json
import os
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from repeater.glass.contracts import ResultV2, result_sha256
from repeater.glass.job_store import JobStore, ledger_context

BOOT = "00000000-0000-4000-8000-000000000001"
CAPS = {"diagnostic.read": 1, "set_mode": 1}


@pytest.fixture
def private_store():
    # Secure existing ancestry, not pytest's possibly group-writable cache.
    # No permission repair or relaxed helper monkeypatches.
    with tempfile.TemporaryDirectory(prefix="node-ledger-test-", dir=Path.home()) as path:
        yield Path(path)


def context():
    return ledger_context(
        {"device_id": BOOT, "base_url": "https://glass.test", "operational_token": "A" * 43},
        "/home/node/credentials.json",
    )


def delivery(job=True):
    now = datetime.now(timezone.utc)
    value = {
        "type": "job" if job else "query",
        "version": 2,
        "device_id": BOOT,
        "request_id": str(uuid4()),
        "action": "set_mode" if job else "diagnostic.read",
        "capability_version": 1,
        "created_at": (now - timedelta(seconds=5)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "params": {"mode": "monitor"} if job else {},
        "expected_revision": None,
        "lease_id": str(uuid4()),
        "attempt": 1,
        "lease_expires_at": (now + timedelta(minutes=10)).isoformat(),
    }
    if job:
        value.update(execution_id=str(uuid4()), idempotency_key=str(uuid4()))
    return value


def acceptance(result):
    return {
        "request_id": result["request_id"],
        "execution_id": result["execution_id"],
        "acceptance_id": str(uuid4()),
        "result_sha256": result_sha256(ResultV2.model_validate(result)),
    }


def success(_):
    return {"status": "succeeded", "applied": True}


def kill_worker(path, boundary):
    payload = json.loads((Path(path) / "input.json").read_text())
    if "clock" in payload:
        from repeater.glass import job_store as module

        module._clock = lambda now=None: (
            datetime.fromisoformat(payload["clock"]) if now is None else now
        )
    store = JobStore(payload["context"], path)
    original = store._commit
    commits = 0

    def marker(name):
        if boundary == name:
            print(name, flush=True)
            sys.stdin.readline()  # Parent SIGKILLs an actual blocked process.

    def commit(db, directory):
        nonlocal commits
        original(db, directory)
        commits += 1
        boundaries = (
            {1: "start", 2: "result", 3: "ack"}
            if payload.get("received")
            else {1: "receipt", 2: "start", 3: "result", 4: "ack"}
        )
        marker(boundaries.get(commits))

    store._commit = commit

    def effect(_):
        with open(Path(path) / "effects", "ab") as stream:
            stream.write(b"effect\n")
            stream.flush()
            os.fsync(stream.fileno())
        marker("effect")
        return success(None)

    result = store.execute(payload["request"], BOOT, effect, CAPS)
    store.acknowledge([acceptance(result)], [result])


@pytest.mark.parametrize("boundary", ["receipt", "start", "effect", "result", "ack"])
def test_actual_sigkill_each_persistence_boundary(private_store, boundary):
    request = delivery()
    (private_store / "input.json").write_text(
        json.dumps({"context": context(), "request": request})
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from tests.test_glass_job_store import kill_worker; import sys; kill_worker(sys.argv[1],sys.argv[2])",
            str(private_store),
            boundary,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([child.stdout], [], [], 20)
        assert ready, "child did not reach crash boundary"
        assert child.stdout.readline().strip() == boundary
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)
        assert child.returncode == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    ledger = JobStore(context(), private_store)
    effects = private_store / "effects"
    before = effects.read_bytes() if effects.exists() else b""

    def retry(_):
        with effects.open("ab") as stream:
            stream.write(b"effect\n")
        return success(None)

    outcome = ledger.execute(request, str(uuid4()), retry, CAPS)
    after = effects.read_bytes() if effects.exists() else b""
    assert after.count(b"effect\n") == (0 if boundary == "start" else 1)
    assert outcome["status"] == ("unknown" if boundary in {"start", "effect"} else "succeeded")
    if boundary != "receipt":
        assert after == before
    if boundary == "ack":
        assert ledger.pending_results() == []
    else:
        assert ledger.pending_results() == [outcome]
    # Lost ACK and restarted boot leave SAME exact body/digest, never a fresh
    # outcome timestamp or re-enactment on a new delivery lease.
    newlease = dict(request, lease_id=str(uuid4()), attempt=2)
    assert ledger.execute(newlease, str(uuid4()), retry, CAPS) == outcome
    assert (effects.read_bytes() if effects.exists() else b"") == after


@pytest.mark.parametrize("job", [True, False])
@pytest.mark.parametrize("expiry", ["lease", "request"])
def test_sigkill_expired_receipt_is_durable_terminal_until_exact_ack(
    private_store, monkeypatch, job, expiry
):
    from repeater.glass import job_store as module

    now = datetime.now(timezone.utc)
    clock = [now]
    monkeypatch.setattr(
        module, "_clock", lambda value=None: value if value is not None else clock[0]
    )
    request = delivery(job)
    deadline = now + timedelta(minutes=1)
    request["lease_expires_at"] = deadline.isoformat()
    if expiry == "request":
        request["expires_at"] = deadline.isoformat()
    (private_store / "input.json").write_text(
        json.dumps({"context": context(), "request": request, "clock": now.isoformat()})
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from tests.test_glass_job_store import kill_worker; import sys; kill_worker(sys.argv[1], 'receipt')",
            str(private_store),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([child.stdout], [], [], 20)
        assert ready and child.stdout.readline().strip() == "receipt"
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)
        assert child.returncode == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    clock[0] = deadline  # Expiry is inclusive; lease-only expiry precedes request expiry.
    ledger = JobStore(context(), private_store)
    pending = ledger.pending_results()
    assert len(pending) == 1
    result = pending[0]
    assert result["status"] == "failed" and result["error_code"] == "expired_before_start"
    assert result["applied"] is False
    assert result["lease_id"] == request["lease_id"] and result["attempt"] == request["attempt"]
    assert result["boot_id"] == BOOT
    assert ResultV2.model_validate(result).completed_at == deadline
    assert ResultV2.model_validate(result).sent_at == deadline
    with ledger._locked() as (db, _):
        record = json.loads(db.execute("SELECT body FROM records").fetchone()[0])
        assert record["offer"]["lease_id"] == request["lease_id"]
        assert [phase["state"] for phase in record["phases"]] == ["received", "failed"]
        assert all(phase["boot_id"] == BOOT for phase in record["phases"])
    assert (
        ledger.execute(request, str(uuid4()), lambda _: pytest.fail("expired receipt effect"), CAPS)
        == result
    )
    if job:
        retry = dict(
            request,
            lease_id=str(uuid4()),
            attempt=2,
            lease_expires_at=(
                deadline + timedelta(minutes=5) if expiry == "lease" else deadline
            ).isoformat(),
        )
        assert (
            ledger.execute(retry, str(uuid4()), lambda _: pytest.fail("new lease effect"), CAPS)
            == result
        )
    clock[0] += timedelta(days=8)
    fresh = delivery()
    fresh.update(
        created_at=clock[0].isoformat(),
        expires_at=(clock[0] + timedelta(hours=1)).isoformat(),
        lease_expires_at=(clock[0] + timedelta(minutes=10)).isoformat(),
    )
    ledger.receive(fresh, BOOT, CAPS)
    assert JobStore(context(), private_store).pending_results() == [
        result
    ]  # Unacked terminal cannot age out.
    bad = dict(acceptance(result), result_sha256="0" * 64)
    with pytest.raises(ValueError):
        ledger.acknowledge([bad], [result])
    assert ledger.pending_results() == [result]
    ack = acceptance(result)
    assert ledger.acknowledge([ack], [result]) == 1
    assert ledger.acknowledge([ack], [result]) == 0
    assert JobStore(context(), private_store).pending_results() == []
    clock[0] += timedelta(days=7)
    newer = delivery()
    newer.update(
        created_at=clock[0].isoformat(),
        expires_at=(clock[0] + timedelta(hours=1)).isoformat(),
        lease_expires_at=(clock[0] + timedelta(minutes=10)).isoformat(),
    )
    ledger.receive(newer, BOOT, CAPS)
    with ledger._locked() as (db, _):
        records = ledger._records(db)
        assert len(records) == 2
        assert all(r["offer"]["request_id"] != request["request_id"] for _, r in records)
    assert not (private_store / "effects").exists()


@pytest.mark.parametrize("trigger", ["pending", "reconcile"])
def test_expired_receipts_keep_reservation_until_ack(private_store, monkeypatch, trigger):
    from repeater.glass import job_store as module

    clock = [datetime.now(timezone.utc)]
    monkeypatch.setattr(
        module, "_clock", lambda value=None: value if value is not None else clock[0]
    )
    ledger = JobStore(context(), private_store)
    deadline = clock[0] + timedelta(seconds=1)
    for _ in range(64):
        request = delivery()
        request["lease_expires_at"] = deadline.isoformat()
        ledger.receive(request, BOOT, CAPS)
    clock[0] = deadline
    if trigger == "reconcile":
        assert ledger.reconcile(str(uuid4()), {}) == []
        with ledger._locked() as (db, _):
            assert all(r["state"] == "failed" for _, r in ledger._records(db))
    pending = ledger.pending_results()
    assert len(pending) == 64
    assert all(r["error_code"] == "expired_before_start" for r in pending)
    with pytest.raises(ValueError, match="capacity"):
        ledger.receive(delivery(), BOOT, CAPS)
    ledger.acknowledge([acceptance(pending[0])], [pending[0]])
    ledger.receive(delivery(), BOOT, CAPS)
    with ledger._locked() as (db, _):
        records = ledger._records(db)
        assert len(records) == 65 and sum(ledger._reserved(r) for _, r in records) == 64
        assert max(len(r["phases"]) for _, r in records) == 2


def concurrent_worker(path):
    payload = json.loads((Path(path) / "input.json").read_text())
    store = JobStore(payload["context"], path)

    def effect(_):
        with open(Path(path) / "effects", "ab") as stream:
            stream.write(b"effect\n")
            stream.flush()
            os.fsync(stream.fileno())
        return success(None)

    print(json.dumps(store.execute(payload["request"], BOOT, effect, CAPS)), flush=True)


def test_simultaneous_real_processes_hold_executor_flock(private_store):
    request = delivery()
    (private_store / "input.json").write_text(
        json.dumps({"context": context(), "request": request})
    )
    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from tests.test_glass_job_store import concurrent_worker; import sys; concurrent_worker(sys.argv[1])",
                str(private_store),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(6)
    ]
    try:
        results = []
        for child in children:
            output, error = child.communicate(timeout=30)
            assert child.returncode == 0, error
            results.append(json.loads(output))
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    assert all(result == results[0] for result in results)
    assert (private_store / "effects").read_bytes() == b"effect\n"


@pytest.mark.parametrize("acknowledge_read", [True, False])
def test_expired_read_retention_preserves_unacked_results_and_job_tombstones(
    private_store, acknowledge_read
):
    store = JobStore(context(), private_store)
    query, job = delivery(False), delivery(True)
    for request in (query, job):
        outcome = store.execute(request, BOOT, success, CAPS)
        if request["type"] == "job" or acknowledge_read:
            store.acknowledge([acceptance(outcome)], [outcome])
    later = max(datetime.fromisoformat(q["expires_at"]) for q in (query, job)) + timedelta(
        seconds=1
    )
    incoming = delivery(False)
    incoming.update(
        created_at=later.isoformat(),
        expires_at=(later + timedelta(hours=1)).isoformat(),
        lease_expires_at=(later + timedelta(minutes=10)).isoformat(),
    )
    store.receive(incoming, BOOT, CAPS, now=later)
    with store._locked() as (db, _):
        records = store._records(db)
    ids = {r["offer"]["request_id"] for _, r in records}
    assert (query["request_id"] not in ids) is acknowledge_read
    assert job["request_id"] in ids
    assert incoming["request_id"] in ids


def test_guard_wait_cannot_admit_an_expired_delivery(private_store, monkeypatch):
    from repeater.glass import job_store as module

    request = delivery()
    instant = datetime.now(timezone.utc)
    monkeypatch.setattr(module, "_clock", lambda now=None: instant if now is None else now)
    store = JobStore(context(), private_store)
    effects = []

    def guard():
        nonlocal instant
        # Config/credential guard may wait for the real runtime mutex. Model
        # the lease expiring during that wait without a flaky timed sleep.
        instant = datetime.fromisoformat(request["lease_expires_at"]) + timedelta(seconds=1)

    with pytest.raises(ValueError, match="expired"):
        store.execute(
            request,
            BOOT,
            lambda offered: effects.append(offered) or success(offered),
            CAPS,
            commit_guard=guard,
        )
    assert effects == []
    results = store.pending_results()
    assert len(results) == 1
    assert results[0]["error_code"] == "expired_before_start"


def test_durable_start_commit_fault_is_unknown_not_repeated(private_store, monkeypatch):
    ledger = JobStore(context(), private_store)
    original = ledger._commit
    calls = []
    commits = 0

    def commit(db, directory):
        nonlocal commits
        original(db, directory)
        commits += 1
        if commits == 2:
            raise OSError("postcommit fsync uncertainty")

    monkeypatch.setattr(ledger, "_commit", commit)
    request = delivery()
    with pytest.raises(OSError):
        ledger.execute(request, BOOT, lambda _: calls.append(1), CAPS)
    reopened = JobStore(context(), private_store)
    outcome = reopened.execute(request, str(uuid4()), lambda _: calls.append(1), CAPS)
    assert outcome["status"] == "unknown" and not calls
    assert reopened.pending_results() == [outcome]


def test_result_size_and_corrupt_sidefile_fail_closed(private_store):
    ledger = JobStore(context(), private_store)
    result = ledger.execute(
        delivery(), BOOT, lambda _: {"status": "succeeded", "details": {"large": "x" * 65536}}, CAPS
    )
    assert result["status"] == "unknown"
    journal = private_store / "execution-ledger" / "ledger.sqlite-journal"
    journal.write_bytes(b"unsafe")
    os.chmod(journal, 0o644)
    with pytest.raises(ValueError):
        ledger.pending_results()
    journal.unlink()
    journal.symlink_to(private_store / "input.json")
    with pytest.raises(OSError):
        ledger.pending_results()


def test_actual_row_cap_and_acknowledged_retention(private_store):
    ledger = JobStore(context(), private_store)
    for _ in range(256):
        result = ledger.execute(delivery(), BOOT, success, CAPS)
        ledger.acknowledge([acceptance(result)], [result])
    with pytest.raises(ValueError, match="capacity"):
        ledger.execute(delivery(), BOOT, lambda _: pytest.fail("row cap effect"), CAPS)
    future = datetime.now(timezone.utc) + timedelta(days=8)
    request = delivery()
    request.update(
        created_at=(future - timedelta(seconds=1)).isoformat(),
        expires_at=(future + timedelta(hours=1)).isoformat(),
        lease_expires_at=(future + timedelta(minutes=1)).isoformat(),
    )
    assert ledger.execute(request, BOOT, success, CAPS, now=future)["status"] == "succeeded"
    with ledger._locked() as (db, _):
        assert db.execute("SELECT count(*) FROM records").fetchone()[0] == 1


def test_page_headroom_reserved_before_effect(private_store, monkeypatch):
    from repeater.glass import job_store as module

    ledger = JobStore(context(), private_store)
    monkeypatch.setattr(module, "MAX_BYTES", 128 * 1024)
    calls = []
    with pytest.raises(ValueError, match="page capacity"):
        ledger.execute(delivery(), BOOT, lambda _: calls.append(1), CAPS)
    assert not calls
    with ledger._locked() as (db, _):
        assert (
            json.loads(db.execute("SELECT body FROM records").fetchone()[0])["state"] == "received"
        )


def test_receipt_only_expired_lease_does_not_resume(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    ledger.receive(request, BOOT, CAPS)
    result = ledger.execute(
        request,
        str(uuid4()),
        lambda _: pytest.fail("expired receipt effect"),
        CAPS,
        now=datetime.now(timezone.utc) + timedelta(minutes=11),
    )
    assert result["status"] == "failed" and result["error_code"] == "expired_before_start"
    assert result["lease_id"] == request["lease_id"] and result["boot_id"] == BOOT


def test_receipt_retry_fresh_lease_cannot_renew_expired_authority(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    received_at = datetime.now(timezone.utc)
    ledger.receive(request, BOOT, CAPS, now=received_at)
    with ledger._locked() as (db, _):
        original = json.loads(db.execute("SELECT body FROM records").fetchone()[0])
    retry_at = received_at + timedelta(minutes=11)
    retry = dict(
        request,
        lease_id=str(uuid4()),
        attempt=2,
        lease_expires_at=(retry_at + timedelta(minutes=10)).isoformat(),
    )
    calls, guards = [], []
    result = ledger.execute(
        retry,
        str(uuid4()),
        lambda r: calls.append(r),
        CAPS,
        now=retry_at,
        commit_guard=lambda: guards.append(1),
    )
    assert calls == guards == []
    assert result["status"] == "failed" and result["error_code"] == "expired_before_start"
    assert result["lease_id"] == request["lease_id"] and result["attempt"] == request["attempt"]
    with ledger._locked() as (db, _):
        saved = json.loads(db.execute("SELECT body FROM records").fetchone()[0])
        assert saved["offer"] == original["offer"]
        assert saved["boot_id"] == original["boot_id"]
        assert [p["state"] for p in saved["phases"]] == ["received", "failed"]
    reopened = JobStore(context(), private_store)
    assert (
        reopened.execute(
            retry, BOOT, lambda _: pytest.fail("renewed receipt effect"), CAPS, now=retry_at
        )
        == result
    )
    assert reopened.pending_results() == [result]


@pytest.mark.parametrize("incoming_expired", [False, True])
def test_receipt_retry_executes_and_reports_original_offer(private_store, incoming_expired):
    ledger = JobStore(context(), private_store)
    request = delivery()
    now = datetime.now(timezone.utc)
    ledger.receive(request, BOOT, CAPS, now=now)
    with ledger._locked() as (db, _):
        original_offer = json.loads(db.execute("SELECT body FROM records").fetchone()[0])["offer"]
    retry_at = now + timedelta(seconds=1)
    retry = dict(
        request,
        lease_id=str(uuid4()),
        attempt=2,
        lease_expires_at=(now if incoming_expired else now + timedelta(minutes=20)).isoformat(),
    )
    calls = []

    def effect(received):
        calls.append(received.model_dump(mode="json"))
        return success(received)

    result = ledger.execute(retry, str(uuid4()), effect, CAPS, now=retry_at)
    assert calls == [original_offer]
    assert result["status"] == "succeeded"
    assert result["lease_id"] == original_offer["lease_id"]
    assert result["attempt"] == original_offer["attempt"]
    assert (
        ledger.execute(
            retry, BOOT, lambda _: pytest.fail("receipt replay effect"), CAPS, now=retry_at
        )
        == result
    )
    assert JobStore(context(), private_store).pending_results() == [result]
    with ledger._locked() as (db, _):
        assert (
            json.loads(db.execute("SELECT body FROM records").fetchone()[0])["offer"]
            == original_offer
        )


def test_generation_leaf_rotation_stable_and_strict_caps(private_store):
    credentials = {
        "device_id": BOOT,
        "base_url": "https://glass.test",
        "operational_token": "A" * 43,
        "fingerprint_sha256": "a" * 64,
    }
    assert ledger_context(credentials, "/node/credentials.json") == ledger_context(
        dict(credentials, fingerprint_sha256="b" * 64), "/node/credentials.json"
    )
    ledger = JobStore(context(), private_store)
    result = ledger.execute(
        delivery(), BOOT, lambda _: pytest.fail("boolean capability effect"), {"set_mode": True}
    )
    assert result["status"] == "unsupported"


def test_exact_ack_and_immutable_conflicts(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    result = ledger.execute(request, BOOT, success, CAPS)
    ack = acceptance(result)
    for bad in [
        dict(ack, result_sha256="0" * 64),
        dict(ack, execution_id=str(uuid4())),
        dict(ack, request_id=str(uuid4())),
        dict(ack, acceptance_id=None),
    ]:
        with pytest.raises(ValueError):
            ledger.acknowledge([bad], [result])
        assert ledger.pending_results() == [result]
    with pytest.raises(ValueError):
        ledger.acknowledge([ack], [dict(result, message="tampered")])
    assert ledger.acknowledge([ack], [result]) == 1
    assert ledger.acknowledge([ack], [result]) == 0
    assert ledger.pending_results() == []
    changed = copy.deepcopy(request)
    changed["params"]["mode"] = "forward"
    with pytest.raises(ValueError, match="immutable"):
        ledger.execute(changed, BOOT, success, CAPS)
    with pytest.raises(ValueError):
        JobStore(dict(context(), generation_sha256="b" * 64), private_store)
    with pytest.raises(ValueError):
        JobStore(dict(context(), base_url="https://other.test"), private_store)
    with pytest.raises(ValueError):
        JobStore(dict(context(), credential_file="/other/credentials.json"), private_store)


def test_query_replay_only_new_lease_reexecutes(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery(False)
    calls = []

    def read(_):
        calls.append(1)
        return {"status": "succeeded", "details": {"read": len(calls)}}

    first = ledger.execute(request, BOOT, read, CAPS)
    assert ledger.execute(request, BOOT, read, CAPS) == first
    second = ledger.execute(dict(request, lease_id=str(uuid4()), attempt=2), BOOT, read, CAPS)
    assert len(calls) == 2
    assert ledger.pending_results() == [first]  # unique identity per InformV2
    ledger.acknowledge([acceptance(first)], [first])
    assert ledger.pending_results() == [second]


def test_capacity_unsupported_permissions_and_fsync(private_store, monkeypatch):
    ledger = JobStore(context(), private_store)
    calls = []
    for _ in range(64):
        result = ledger.execute(delivery(), BOOT, lambda r: calls.append(r), {})
        assert result["status"] == "unsupported"
    assert not calls
    with pytest.raises(ValueError, match="capacity"):
        ledger.execute(delivery(), BOOT, success, CAPS)
    db = private_store / "execution-ledger" / "ledger.sqlite"
    assert db.stat().st_mode & 0o777 == 0o600
    assert db.parent.stat().st_mode & 0o777 == 0o700
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute("PRAGMA page_count").fetchone()[0]
            * conn.execute("PRAGMA page_size").fetchone()[0]
            <= 32 * 1024 * 1024
        )
    os.chmod(db, 0o644)
    with pytest.raises(ValueError):
        ledger.pending_results()
    os.chmod(db, 0o600)  # test-owned damage cleanup, not production repair
    from repeater.glass import job_store as module

    monkeypatch.setattr(module, "_fsync", lambda _: (_ for _ in ()).throw(OSError("injected")))
    with pytest.raises(OSError):
        ledger.execute(delivery(), BOOT, lambda r: calls.append(r), CAPS)
    assert not calls


def test_cancel_and_guard_before_start(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    ledger.receive(request, BOOT, CAPS)
    assert ledger.cancel(request["execution_id"]) == "cancelled"
    assert (
        ledger.execute(request, BOOT, lambda _: pytest.fail("cancelled effect"), CAPS)["error_code"]
        == "cancelled"
    )
    assert ledger.cancel(request["execution_id"]) == "too_late"
    other = delivery()

    def reject():
        raise ValueError("cancel before start")

    with pytest.raises(ValueError):
        ledger.execute(
            other, BOOT, lambda _: pytest.fail("unadmitted effect"), CAPS, commit_guard=reject
        )
    assert ledger.execute(other, BOOT, success, CAPS)["status"] == "succeeded"


def test_predeadline_proof_survives_lost_ack_and_reopen(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    now = datetime.now(timezone.utc)
    newboot = str(uuid4())
    expected = {
        "expected_boot_id": newboot,
        "expected_version": "v2",
        "expected_revision": "a" * 64,
        "ready_deadline": (now + timedelta(seconds=30)).isoformat(),
    }
    first = ledger.execute(
        request, BOOT, lambda _: {"status": "awaiting_verification", "verification": expected}, CAPS
    )
    proof = {
        "boot_id": newboot,
        "software_version": "v2",
        "effective_revision": "a" * 64,
        "ready": True,
        "uptime_seconds": 1,
    }
    assert ledger.reconcile(newboot, {request["execution_id"]: proof}, now=now) == []
    assert ledger.pending_results() == [first]
    reopened = JobStore(context(), private_store)
    assert reopened.reconcile(newboot, {}, now=now + timedelta(seconds=31)) == []
    ack = acceptance(first)
    reopened.acknowledge([ack], [first])
    second = reopened.pending_results()[0]
    assert second["status"] == "succeeded" and second["boot_id"] == newboot
    assert reopened.acknowledge([ack], [first]) == 0
    assert reopened.pending_results() == [second]
    with reopened._locked() as (db, _):
        record = json.loads(db.execute("SELECT body FROM records").fetchone()[0])
        assert record["phases"][-2]["result"] == first
        from repeater.glass.contracts import ResultAcceptanceV2

        assert record["phases"][-2]["ack"] == ResultAcceptanceV2.model_validate(ack).model_dump(
            mode="json"
        )


def test_restart_evidence_and_timeout_are_not_echo_success(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    now = datetime.now(timezone.utc)
    newboot = str(uuid4())
    expected = {
        "expected_boot_id": newboot,
        "expected_version": "v2",
        "expected_revision": "a" * 64,
        "ready_deadline": (now + timedelta(seconds=30)).isoformat(),
    }
    result = ledger.execute(
        request, BOOT, lambda _: {"status": "awaiting_verification", "verification": expected}, CAPS
    )
    assert ledger.reconcile(newboot, {}, now=now) == []
    assert ledger.pending_results() == [result]
    ledger.acknowledge([acceptance(result)], [result])
    assert (
        ledger.reconcile(
            newboot, {request["execution_id"]: {"boot_id": newboot, "ready": True}}, now=now
        )
        == []
    )
    proof = {
        "boot_id": newboot,
        "software_version": "v2",
        "effective_revision": "a" * 64,
        "ready": True,
        "uptime_seconds": 1,
    }
    good = ledger.reconcile(newboot, {request["execution_id"]: proof}, now=now)
    assert good[0]["status"] == "succeeded"
    request2 = delivery()
    pending = ledger.execute(
        request2,
        BOOT,
        lambda _: {"status": "awaiting_verification", "verification": expected},
        CAPS,
    )
    ledger.acknowledge([acceptance(pending)], [pending])
    unknown = ledger.reconcile(newboot, {}, now=now + timedelta(seconds=31))
    assert unknown[0]["status"] == "unknown" and unknown[0]["completed_at"] is None


@pytest.mark.parametrize("proof_before_ack", [False, True])
def test_acknowledged_verification_keeps_reserved_slot(private_store, proof_before_ack):
    ledger = JobStore(context(), private_store)
    request = delivery()
    now = datetime.now(timezone.utc)
    newboot = str(uuid4())
    expected = {
        "expected_boot_id": newboot,
        "expected_version": "v2",
        "expected_revision": "a" * 64,
        "ready_deadline": (now + timedelta(minutes=5)).isoformat(),
    }
    first = ledger.execute(
        request, BOOT, lambda _: {"status": "awaiting_verification", "verification": expected}, CAPS
    )
    proof = {
        "boot_id": newboot,
        "software_version": "v2",
        "effective_revision": "a" * 64,
        "ready": True,
        "uptime_seconds": 1,
    }
    if proof_before_ack:
        assert ledger.reconcile(newboot, {request["execution_id"]: proof}, now=now) == []
    else:
        ledger.acknowledge([acceptance(first)], [first])
    fresh = [ledger.execute(delivery(), BOOT, success, CAPS) for _ in range(63)]
    with pytest.raises(ValueError, match="capacity"):
        ledger.execute(delivery(), BOOT, lambda _: pytest.fail("unreserved effect"), CAPS)
    if proof_before_ack:
        ledger.acknowledge([acceptance(first)], [first])
    else:
        assert (
            ledger.reconcile(newboot, {request["execution_id"]: proof}, now=now)[0]["status"]
            == "succeeded"
        )
    pending = ledger.pending_results()
    assert len(pending) == 64
    assert pending[1:] == fresh
    assert JobStore(context(), private_store).pending_results() == pending


def test_backward_clock_outcome_is_not_before_durable_start(private_store, monkeypatch):
    from repeater.glass import job_store as module

    ledger = JobStore(context(), private_store)
    now = datetime.now(timezone.utc)
    clock = [now]
    monkeypatch.setattr(
        module, "_clock", lambda value=None: value if value is not None else clock[0]
    )

    def effect(_):
        clock[0] = now - timedelta(seconds=3)
        return success(None)

    request = delivery()
    ledger.receive(request, BOOT, CAPS, now=now - timedelta(seconds=2))
    result = ledger.execute(request, BOOT, effect, CAPS)
    assert datetime.fromisoformat(result["sent_at"].replace("Z", "+00:00")) >= now
    with ledger._locked() as (db, _):
        record = json.loads(db.execute("SELECT body FROM records").fetchone()[0])
        assert datetime.fromisoformat(record["phases"][-1]["at"]) >= datetime.fromisoformat(
            record["phases"][-2]["at"]
        )


def test_backward_clock_verified_phase_preserves_exact_prior_bytes(private_store):
    ledger = JobStore(context(), private_store)
    request = delivery()
    now = datetime.now(timezone.utc)
    future = now + timedelta(seconds=20)
    newboot = str(uuid4())
    expected = {
        "expected_boot_id": newboot,
        "expected_version": "v2",
        "expected_revision": "a" * 64,
        "ready_deadline": (now + timedelta(minutes=5)).isoformat(),
    }
    ledger.receive(request, BOOT, CAPS, now=now)
    first = ledger.execute(
        request,
        BOOT,
        lambda _: {"status": "awaiting_verification", "verification": expected},
        CAPS,
        now=future,
    )
    wire = json.dumps(first, sort_keys=True)
    ack = acceptance(first)
    ledger.acknowledge([ack], [first])
    reopened = JobStore(context(), private_store)
    proof = {
        "boot_id": newboot,
        "software_version": "v2",
        "effective_revision": "a" * 64,
        "ready": True,
        "uptime_seconds": 1,
    }
    second = reopened.reconcile(newboot, {request["execution_id"]: proof}, now=now)[0]
    assert datetime.fromisoformat(second["sent_at"].replace("Z", "+00:00")) >= future
    assert reopened.acknowledge([ack], [first]) == 0
    assert JobStore(context(), private_store).pending_results() == [second]
    with reopened._locked() as (db, _):
        record = json.loads(db.execute("SELECT body FROM records").fetchone()[0])
        assert json.dumps(record["phases"][-2]["result"], sort_keys=True) == wire
        from repeater.glass.contracts import ResultAcceptanceV2

        assert record["phases"][-2]["ack"] == ResultAcceptanceV2.model_validate(ack).model_dump(
            mode="json"
        )


def test_reconcile_samples_clock_after_real_flock_wait(private_store, monkeypatch):
    import threading

    from repeater.glass import job_store as module

    ledger = JobStore(context(), private_store)
    request = delivery()
    now = datetime.now(timezone.utc)
    newboot = str(uuid4())
    expected = {
        "expected_boot_id": newboot,
        "expected_version": "v2",
        "expected_revision": "a" * 64,
        "ready_deadline": (now + timedelta(seconds=10)).isoformat(),
    }
    first = ledger.execute(
        request, BOOT, lambda _: {"status": "awaiting_verification", "verification": expected}, CAPS
    )
    ledger.acknowledge([acceptance(first)], [first])
    clock, waiting, errors, results = [now], threading.Event(), [], []
    monkeypatch.setattr(
        module, "_clock", lambda value=None: value if value is not None else clock[0]
    )
    original = module.fcntl.flock

    def flock(fd, operation):
        if threading.current_thread().name == "reconcile-clock":
            waiting.set()
        return original(fd, operation)

    monkeypatch.setattr(module.fcntl, "flock", flock)

    def reconcile():
        try:
            results.extend(ledger.reconcile(newboot, {}))
        # Capture even cancellation/system-exit so any worker failure fails the
        # parent assertion; narrowing this catch could hide a terminal boundary.
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    with ledger._locked():
        thread = threading.Thread(target=reconcile, name="reconcile-clock")
        thread.start()
        assert waiting.wait(10)
        clock[0] = now + timedelta(seconds=11)
    thread.join(10)
    assert not thread.is_alive() and not errors
    assert len(results) == 1 and results[0]["status"] == "unknown"
    assert datetime.fromisoformat(results[0]["sent_at"].replace("Z", "+00:00")) == clock[0]


def test_sigkill_recovery_uses_durable_start_clock_floor(private_store):
    future = datetime.now(timezone.utc) + timedelta(seconds=30)
    request = delivery()
    JobStore(context(), private_store).receive(request, BOOT, CAPS)
    (private_store / "input.json").write_text(
        json.dumps(
            {
                "context": context(),
                "request": request,
                "clock": future.isoformat(),
                "received": True,
            }
        )
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from tests.test_glass_job_store import kill_worker; import sys; kill_worker(sys.argv[1], 'start')",
            str(private_store),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([child.stdout], [], [], 20)
        assert ready and child.stdout.readline().strip() == "start"
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)
        assert child.returncode == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    ledger = JobStore(context(), private_store)
    result = ledger.execute(request, str(uuid4()), lambda _: pytest.fail("crash replay"), CAPS)
    assert result["status"] == "unknown" and result["boot_id"] == BOOT
    assert datetime.fromisoformat(result["sent_at"].replace("Z", "+00:00")) >= future
    # Clock conflict stays observable in the exact outbox; no invented receipt.
    assert JobStore(context(), private_store).pending_results() == [result]
    assert not (private_store / "effects").exists()
