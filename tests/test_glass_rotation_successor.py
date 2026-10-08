"""Successor preparation only: synthetic PKI, no cutover or broker evidence."""
# ruff: noqa: F811 - imported pytest fixtures

import hashlib
import json

import pytest

from repeater.glass import enrollment as e
from repeater.glass import rotation_completion as c
from repeater.glass import rotation_reports as q
from repeater.glass import rotation_state as r
from tests.test_glass_rotation_completion import accepted, complete, pure_completion  # noqa: F401
from tests.test_glass_rotation_reports import (  # noqa: F401
    NEXT_BOOT,
    acknowledge,
    args,
    bundle,
    enroll_fixture,
    installation,
    installed,
    queue,
    snapshot,
    state,
)


def test_v1_installed_prepare_retry_preserves_request_and_journal(installed, monkeypatch):
    before = snapshot(installed)
    pending = json.loads(before["pending.json"])
    assert pending["version"] == 1
    assert "install.json" in before and "completed.json" not in before

    def forbidden(*a, **k):
        raise AssertionError("installed retry must not generate a key or publish state")

    for name in ("_new_pending", "_write_staged", "_replace"):
        monkeypatch.setattr(r, name, forbidden)
    guards = []
    expected = {field: pending[field] for field in ("device_id", "request_id", "csr_pem")}
    for _ in range(2):
        assert (
            r.prepare_rotation(
                installed[0], **args(installed), commit_guard=lambda: guards.append(1)
            )
            == expected
        )
        assert snapshot(installed) == before
    assert guards == [1, 1]


@pytest.mark.parametrize("journal_kind", ["original", "malformed", "symlink", "directory"])
@pytest.mark.parametrize("pending_kind", ["missing", "v2"])
def test_journal_without_legacy_pending_never_generates_or_reuses(
    installed, monkeypatch, journal_kind, pending_kind
):
    pending_path = state(installed, "pending.json")
    if pending_kind == "missing":
        pending_path.unlink()
    else:
        pending = json.loads(pending_path.read_bytes())
        pending.update(version=2, previous_completed_sha256="0" * 64)
        pending_path.write_text(json.dumps(pending))
    journal = state(installed, "install.json")
    if journal_kind != "original":
        journal.unlink()
        if journal_kind == "malformed":
            journal.write_bytes(b"not-json")
            journal.chmod(0o600)
        elif journal_kind == "symlink":
            journal.symlink_to("missing-journal")
        else:
            journal.mkdir(mode=0o700)
    before = snapshot(installed)
    guards = []
    generated = []

    def forbidden(*a, **k):
        generated.append(1)
        raise AssertionError("journal must block request publication")

    for name in ("_new_pending", "_write_staged", "_replace"):
        monkeypatch.setattr(r, name, forbidden)
    with pytest.raises(e.EnrollmentError):
        r.prepare_rotation(installed[0], **args(installed), commit_guard=lambda: guards.append(1))
    assert generated == guards == []
    assert snapshot(installed) == before
    assert journal.lstat()  # A dangling symlink also remains present.
    if journal_kind == "symlink":
        assert journal.is_symlink() and journal.readlink().as_posix() == "missing-journal"
    elif journal_kind == "directory":
        assert journal.is_dir()
    if pending_kind == "missing":
        assert not pending_path.exists()


def test_successor_schema_and_pure_authority(pure_completion):
    completed, current, context, binding = pure_completion
    # Exercise the expected v2 schema before the new builder API is introduced.
    pending = r._new_pending(context)
    pending.update(version=2, previous_completed_sha256=c._digest(completed, c._LIMIT))
    assert r._validate_pending(pending, context) == pending
    assert r._validate_successor_pending(pending, current, completed, context, binding) == pending


def test_actual_completed_cycle_then_atomic_successor(accepted):
    complete(accepted)
    before = snapshot(accepted)
    request = r.prepare_rotation(accepted[0], **args(accepted))
    pending = json.loads(state(accepted, "pending.json").read_bytes())
    assert pending["version"] == 2
    assert (
        pending["previous_completed_sha256"]
        == hashlib.sha256(
            r._canonical_json(json.loads(before["completed.json"]), c._LIMIT)
        ).hexdigest()
    )
    assert pending["request_id"] != accepted[0]["rotation_request_id"]
    assert pending["private_key"] != accepted[0]["private_key"]
    assert set(request) == {"device_id", "request_id", "csr_pem"}
    for name, raw in before.items():
        assert snapshot(accepted)[name] == raw
    saved = snapshot(accepted)
    assert r.prepare_rotation(accepted[0], **args(accepted)) == request
    assert snapshot(accepted) == saved


def successor(case):
    return r.prepare_rotation(case[0], **args(case))


@pytest.mark.parametrize("missing_accepted", [False, True])
def test_old_leaf_reports_and_outbox_retry_preserve_successor(accepted, missing_accepted):
    old = queue(accepted)
    complete(accepted)
    request = successor(accepted)
    if missing_accepted:
        state(accepted, "report-accepted.json").unlink()
    before = snapshot(accepted)
    assert queue(accepted) == old
    assert acknowledge(accepted, old)["accepted"] is True
    assert snapshot(accepted) == before
    new = queue(accepted, NEXT_BOOT)
    assert new["request_id"] == accepted[0]["rotation_request_id"] != request["request_id"]
    assert new["cert_serial"] == accepted[0]["cert_serial"]
    assert q.load_report(accepted[0], **args(accepted)) == new
    pending = state(accepted, "pending.json").read_bytes()
    assert successor(accepted) == request  # Outbox blocks creation, not reuse.
    assert state(accepted, "pending.json").read_bytes() == pending
    for call in (c.complete_rotation, c.load_completed):
        with pytest.raises(e.EnrollmentError):
            call(accepted[0], **args(accepted))
    acknowledge(accepted, new)
    for call in (c.complete_rotation, c.load_completed):
        with pytest.raises(e.EnrollmentError):
            call(accepted[0], **args(accepted))
    assert state(accepted, "pending.json").read_bytes() == pending
    assert state(accepted, "completed.json").read_bytes() == before["completed.json"]
    assert accepted[2].read_bytes() == before["credential"]


def test_outbox_blocks_generation_without_stranding_existing_key(accepted):
    complete(accepted)
    queue(accepted, NEXT_BOOT)
    before = snapshot(accepted)
    with pytest.raises(e.EnrollmentError):
        successor(accepted)
    assert snapshot(accepted) == before
    assert not state(accepted, "pending.json").exists()


@pytest.mark.parametrize(
    "remaining", [("pending.json",), ("install.json",), ("pending.json", "install.json")]
)
def test_partial_retirement_cannot_prepare_successor(accepted, remaining):
    originals = snapshot(accepted)
    complete(accepted)
    for name in remaining:
        path = state(accepted, name)
        path.write_bytes(originals[name])
        path.chmod(0o600)
    before = snapshot(accepted)
    with pytest.raises(e.EnrollmentError):
        successor(accepted)
    assert snapshot(accepted) == before


@pytest.mark.parametrize(
    "bad",
    [
        "missing",
        "relative",
        "alternate",
        "caller",
        "current",
        "completion",
        "accepted",
        "symlink",
        "mode",
        "duplicate",
    ],
)
def test_successor_authority_refuses_without_request_mutation(accepted, bad):
    complete(accepted)
    case = accepted
    if bad == "missing":
        options = {"store_dir": case[1]}
    elif bad == "relative":
        options = dict(args(case), credential_file="credentials.json")
    elif bad == "alternate":
        target = case[2].with_name("alternate.json")
        target.write_bytes(case[2].read_bytes())
        target.chmod(0o600)
        options = dict(args(case), credential_file=target)
    else:
        options = args(case)
        if bad == "caller":
            case = dict(case[0], extra=True), case[1], case[2]
        elif bad == "current":
            case[2].write_text(json.dumps(dict(case[0], extra=True)))
        elif bad == "completion":
            path = state(case, "completed.json")
            value = json.loads(path.read_bytes())
            value["candidate_sha256"] = "0" * 64
            path.write_text(json.dumps(value))
        elif bad == "accepted":
            path = state(case, "report-accepted.json")
            value = json.loads(path.read_bytes())
            value["ack"]["accepted"] = 1
            path.write_text(json.dumps(value))
        elif bad == "symlink":
            target = case[2].with_name("saved.json")
            case[2].rename(target)
            case[2].symlink_to(target)
        elif bad == "mode":
            case[2].chmod(0o644)
        else:
            raw = case[2].read_text()
            case[2].write_text(raw[:-1] + ',"device_id":"duplicate"}')
    before = snapshot(case)
    guards = []
    with pytest.raises(e.EnrollmentError):
        r.prepare_rotation(case[0], **options, commit_guard=lambda: guards.append(1))
    assert snapshot(case) == before
    assert guards == []


@pytest.mark.parametrize(
    "bad",
    [
        "v1",
        "marker",
        "old_request",
        "old_key",
        "context",
        "pkcs8",
        "csr",
        "version_bool",
        "version_unknown",
        "extra",
    ],
)
def test_pure_successor_rejects_invalid_chain(pure_completion, bad):
    completed, current, context, binding = pure_completion
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    if bad == "v1":
        pending = r._new_pending(context)
    elif bad == "marker":
        pending["previous_completed_sha256"] = "0" * 64
    elif bad == "old_request":
        pending["request_id"] = current["rotation_request_id"]
    elif bad == "old_key":
        # A fully valid CSR/key pair that cryptographically reuses CURRENT.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID

        key = serialization.load_pem_private_key(current["private_key"].encode(), password=None)
        pending["private_key"] = current["private_key"]
        pending["csr_pem"] = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "device:" + current["device_id"])]
                )
            )
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )
        assert r._validate_pending(pending, context) == pending
    elif bad == "context":
        pending["base_url"] += "/foreign"
    elif bad == "pkcs8":
        pending["private_key"] += "foreign"
    elif bad == "csr":
        pending["csr_pem"] += "foreign"
    elif bad == "version_bool":
        pending["version"] = True
    elif bad == "version_unknown":
        pending["version"] = 3
    else:
        pending["extra"] = "foreign"
    with pytest.raises((e.EnrollmentError, ValueError)):
        r._validate_successor_pending(pending, current, completed, context, binding)


@pytest.mark.parametrize("version", [True, False, 0, 3, "2", None])
def test_pending_literal_versions_only(bundle, version):
    context = r._context(bundle)
    value = r._new_pending(context)
    value["version"] = version
    with pytest.raises(e.EnrollmentError):
        r._validate_pending(value, context)


@pytest.mark.parametrize("marker", ["A" * 64, "0" * 63, "0" * 65, "g" * 64, 1, None])
def test_pending_marker_bounds(bundle, marker):
    context = r._context(bundle)
    value = r._new_pending(context)
    value.update(version=2, previous_completed_sha256=marker)
    with pytest.raises(e.EnrollmentError):
        r._validate_pending(value, context)


def test_pending_exact_fields_and_size(bundle):
    context = r._context(bundle)
    v1 = r._new_pending(context)
    v2 = r._new_pending(context, previous_completed_sha256="0" * 64)
    assert set(v2) == r._V2_FIELDS
    for value in (
        dict(v1, previous_completed_sha256="0" * 64),
        {k: v for k, v in v2.items() if k != "previous_completed_sha256"},
        dict(v2, csr_pem="x" * (r._LIMIT + 1)),
    ):
        with pytest.raises(e.EnrollmentError):
            r._validate_pending(value, context)


def test_pure_v2_offline_candidate_not_install_permission(pure_completion, enroll_fixture):
    from cryptography.hazmat.primitives import hashes

    completed, current, context, binding = pure_completion
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    r._validate_successor_pending(pending, current, completed, context, binding)
    response = e.post_verified_json(current["base_url"] + "/renew", pending)
    response.update(
        request_id=pending["request_id"],
        state="issued",
        fingerprint_sha256=r._single_certificate(response["client_cert"])
        .fingerprint(hashes.SHA256())
        .hex(),
    )
    candidate = r._build_renewal_candidate(current, r._renewal_response(response), pending)
    assert candidate["private_key"] == pending["private_key"]
    assert candidate["rotation_request_id"] == pending["request_id"]
    assert current["rotation_request_id"] == completed["request_id"]


@pytest.mark.parametrize("bad", ["digest", "accepted", "backup", "metadata", "caller_binding"])
def test_pure_successor_requires_valid_current_completed(pure_completion, bad):
    completed, current, context, binding = pure_completion
    if bad == "digest":
        completed["candidate_sha256"] = "0" * 64
    elif bad == "accepted":
        completed["accepted_record"]["ack"]["accepted"] = 1
    elif bad == "backup":
        completed["install_journal"]["previous_sha256"] = "0" * 64
    elif bad == "metadata":
        current["fingerprint_sha256"] = "0" * 64
    else:
        binding["candidate_sha256"] = "0" * 64
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    with pytest.raises(e.EnrollmentError):
        r._validate_successor_pending(pending, current, completed, context, binding)


def test_v1_schema_preserved(bundle):
    context = r._context(bundle)
    pending = r._new_pending(context)
    assert set(pending) == r._FIELDS
    assert pending["version"] == 1
    assert r._validate_pending(pending, context) == pending


def test_successor_install_gate_before_credential_parent_or_writes(accepted, monkeypatch):
    complete(accepted)
    request = successor(accepted)
    response = c._response(accepted[0])
    response["request_id"] = request["request_id"]
    before = snapshot(accepted)
    opened = []
    original = r.m._open_directory

    def directory(path):
        opened.append(str(path))
        if len(opened) > 1:
            raise AssertionError("credential parent must not be opened")
        return original(path)

    writes = []

    def forbidden(*a, **k):
        writes.append(1)
        raise AssertionError("successor installation must not write")

    monkeypatch.setattr(r.m, "_open_directory", directory)
    for name in ("_write_staged", "_replace", "_fsync"):
        monkeypatch.setattr(r, name, forbidden)
    with pytest.raises(e.EnrollmentError):
        r.install_renewal_candidate(accepted[0], response, **args(accepted))
    assert opened == [str(accepted[1])]
    assert writes == []
    assert snapshot(accepted) == before


def test_stage_collision_never_unlinks_foreign_name(accepted, monkeypatch):
    complete(accepted)
    collision = state(accepted, ".stage-" + "a" * 32)
    collision.write_bytes(b"foreign-owner-stage")
    collision.chmod(0o600)
    before = snapshot(accepted)
    monkeypatch.setattr(r.secrets, "token_hex", lambda n: "a" * 32)
    with pytest.raises(e.EnrollmentError):
        successor(accepted)
    assert snapshot(accepted) == before


@pytest.mark.parametrize("fault", ["write", "file_fsync", "replace", "dir_fsync", "readback"])
def test_successor_publication_faults_and_key_preserving_retry(accepted, monkeypatch, fault):
    import os
    import stat

    complete(accepted)
    before = snapshot(accepted)
    directory = state(accepted, ".lock").parent
    original_sync, original_read = r._fsync, r._read_pending

    def fail(*a, **k):
        raise OSError("synthetic private error")

    with monkeypatch.context() as patch:
        if fault == "write":

            def partial(fd, name, data, *, on_create=None):
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                try:
                    on_create()
                    os.write(target, data[:20])
                finally:
                    os.close(target)
                fail()

            patch.setattr(r, "_write_staged", partial)
        elif fault == "replace":
            patch.setattr(r, "_replace", fail)
        elif fault in {"file_fsync", "dir_fsync"}:

            def sync(fd):
                info = os.fstat(fd)
                if fault == "dir_fsync" and info.st_ino == directory.stat().st_ino:
                    fail()
                if fault == "file_fsync" and stat.S_ISREG(info.st_mode) and info.st_size > 0:
                    fail()
                return original_sync(fd)

            patch.setattr(r, "_fsync", sync)
        else:

            def read(fd, context):
                if state(accepted, "pending.json").exists():
                    fail()
                return original_read(fd, context)

            patch.setattr(r, "_read_pending", read)
        with pytest.raises(e.EnrollmentError) as error:
            successor(accepted)
        assert "synthetic private error" not in str(error.value)
    assert not list(directory.glob(".stage-*"))
    for name, raw in before.items():
        assert snapshot(accepted)[name] == raw
    pending = state(accepted, "pending.json")
    published = pending.read_bytes() if pending.exists() else None
    result = successor(accepted)
    if fault in {"dir_fsync", "readback"}:
        assert published is not None and pending.read_bytes() == published
        assert result["request_id"] == json.loads(published)["request_id"]
    else:
        assert published is None


@pytest.mark.parametrize("reject", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_successor_trusted_guard_once_before_stage_or_retry_fsync(
    accepted, monkeypatch, reject, retry
):
    complete(accepted)
    if retry:
        successor(accepted)
    before = snapshot(accepted)
    events = []
    original_write, original_sync = r._write_staged, r._fsync
    inode = state(accepted, ".lock").parent.stat().st_ino

    def write(*a, **k):
        assert events == ["guard"]
        events.append("write")
        return original_write(*a, **k)

    def sync(fd):
        import os

        if os.fstat(fd).st_ino == inode:
            assert "guard" in events
            events.append("directory_fsync")
        return original_sync(fd)

    def guard():
        assert not events and snapshot(accepted) == before
        events.append("guard")
        if reject:
            raise RuntimeError("private admission error")

    monkeypatch.setattr(r, "_write_staged", write)
    monkeypatch.setattr(r, "_fsync", sync)
    if reject:
        with pytest.raises(e.EnrollmentError):
            r.prepare_rotation(accepted[0], **args(accepted), commit_guard=guard)
        assert events == ["guard"]
        assert snapshot(accepted) == before
    else:
        r.prepare_rotation(accepted[0], **args(accepted), commit_guard=guard)
        assert events.count("guard") == 1
        assert events[-1] == "directory_fsync"


def test_successor_concurrent_processes_and_restart_reuse(accepted):
    import subprocess
    import sys
    from concurrent.futures import ThreadPoolExecutor

    complete(accepted)
    code = (
        "import json,sys; from repeater.glass.rotation_state import prepare_rotation; "
        "current=json.load(open(sys.argv[2])); "
        "print(json.dumps(prepare_rotation(current,store_dir=sys.argv[1],credential_file=sys.argv[2])))"
    )

    def invoke(_):
        return json.loads(
            subprocess.check_output(
                [sys.executable, "-c", code, str(accepted[1]), str(accepted[2])], text=True
            )
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(invoke, range(8)))
    assert all(result == results[0] for result in results)
    before = snapshot(accepted)
    assert invoke(None) == results[0]
    assert snapshot(accepted) == before


@pytest.mark.parametrize("journal", [False, True])
def test_pure_remaining_requires_report_opt_in_and_absent_journal(
    pure_completion, monkeypatch, journal
):
    completed, current, context, binding = pure_completion
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    monkeypatch.setattr(r, "_read_pending", lambda *a: pending)
    monkeypatch.setattr(c, "_no_outbox", lambda *a: None)
    monkeypatch.setattr(
        c,
        "_optional",
        lambda fd, name, limit: (
            completed["install_journal"] if name == "install.json" and journal else None
        ),
    )
    with pytest.raises(e.EnrollmentError):
        c._remaining(123, completed, current, context, binding)
    if journal:
        with pytest.raises(e.EnrollmentError):
            c._remaining(
                123,
                completed,
                current,
                context,
                binding,
                allow_outbox=True,
                allow_successor_pending=True,
            )
    else:
        assert c._remaining(
            123,
            completed,
            current,
            context,
            binding,
            allow_outbox=True,
            allow_successor_pending=True,
        ) == (pending, None)


@pytest.mark.parametrize(
    "bad", ["marker", "old_request", "key", "v1", "journal", "completed_missing"]
)
def test_existing_successor_is_never_repaired(accepted, bad):
    complete(accepted)
    successor(accepted)
    path = state(accepted, "pending.json")
    pending = json.loads(path.read_bytes())
    if bad == "marker":
        pending["previous_completed_sha256"] = "0" * 64
    elif bad == "old_request":
        pending["request_id"] = accepted[0]["rotation_request_id"]
    elif bad == "key":
        pending["private_key"] = accepted[0]["private_key"]
    elif bad == "v1":
        pending["version"] = 1
        del pending["previous_completed_sha256"]
    elif bad == "journal":
        completed = json.loads(state(accepted, "completed.json").read_bytes())
        journal = state(accepted, "install.json")
        journal.write_text(json.dumps(completed["install_journal"]))
        journal.chmod(0o600)
    else:
        state(accepted, "completed.json").unlink()
    path.write_text(json.dumps(pending))
    before = snapshot(accepted)
    with pytest.raises(e.EnrollmentError):
        successor(accepted)
    if bad != "completed_missing":
        with pytest.raises(e.EnrollmentError):
            queue(accepted, NEXT_BOOT)
    assert snapshot(accepted) == before
