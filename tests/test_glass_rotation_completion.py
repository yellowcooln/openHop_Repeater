"""Inactive completion core: real synthetic PKI, never broker proof.

Uses the c1-c5a fixture chain and unchanged production ancestry checks. A
0775 cache ancestor must fail; secure isolated parent execution is required.
"""

import importlib
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from repeater.glass import enrollment as e
from repeater.glass import rotation_state as r
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


def api():
    return importlib.import_module("repeater.glass.rotation_completion")


def complete(case, **kwargs):
    return api().complete_rotation(case[0], **args(case), **kwargs)


def load(case):
    return api().load_completed(case[0], **args(case))


@pytest.fixture
def accepted(installed):  # noqa: F811
    acknowledge(installed, queue(installed))
    return installed


def test_completion_api_exists():
    assert callable(api().complete_rotation)
    assert callable(api().load_completed)


@pytest.fixture
def pure_completion(bundle, enroll_fixture):  # noqa: F811
    """Pure real-PKI validator test, not durable c1-c5a or permission evidence."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    from repeater.glass import rotation_reports as q

    pending = r._validate_pending(r._new_pending(r._context(bundle)), r._context(bundle))
    response = e.post_verified_json(bundle["base_url"] + "/renew", pending)
    leaf = x509.load_pem_x509_certificate(response["client_cert"].encode("ascii"))
    response.update(
        request_id=pending["request_id"],
        state="issued",
        fingerprint_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
    )
    current = r._build_renewal_candidate(bundle, r._renewal_response(response), pending)
    context = r._context(current)
    path = str(enroll_fixture[0]["credential_file"])
    binding = {
        "version": 1,
        "base_url": context["base_url"],
        "generation_sha256": context["generation_sha256"],
        "credential_file": path,
        "candidate_sha256": r._bundle_digest(current),
    }
    journal = dict(
        context,
        version=1,
        request_id=pending["request_id"],
        credential_file=path,
        previous_bundle=bundle,
        previous_sha256=r._bundle_digest(bundle),
        candidate_sha256=binding["candidate_sha256"],
    )
    r._validate_install_journal(journal, context, pending, path)
    report = q._report(
        {
            "device_id": current["device_id"],
            "request_id": pending["request_id"],
            "cert_serial": current["cert_serial"],
            "fingerprint_sha256": current["fingerprint_sha256"],
            "boot_id": NEXT_BOOT,
            "connected": True,
        },
        current,
    )
    ack = q._ack(
        {
            "device_id": report["device_id"],
            "request_id": report["request_id"],
            "cert_serial": report["cert_serial"],
            "accepted": True,
            "state": "node_reported",
        },
        report,
    )
    value = dict(
        context,
        version=1,
        credential_file=path,
        request_id=pending["request_id"],
        cert_serial=current["cert_serial"],
        fingerprint_sha256=current["fingerprint_sha256"],
        candidate_sha256=binding["candidate_sha256"],
        pending_sha256=api()._digest(pending, r._LIMIT),
        install_journal=journal,
        accepted_record=dict(binding, report=report, ack=ack),
    )
    return value, current, context, binding


def test_pure_completion_validator_real_pki(pure_completion):
    value, current, context, binding = pure_completion
    assert api()._validate(value, current, context, binding) == value
    assert api()._response(current)["fingerprint_sha256"] == current["fingerprint_sha256"]
    assert set(api()._public(current)) == set(api()._PUBLIC) | {"state"}


@pytest.mark.parametrize(
    "bad",
    [
        "bool",
        "pending_digest",
        "accepted_true",
        "accepted_foreign",
        "backup_digest",
        "backup_context",
        "backup_ca",
        "backup_serial",
        "backup_expiry",
        "backup_bound",
    ],
)
def test_pure_completion_validator_rejects(pure_completion, bad):
    value, current, context, binding = pure_completion
    previous = value["install_journal"]["previous_bundle"]
    if bad == "bool":
        value["version"] = True
    elif bad == "pending_digest":
        value["pending_sha256"] = "A" * 64
    elif bad == "accepted_true":
        value["accepted_record"]["ack"]["accepted"] = 1
    elif bad == "accepted_foreign":
        value["accepted_record"]["candidate_sha256"] = "0" * 64
    elif bad == "backup_digest":
        value["install_journal"]["previous_sha256"] = "0" * 64
    else:
        field, change = {
            "backup_context": ("base_url", "https://foreign.example"),
            "backup_ca": ("ca_cert", previous["ca_cert"] + "garbage"),
            "backup_serial": ("cert_serial", "01"),
            "backup_expiry": ("expires_at", "2020-01-01"),
            "backup_bound": ("extra", "x" * 65536),
        }[bad]
        previous[field] = change
        if bad != "backup_bound":
            value["install_journal"]["previous_sha256"] = r._bundle_digest(previous)
    with pytest.raises(e.EnrollmentError):
        api()._validate(value, current, context, binding)


@pytest.mark.parametrize("missing", ["completed", "lock", "state", "current"])
def test_loader_missing_is_not_generic_absence(accepted, missing):
    if missing == "completed":
        before = snapshot(accepted)
        assert load(accepted) is None
        assert snapshot(accepted) == before
        return
    if missing == "current":
        accepted[2].unlink()
    elif missing == "state":
        directory = state(accepted, ".lock").parent
        directory.rename(directory.with_name("preserved-state"))
    else:
        state(accepted, ".lock").unlink()
    with pytest.raises(e.EnrollmentError):
        load(accepted)
    assert not state(accepted, "completed.json").exists()


@pytest.mark.parametrize("bad", ["relative", "traversal", "reserved", "state_parent", "alternate"])
def test_credential_path_binding_no_writes(accepted, bad):
    current, store, target = accepted
    if bad == "relative":
        path = target.name
    elif bad == "traversal":
        path = str(store) + "/../" + store.name + "/" + target.name
    elif bad == "reserved":
        path = store / "completed.json"
    else:
        path = (store / "rotation-state" if bad == "state_parent" else store) / "alternate.json"
        path.write_bytes(target.read_bytes())
        path.chmod(0o600)
    before = snapshot(accepted)
    for call in (api().complete_rotation, api().load_completed):
        # Without an existing completion, loader checks current authority only;
        # alternate private files are valid for absence, not deletion authority.
        if bad == "alternate" and call == api().load_completed:
            assert call(current, store_dir=store, credential_file=path) is None
        else:
            with pytest.raises(e.EnrollmentError):
                call(current, store_dir=store, credential_file=path)
    assert snapshot(accepted) == before


@pytest.mark.parametrize("bad", ["valid_foreign_key", "pending_digest", "journal", "outbox"])
def test_remaining_state_refused_after_publication(accepted, monkeypatch, bad):
    with monkeypatch.context() as patch:
        patch.setattr(api(), "_unlink", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    if bad == "valid_foreign_key":
        pending = r._new_pending(r._context(accepted[0]))
        pending["request_id"] = accepted[0]["rotation_request_id"]
        state(accepted, "pending.json").write_text(json.dumps(pending))
    elif bad == "pending_digest":
        path = state(accepted, "completed.json")
        value = json.loads(path.read_bytes())
        value["pending_sha256"] = "0" * 64
        path.write_text(json.dumps(value))
    elif bad == "journal":
        path = state(accepted, "install.json")
        value = json.loads(path.read_bytes())
        value["previous_bundle"]["extra"] = "foreign"
        value["previous_sha256"] = r._bundle_digest(value["previous_bundle"])
        path.write_text(json.dumps(value))
    else:
        state(accepted, "report-outbox.json").symlink_to("missing-foreign")
    before = snapshot(accepted)
    for call in (lambda: complete(accepted), lambda: load(accepted)):
        with pytest.raises(e.EnrollmentError):
            call()
    assert snapshot(accepted) == before


def test_creation_previous_bound_no_writes(accepted):
    path = state(accepted, "install.json")
    value = json.loads(path.read_bytes())
    value["previous_bundle"]["extra"] = "x" * 65536
    path.write_text(json.dumps(value))
    before = snapshot(accepted)
    guards = []
    with pytest.raises(e.EnrollmentError):
        complete(accepted, commit_guard=lambda: guards.append(1))
    assert not guards
    assert snapshot(accepted) == before


@pytest.mark.parametrize("cleanup_fault", [False, True])
def test_owned_stage_cleanup_and_descriptors(accepted, monkeypatch, cleanup_fault):
    original_open, original_unlink = os.open, api()._unlink
    opened = []
    foreign = state(accepted, ".stage-" + "a" * 32)
    foreign.write_bytes(b"unrelated stage")

    def tracked(*a, **k):
        fd = original_open(*a, **k)
        opened.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(api().os, "open", tracked)
        if cleanup_fault:
            patch.setattr(r, "_fsync", lambda fd: (_ for _ in ()).throw(OSError("stage-fault")))

            def unlink(name, **k):
                if name.startswith(".stage-"):
                    raise OSError("secret-cleanup-fault")
                return original_unlink(name, **k)

            patch.setattr(api(), "_unlink", unlink)
        else:
            patch.setattr(api().secrets, "token_hex", lambda _: "a" * 32)
        with pytest.raises(e.EnrollmentError) as error:
            complete(accepted)
        assert "secret-" not in str(error.value)
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)
    assert foreign.read_bytes() == b"unrelated stage"
    assert not state(accepted, "completed.json").exists()


def test_completion_public_exact_one_private_backup(accepted):
    before = snapshot(accepted)
    journal = json.loads(state(accepted, "install.json").read_bytes())
    # Unrelated entries, immutable MQTT directories, and current/accepted bytes
    # are outside retirement authority.
    foreign = state(accepted, ".stage-unrelated")
    foreign.write_bytes(b"unrelated")
    mqtt = accepted[1] / "mqtt-credentials"
    mqtt.mkdir(mode=0o700)
    immutable = mqtt / "immutable.pem"
    immutable.write_bytes(b"do not remove")
    assert load(accepted) is None
    expected = {
        k: accepted[0]["rotation_request_id"] if k == "request_id" else accepted[0][k]
        for k in api()._PUBLIC
    } | {"state": "rotation_completed"}
    assert complete(accepted) == expected
    path = state(accepted, "completed.json")
    raw = path.read_bytes()
    saved = json.loads(raw)
    assert set(saved) == api()._FIELDS
    assert saved["install_journal"] == journal
    assert saved["accepted_record"] == json.loads(before["report-accepted.json"])
    assert saved["pending_sha256"] == api()._digest(json.loads(before["pending.json"]), r._LIMIT)
    assert saved["candidate_sha256"] == r._bundle_digest(accepted[0])
    assert len(raw) <= 131072
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    assert not any(k in saved for k in ("private_key", "csr_pem", "previous_bundle"))
    assert accepted[0]["private_key"] not in raw.decode()
    assert (
        saved["install_journal"]["previous_bundle"]["private_key"]
        == journal["previous_bundle"]["private_key"]
    )
    for secret in ("private_key", "operational_token", "BEGIN CERTIFICATE", "csr_pem"):
        assert secret not in json.dumps(expected)
    assert not state(accepted, "pending.json").exists()
    assert not state(accepted, "install.json").exists()
    assert accepted[2].read_bytes() == before["credential"]
    assert state(accepted, "report-accepted.json").read_bytes() == before["report-accepted.json"]
    assert state(accepted, ".lock").read_bytes() == before[".lock"]
    assert foreign.read_bytes() == b"unrelated"
    assert immutable.read_bytes() == b"do not remove"
    frozen = snapshot(accepted)
    assert load(accepted) == expected
    assert snapshot(accepted) == frozen
    assert complete(accepted) == expected
    assert snapshot(accepted) == frozen
    assert path.read_bytes() == raw


@pytest.mark.parametrize("phase", ["unacknowledged", "accepted_outbox"])
def test_outbox_always_prevents_retirement(installed, monkeypatch, phase):  # noqa: F811
    report = queue(installed)
    if phase == "accepted_outbox":
        from repeater.glass import rotation_reports as q

        with monkeypatch.context() as patch:
            patch.setattr(q, "_unlink", lambda *a, **k: (_ for _ in ()).throw(OSError()))
            with pytest.raises(e.EnrollmentError):
                acknowledge(installed, report)
    before = snapshot(installed)
    guards = []
    with pytest.raises(e.EnrollmentError):
        complete(installed, commit_guard=lambda: guards.append(1))
    assert not guards
    assert snapshot(installed) == before
    acknowledge(installed, report)
    assert complete(installed)["state"] == "rotation_completed"


@pytest.mark.parametrize(
    "bad",
    [
        "missing_pending",
        "missing_journal",
        "missing_accepted",
        "missing_lock",
        "missing_current",
        "caller",
        "current",
        "pending_key",
        "pending_request",
        "journal_digest",
        "previous_context",
        "accepted_ack",
        "accepted_digest",
        "accepted_boot",
        "expired_current",
        "fingerprint",
    ],
)
def test_creation_authority_no_writes(accepted, bad):
    current, store, target = accepted
    paths = {
        "pending": "pending.json",
        "journal": "install.json",
        "accepted": "report-accepted.json",
        "lock": ".lock",
    }
    if bad.startswith("missing_"):
        part = bad.removeprefix("missing_")
        (target if part == "current" else state(accepted, paths[part])).unlink()
    elif bad == "caller":
        accepted = dict(current, extra=True), store, target
    elif bad in ("current", "expired_current", "fingerprint"):
        value = dict(current)
        value[
            {
                "current": "extra",
                "expired_current": "expires_at",
                "fingerprint": "fingerprint_sha256",
            }[bad]
        ] = {
            "current": True,
            "expired_current": "2000-01-01T00:00:00Z",
            "fingerprint": "0" * 64,
        }[bad]
        target.write_text(json.dumps(value))
        if bad != "current":
            accepted = value, store, target
    else:
        group = bad.split("_")[0]
        path = state(accepted, paths.get(group, "install.json"))
        value = json.loads(path.read_bytes())
        if bad == "pending_key":
            value["private_key"] = "secret-invalid"
        elif bad == "pending_request":
            value["request_id"] = NEXT_BOOT
        elif bad == "journal_digest":
            value["candidate_sha256"] = "0" * 64
        elif bad == "previous_context":
            value["previous_bundle"]["base_url"] = "https://foreign.example"
            value["previous_sha256"] = r._bundle_digest(value["previous_bundle"])
        elif bad == "accepted_ack":
            value["ack"]["accepted"] = 1
        elif bad == "accepted_digest":
            value["candidate_sha256"] = "0" * 64
        elif bad == "accepted_boot":
            value["report"]["boot_id"] = "invalid"
        path.write_text(json.dumps(value))
    before = {p.name: p.read_bytes() for p in (store / "rotation-state").iterdir()}
    original_current = target.read_bytes() if target.exists() else None
    guards = []
    with pytest.raises(e.EnrollmentError) as error:
        complete(accepted, commit_guard=lambda: guards.append(1))
    assert error.value.__suppress_context__
    assert not guards
    assert {p.name: p.read_bytes() for p in (store / "rotation-state").iterdir()} == before
    assert (target.read_bytes() if target.exists() else None) == original_current


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("reject", [False, True])
def test_guard_once_before_all_mutations(accepted, monkeypatch, retry, reject):
    if retry:
        complete(accepted)
    before = snapshot(accepted)
    events = []
    for name in ("_publish", "_fsync", "_unlink"):
        original = getattr(api(), name)

        def tracked(*a, _name=name, _original=original, **k):
            events.append(_name)
            return _original(*a, **k)

        monkeypatch.setattr(api(), name, tracked)

    def guard():
        assert not events
        assert snapshot(accepted) == before
        events.append("guard")
        if reject:
            raise RuntimeError("secret-guard")

    if reject:
        with pytest.raises(e.EnrollmentError):
            complete(accepted, commit_guard=guard)
        assert snapshot(accepted) == before
        assert events == ["guard"]
    else:
        complete(accepted, commit_guard=guard)
        assert events[0] == "guard" and events.count("guard") == 1


@pytest.mark.parametrize("fault", ["write", "replace", "stage_read", "dir_fsync", "published_read"])
def test_publication_fault_retry(accepted, monkeypatch, fault):
    module = api()
    before = snapshot(accepted)
    real_write, real_replace, real_read, real_sync = (
        module._write_staged,
        module._replace,
        module._read_private_json,
        module._fsync,
    )
    published = False

    def fail():
        raise OSError("secret-io")

    def write(fd, name, data, **kw):
        if fault == "write":
            handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
            kw["on_create"]()
            os.write(handle, data[:10])
            os.close(handle)
            fail()
        return real_write(fd, name, data, **kw)

    def replace(*a, **k):
        nonlocal published
        if fault == "replace":
            fail()
        result = real_replace(*a, **k)
        published = True
        return result

    def read(fd, name, limit):
        if (fault == "stage_read" and name.startswith(".stage-")) or (
            fault == "published_read" and published and name == "completed.json"
        ):
            fail()
        return real_read(fd, name, limit)

    def sync(fd):
        if fault == "dir_fsync" and published:
            fail()
        return real_sync(fd)

    with monkeypatch.context() as patch:
        for name, fn in (
            ("_write_staged", write),
            ("_replace", replace),
            ("_read_private_json", read),
            ("_fsync", sync),
        ):
            patch.setattr(module, name, fn)
        with pytest.raises(e.EnrollmentError) as error:
            complete(accepted)
        assert "secret-io" not in str(error.value)
    if not published:
        assert snapshot(accepted) == before
    else:
        for name, raw in before.items():
            assert snapshot(accepted)[name] == raw
    assert not list(state(accepted, ".lock").parent.glob(".stage-*"))
    receipt = state(accepted, "completed.json").read_bytes() if published else None
    complete(accepted)
    if receipt is not None:
        assert state(accepted, "completed.json").read_bytes() == receipt


@pytest.mark.parametrize("fault", ["short_write", "flush", "file_fsync"])
def test_actual_stage_stream_fault(accepted, monkeypatch, fault):
    original = os.fdopen
    before = snapshot(accepted)

    class Broken:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *values):
            return self.stream.__exit__(*values)

        def fileno(self):
            return self.stream.fileno()

        def write(self, data):
            return self.stream.write(data[:10] if fault == "short_write" else data)

        def flush(self):
            if fault == "flush":
                raise OSError("secret-flush")
            self.stream.flush()

    def fdopen(fd, mode):
        stream = original(fd, mode)
        return Broken(stream) if mode == "wb" else stream

    with monkeypatch.context() as patch:
        patch.setattr(api().os, "fdopen", fdopen)
        if fault == "file_fsync":
            patch.setattr(r, "_fsync", lambda fd: (_ for _ in ()).throw(OSError("secret-fsync")))
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    assert snapshot(accepted) == before
    complete(accepted)


@pytest.mark.parametrize(
    "fault", ["pending_unlink", "pending_fsync", "journal_unlink", "journal_fsync", "final_read"]
)
def test_partial_retirement_readonly_load_and_retry(accepted, monkeypatch, fault):
    original_unlink, original_sync, original_read = (
        api()._unlink,
        api()._fsync,
        api()._read_private_json,
    )
    deleted = []

    def unlink(name, **kw):
        if fault == {"pending.json": "pending_unlink", "install.json": "journal_unlink"}.get(name):
            raise OSError("crash")
        result = original_unlink(name, **kw)
        deleted.append(name)
        return result

    def sync(fd):
        if deleted and fault == {
            "pending.json": "pending_fsync",
            "install.json": "journal_fsync",
        }.get(deleted[-1]):
            raise OSError("crash")
        return original_sync(fd)

    def read(fd, name, limit):
        if fault == "final_read" and "install.json" in deleted and name == "completed.json":
            raise OSError("crash")
        return original_read(fd, name, limit)

    with monkeypatch.context() as patch:
        patch.setattr(api(), "_unlink", unlink)
        patch.setattr(api(), "_fsync", sync)
        patch.setattr(api(), "_read_private_json", read)
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    receipt = state(accepted, "completed.json").read_bytes()
    frozen = snapshot(accepted)
    assert load(accepted)["state"] == "rotation_completed"
    assert snapshot(accepted) == frozen
    complete(accepted)
    assert state(accepted, "completed.json").read_bytes() == receipt
    assert accepted[2].read_bytes() == frozen["credential"]


@pytest.mark.parametrize(
    "name,bad",
    [
        (name, bad)
        for name in (
            "completed.json",
            "pending.json",
            "install.json",
            "report-accepted.json",
            ".lock",
            "credential",
        )
        for bad in ("mode", "symlink", "fifo", "duplicate", "oversize", "acl", "owner")
        if not (name == ".lock" and bad in ("duplicate", "oversize"))
    ],
)
def test_unsafe_private_records_no_repairs(accepted, monkeypatch, name, bad):
    # Preserve pending and journal to test the partial-publication state.
    with monkeypatch.context() as patch:
        patch.setattr(api(), "_unlink", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    path = accepted[2] if name == "credential" else state(accepted, name)
    if bad == "mode":
        path.chmod(0o644)
    elif bad == "symlink":
        saved = path.with_name("foreign-saved")
        path.rename(saved)
        path.symlink_to(saved)
    elif bad == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif bad == "duplicate":
        raw = path.read_text()
        path.write_text(raw[:-1] + ',"version":1}')
    elif bad == "oversize":
        path.write_bytes(b" " * 131073)
    elif bad == "acl":
        real, inode = os.listxattr, path.stat().st_ino
        monkeypatch.setattr(
            api().os,
            "listxattr",
            lambda fd: (
                ["system.posix_acl_access"]
                if isinstance(fd, int) and os.fstat(fd).st_ino == inode
                else real(fd)
            ),
        )
    else:
        real, inode = os.fstat, path.stat().st_ino

        def foreign(fd):
            info = real(fd)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return info

        monkeypatch.setattr(api().os, "fstat", foreign)
    before = path.lstat()
    raw = path.read_bytes() if bad != "fifo" else None
    for call in (lambda: complete(accepted), lambda: load(accepted)):
        with pytest.raises(e.EnrollmentError):
            call()
    after = path.lstat()
    assert (before.st_ino, before.st_mode, before.st_mtime_ns, before.st_size) == (
        after.st_ino,
        after.st_mode,
        after.st_mtime_ns,
        after.st_size,
    )
    if raw is not None:
        assert path.read_bytes() == raw


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "base_url",
        "device_id",
        "generation_sha256",
        "credential_file",
        "request_id",
        "cert_serial",
        "fingerprint_sha256",
        "candidate_sha256",
        "pending_sha256",
        "extra",
    ],
)
def test_foreign_completed_immutable_no_retirement(accepted, monkeypatch, field):
    with monkeypatch.context() as patch:
        patch.setattr(api(), "_unlink", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    path = state(accepted, "completed.json")
    saved = json.loads(path.read_bytes())
    saved[field] = True if field == "version" else "foreign"
    path.write_text(json.dumps(saved))
    before = snapshot(accepted)
    for call in (lambda: complete(accepted), lambda: load(accepted)):
        with pytest.raises(e.EnrollmentError):
            call()
    assert snapshot(accepted) == before


def test_current_change_during_stage_aborts(accepted, monkeypatch):
    before = snapshot(accepted)
    original = api()._write_staged

    def write(*a, **k):
        result = original(*a, **k)
        accepted[2].write_bytes(before["credential"] + b" ")
        return result

    monkeypatch.setattr(api(), "_write_staged", write)
    with pytest.raises(e.EnrollmentError):
        complete(accepted)
    assert not state(accepted, "completed.json").exists()
    for name, raw in before.items():
        if name != "credential":
            assert snapshot(accepted)[name] == raw
    assert not list(state(accepted, ".lock").parent.glob(".stage-*"))


@pytest.mark.parametrize(
    "window",
    ["before_publish", "after_publish", "before_pending", "after_pending", "after_journal"],
)
def test_process_death_restart(accepted, window):
    code = """import json, os, sys
from repeater.glass import rotation_completion as q
c=json.load(sys.stdin)
window=sys.argv[3]
replace,unlink=q._replace,q._unlink
def replacement(*a,**k):
    if window=='before_publish': os._exit(23)
    result=replace(*a,**k)
    if window=='after_publish': os._exit(23)
    return result
def removal(name,**k):
    if name=='pending.json' and window=='before_pending': os._exit(23)
    result=unlink(name,**k)
    if (name=='pending.json' and window=='after_pending') or (name=='install.json' and window=='after_journal'): os._exit(23)
    return result
q._replace,q._unlink=replacement,removal
q.complete_rotation(c,store_dir=sys.argv[1],credential_file=sys.argv[2])
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(accepted[1]), str(accepted[2]), window],
        input=json.dumps(accepted[0]),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 23, result.stderr
    receipt = state(accepted, "completed.json")
    raw = receipt.read_bytes() if receipt.exists() else None
    result = child(accepted)
    assert result["state"] == "rotation_completed"
    if raw is not None:
        assert receipt.read_bytes() == raw
    # Abrupt death can leave this dead process's stage; no subsequent call may
    # remove it without explicit recovery ownership.
    stages = list(receipt.parent.glob(".stage-*"))
    assert bool(stages) == (window == "before_publish")


def child(case):
    code = (
        "import json,sys; from repeater.glass import rotation_completion as q; "
        "c=json.load(sys.stdin); print(json.dumps(q.complete_rotation(c,"
        "store_dir=sys.argv[1],credential_file=sys.argv[2])))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(case[1]), str(case[2])],
        input=json.dumps(case[0]),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_simultaneous_process_completion(accepted):
    before = snapshot(accepted)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: child(accepted), range(8)))
    assert all(result == results[0] for result in results)
    receipt = state(accepted, "completed.json").read_bytes()
    assert child(accepted) == results[0]
    assert state(accepted, "completed.json").read_bytes() == receipt
    assert accepted[2].read_bytes() == before["credential"]
    assert state(accepted, "report-accepted.json").read_bytes() == before["report-accepted.json"]


def test_embedded_receipt_survives_missing_accepted_and_new_boot(accepted):
    complete(accepted)
    path = state(accepted, "report-accepted.json")
    value = json.loads(path.read_bytes())
    value["report"]["boot_id"] = NEXT_BOOT
    path.write_text(json.dumps(value))
    receipt = state(accepted, "completed.json").read_bytes()
    assert complete(accepted) == load(accepted)
    path.unlink()
    assert complete(accepted) == load(accepted)
    assert state(accepted, "completed.json").read_bytes() == receipt


@pytest.mark.parametrize(
    "bad",
    [
        "digest",
        "context",
        "ca",
        "serial",
        "expiry",
        "key_type",
        "bundle_bound",
        "accepted_bound",
        "journal_bound",
        "total_bound",
    ],
)
def test_historical_backup_and_bounds_refuse_no_deletion(accepted, monkeypatch, bad):
    with monkeypatch.context() as patch:
        patch.setattr(api(), "_unlink", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    path = state(accepted, "completed.json")
    value = json.loads(path.read_bytes())
    journal = value["install_journal"]
    previous = journal["previous_bundle"]
    if bad == "digest":
        journal["previous_sha256"] = "0" * 64
    elif bad == "context":
        previous["operational_token"] = "foreign"
    elif bad == "ca":
        previous["ca_cert"] += "garbage"
    elif bad == "serial":
        previous["cert_serial"] = "01"
    elif bad == "expiry":
        previous["expires_at"] = "2020-01-01"
    elif bad == "key_type":
        previous["private_key"] = True
    elif bad == "bundle_bound":
        previous["extra"] = "x" * 65536
    elif bad == "accepted_bound":
        value["accepted_record"]["report"]["boot_id"] = "x" * 8192
    elif bad in ("journal_bound", "total_bound"):
        journal["extra"] = "x" * 131072
    if bad not in ("digest", "bundle_bound"):
        journal["previous_sha256"] = r._bundle_digest(previous)
    path.write_text(json.dumps(value))
    before = snapshot(accepted)
    for call in (lambda: complete(accepted), lambda: load(accepted)):
        with pytest.raises(e.EnrollmentError):
            call()
    assert snapshot(accepted) == before


@pytest.mark.parametrize("expired", ["old_completed", "old_uncompleted", "current_completed"])
def test_real_certificate_expiry_without_clock_patch(
    bundle,  # noqa: F811
    enroll_fixture,  # noqa: F811
    tmp_path,
    monkeypatch,
    expired,
):
    import time
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    # Real short-lived PKI; wall time advances naturally, no global clock hack.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    deadline = now + timedelta(seconds=8)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Completion expiry test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(71)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def leaf(public_key, serial, expiry):
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "device:" + bundle["device_id"])]
                )
            )
            .issuer_name(name)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("urn:openhop:device:" + bundle["device_id"])]
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return {
            "client_cert": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "ca_cert": ca_pem,
            "cert_serial": format(serial, "x"),
            "expires_at": expiry.isoformat(),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        }

    old_key = serialization.load_pem_private_key(
        bundle["private_key"].encode("ascii"), password=None
    )
    old_expiry = now + timedelta(days=1) if expired == "current_completed" else deadline
    old = dict(bundle, **leaf(old_key.public_key(), 72, old_expiry))
    old.pop("fingerprint_sha256")
    target = enroll_fixture[0]["credential_file"]
    target.write_text(json.dumps(old))
    request = r.prepare_rotation(old, store_dir=tmp_path)
    csr = x509.load_pem_x509_csr(request["csr_pem"].encode("ascii"))
    new_expiry = deadline if expired == "current_completed" else now + timedelta(days=1)
    response = dict(
        leaf(csr.public_key(), 73, new_expiry),
        device_id=old["device_id"],
        request_id=request["request_id"],
        state="issued",
    )
    r.install_renewal_candidate(old, response, store_dir=tmp_path, credential_file=target)
    case = json.loads(target.read_bytes()), tmp_path, target
    acknowledge(case, queue(case))
    if expired != "old_uncompleted":
        with monkeypatch.context() as patch:
            patch.setattr(api(), "_unlink", lambda *a, **k: (_ for _ in ()).throw(OSError()))
            with pytest.raises(e.EnrollmentError):
                complete(case)
        assert state(case, "completed.json").exists()
    time.sleep(max(0, (deadline - datetime.now(timezone.utc)).total_seconds()) + 0.1)
    before = snapshot(case)
    if expired == "old_completed":
        assert load(case)["state"] == "rotation_completed"
        assert snapshot(case) == before
        complete(case)
        assert state(case, "completed.json").read_bytes() == before["completed.json"]
    else:
        with pytest.raises(e.EnrollmentError):
            complete(case)
        assert snapshot(case) == before
        if expired == "current_completed":
            with pytest.raises(e.EnrollmentError):
                load(case)
