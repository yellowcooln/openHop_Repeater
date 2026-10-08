"""Post-retirement reports: synthetic PKI, not live broker evidence."""

# ruff: noqa: F811 - pytest injects imported fixtures by name

import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from repeater.glass import enrollment as e
from repeater.glass import rotation_completion as c
from repeater.glass import rotation_reports as q
from tests.test_glass_rotation_completion import (  # noqa: F401
    accepted,
    complete,
    pure_completion,
)
from tests.test_glass_rotation_completion import (
    test_real_certificate_expiry_without_clock_patch as exercise_real_expiry,
)
from tests.test_glass_rotation_reporting import connect, flush, paho, real_handler  # noqa: F401
from tests.test_glass_rotation_reports import (  # noqa: F401
    NEXT_BOOT,
    ack,
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


def test_missing_accepted_uses_validated_embedded_record(pure_completion, monkeypatch):
    value, current, context, binding = pure_completion
    c._validate(value, current, context, binding)

    def absent(*a):
        raise FileNotFoundError

    monkeypatch.setattr(q, "_read_private_json", absent)
    assert q._record(
        123, q._ACCEPTED, current, binding, accepted_fallback=value["accepted_record"]
    ) == (value["accepted_record"], None)
    assert q._record(123, q._ACCEPTED, current, binding) == (None, None)
    assert q._record(
        123, q._OUTBOX, current, binding, accepted_fallback=value["accepted_record"]
    ) == (None, None)


def test_retired_same_boot_embedded_acceptance_no_private_writes(accepted):
    report = json.loads(state(accepted, "report-accepted.json").read_bytes())["report"]
    complete(accepted)
    state(accepted, "report-accepted.json").unlink()
    before = snapshot(accepted)
    assert queue(accepted) == report
    assert q.load_report(accepted[0], **args(accepted)) is None
    calls = []
    assert q.acknowledge_report(
        accepted[0], report, ack(report), **args(accepted), commit_guard=lambda: calls.append(1)
    ) == ack(report)
    assert calls == [1]
    assert snapshot(accepted) == before


@pytest.mark.parametrize(
    "remaining", [(), ("pending.json",), ("install.json",), ("pending.json", "install.json")]
)
def test_partial_retirement_report_authority(accepted, remaining):
    originals = snapshot(accepted)
    complete(accepted)
    for name in remaining:
        path = state(accepted, name)
        path.write_bytes(originals[name])
        path.chmod(0o600)
    before = snapshot(accepted)
    old = queue(accepted)
    assert q.load_report(accepted[0], **args(accepted)) is None
    assert acknowledge(accepted, old) == ack(old)
    assert snapshot(accepted) == before
    new = queue(accepted, NEXT_BOOT)
    assert q.load_report(accepted[0], **args(accepted)) == new
    acknowledge(accepted, new)
    after = snapshot(accepted)
    for name, raw in before.items():
        if name != "report-accepted.json":
            assert after[name] == raw


@pytest.mark.parametrize(
    "fault", ["pending_unlink", "pending_fsync", "journal_unlink", "journal_fsync", "final_read"]
)
def test_report_after_actual_partial_retirement_fault(accepted, monkeypatch, fault):
    unlink, sync, read = c._unlink, c._fsync, c._read_private_json
    deleted = []

    def removal(name, **kwargs):
        if fault == {"pending.json": "pending_unlink", "install.json": "journal_unlink"}.get(name):
            raise OSError("synthetic crash")
        result = unlink(name, **kwargs)
        deleted.append(name)
        return result

    def fsync(fd):
        if deleted and fault == {
            "pending.json": "pending_fsync",
            "install.json": "journal_fsync",
        }.get(deleted[-1]):
            raise OSError("synthetic crash")
        return sync(fd)

    def reread(fd, name, limit):
        if fault == "final_read" and "install.json" in deleted and name == "completed.json":
            raise OSError("synthetic crash")
        return read(fd, name, limit)

    with monkeypatch.context() as patch:
        patch.setattr(c, "_unlink", removal)
        patch.setattr(c, "_fsync", fsync)
        patch.setattr(c, "_read_private_json", reread)
        with pytest.raises(e.EnrollmentError):
            complete(accepted)
    before = snapshot(accepted)
    report = queue(accepted)
    acknowledge(accepted, report)
    assert q.load_report(accepted[0], **args(accepted)) is None
    assert snapshot(accepted) == before
    new = queue(accepted, NEXT_BOOT)
    acknowledge(accepted, new)
    for name, raw in before.items():
        if name != "report-accepted.json":
            assert snapshot(accepted)[name] == raw


@pytest.mark.parametrize("missing_accepted", [False, True])
def test_new_boot_real_receipt_precedence_and_old_outbox(accepted, missing_accepted):
    original = queue(accepted)
    complete(accepted)
    receipt = state(accepted, "completed.json").read_bytes()
    if missing_accepted:
        state(accepted, "report-accepted.json").unlink()
    new = queue(accepted, NEXT_BOOT)
    assert new["boot_id"] == NEXT_BOOT
    assert queue(accepted, "00000000-0000-4000-8000-000000000003") == new
    before = snapshot(accepted)
    with pytest.raises(e.EnrollmentError):
        acknowledge(accepted, original)
    assert snapshot(accepted) == before
    acknowledge(accepted, new)
    assert json.loads(state(accepted, "report-accepted.json").read_bytes())["report"] == new
    before = snapshot(accepted)
    with pytest.raises(e.EnrollmentError):
        acknowledge(accepted, original)
    assert snapshot(accepted) == before
    assert state(accepted, "completed.json").read_bytes() == receipt
    assert q.load_report(accepted[0], **args(accepted)) is None


def test_active_outbox_is_report_only_not_completion_permission(accepted):
    complete(accepted)
    report = queue(accepted, NEXT_BOOT)
    before = snapshot(accepted)
    assert q.load_report(accepted[0], **args(accepted)) == report
    for call in (c.complete_rotation, c.load_completed):
        with pytest.raises(e.EnrollmentError):
            call(accepted[0], **args(accepted))
    assert snapshot(accepted) == before
    acknowledge(accepted, report)
    assert c.load_completed(accepted[0], **args(accepted))["state"] == "rotation_completed"


def refused_without_writes(case):
    before = snapshot(case)
    report = json.loads(state(case, "completed.json").read_bytes())["accepted_record"]["report"]
    guards = []
    for call in (
        lambda: queue(case, NEXT_BOOT),
        lambda: q.load_report(case[0], **args(case)),
        lambda: q.acknowledge_report(
            case[0], report, ack(report), **args(case), commit_guard=lambda: guards.append(1)
        ),
    ):
        with pytest.raises(e.EnrollmentError):
            call()
    assert not guards
    assert snapshot(case) == before


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
        "extra",
    ],
)
def test_foreign_completed_not_ignored_even_with_normal_state(accepted, field):
    originals = snapshot(accepted)
    complete(accepted)
    for name in ("pending.json", "install.json"):
        path = state(accepted, name)
        path.write_bytes(originals[name])
        path.chmod(0o600)
    path = state(accepted, "completed.json")
    value = json.loads(path.read_bytes())
    value[field] = True if field == "version" else "foreign"
    path.write_text(json.dumps(value))
    refused_without_writes(accepted)


@pytest.mark.parametrize(
    "bad",
    [
        "backup_digest",
        "backup_context",
        "backup_ca",
        "accepted",
        "pending",
        "pending_key",
        "pending_digest",
        "journal",
        "outbox",
        "real_accepted",
    ],
)
def test_corrupt_receipt_or_foreign_remaining_no_writes(accepted, bad):
    originals = snapshot(accepted)
    complete(accepted)
    path = state(accepted, "completed.json")
    value = json.loads(path.read_bytes())
    previous = value["install_journal"]["previous_bundle"]
    if bad == "backup_digest":
        value["install_journal"]["previous_sha256"] = "0" * 64
    elif bad in {"backup_context", "backup_ca"}:
        previous["base_url" if bad == "backup_context" else "ca_cert"] += "foreign"
        value["install_journal"]["previous_sha256"] = c._digest(previous, 65536)
    elif bad == "accepted":
        value["accepted_record"]["ack"]["accepted"] = 1
    elif bad.startswith("pending"):
        pending = json.loads(originals["pending.json"])
        if bad == "pending_key":
            pending = c.r._new_pending(c.r._context(accepted[0]))
            pending["request_id"] = value["request_id"]
        elif bad == "pending":
            pending["request_id"] = NEXT_BOOT
        else:
            value["pending_sha256"] = "0" * 64
        target = state(accepted, "pending.json")
        target.write_text(json.dumps(pending))
        target.chmod(0o600)
    elif bad == "journal":
        journal = json.loads(originals["install.json"])
        journal["candidate_sha256"] = "0" * 64
        target = state(accepted, "install.json")
        target.write_text(json.dumps(journal))
        target.chmod(0o600)
    elif bad == "outbox":
        queue(accepted, NEXT_BOOT)
        target = state(accepted, "report-outbox.json")
        outbox = json.loads(target.read_bytes())
        outbox["report"]["boot_id"] = "invalid"
        target.write_text(json.dumps(outbox))
    else:
        target = state(accepted, "report-accepted.json")
        record = json.loads(target.read_bytes())
        record["candidate_sha256"] = "0" * 64
        target.write_text(json.dumps(record))
    path.write_text(json.dumps(value))
    refused_without_writes(accepted)


@pytest.mark.parametrize("reject", [False, True])
def test_embedded_ack_guard_before_fsync_once(accepted, monkeypatch, reject):
    report = queue(accepted)
    complete(accepted)
    state(accepted, "report-accepted.json").unlink()
    before = snapshot(accepted)
    events = []
    original = q._fsync

    def sync(fd):
        events.append("fsync")
        return original(fd)

    def guard():
        assert not events
        assert snapshot(accepted) == before
        events.append("guard")
        if reject:
            raise RuntimeError("private guard error")

    monkeypatch.setattr(q, "_fsync", sync)
    if reject:
        with pytest.raises(e.EnrollmentError):
            q.acknowledge_report(
                accepted[0], report, ack(report), **args(accepted), commit_guard=guard
            )
        assert events == ["guard"]
    else:
        q.acknowledge_report(accepted[0], report, ack(report), **args(accepted), commit_guard=guard)
        assert events == ["guard", "fsync"]
    assert snapshot(accepted) == before


@pytest.mark.parametrize("same_boot", [False, True])
def test_canonical_handler_after_retirement(accepted, paho, monkeypatch, same_boot):
    report = queue(accepted)
    complete(accepted)
    state(accepted, "report-accepted.json").unlink()
    receipt = state(accepted, "completed.json").read_bytes()
    handler = real_handler(accepted)
    if same_boot:
        handler._boot_id = report["boot_id"]
    posts = []

    def post(url, body, **kwargs):
        posts.append((url, body, kwargs))
        return ack(body)

    monkeypatch.setattr(e, "post_verified_json", post)
    before = snapshot(accepted)
    try:
        connect(handler)
        flush(handler)
        flush(handler)
        if same_boot:
            assert posts == []
            assert snapshot(accepted) == before
            assert not state(accepted, "report-accepted.json").exists()
        else:
            assert len(posts) == 1
            assert posts[0][1]["boot_id"] == handler._boot_id
            assert posts[0][0] == accepted[0]["base_url"] + "/device/certificates/report"
            assert posts[0][2] == {
                "token": accepted[0]["operational_token"],
                "timeout": 9,
                "https_ca_file": "/provisioned/https-ca.pem",
                "max_request": 2048,
            }
            assert (
                json.loads(state(accepted, "report-accepted.json").read_bytes())["report"]
                == posts[0][1]
            )
        assert not state(accepted, "report-outbox.json").exists()
        assert state(accepted, "completed.json").read_bytes() == receipt
    finally:
        handler._close_mqtt_publisher()


@pytest.mark.parametrize(
    "name,bad",
    [
        (name, bad)
        for name in (
            "completed.json",
            "report-accepted.json",
            "report-outbox.json",
            "pending.json",
            "install.json",
            ".lock",
            "credential",
        )
        for bad in ("mode", "symlink", "fifo", "duplicate", "oversize", "acl", "owner")
        if not (name == ".lock" and bad in {"duplicate", "oversize"})
    ],
)
def test_unsafe_records_refused_not_repaired(accepted, monkeypatch, name, bad):
    report = queue(accepted)
    originals = snapshot(accepted)
    complete(accepted)
    if name in {"pending.json", "install.json"}:
        path = state(accepted, name)
        path.write_bytes(originals[name])
        path.chmod(0o600)
    if name == "report-outbox.json":
        queue(accepted, NEXT_BOOT)
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
            os,
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

        monkeypatch.setattr(os, "fstat", foreign)

    def safe_snapshot():
        # Do not open a deliberately poisoned FIFO credential or follow symlinks.
        directory = state(accepted, ".lock").parent
        return {
            p.name: p.read_bytes()
            for p in directory.iterdir()
            if p.is_file() and not p.is_symlink()
        } | {
            "credential": accepted[2].read_bytes()
            if accepted[2].is_file() and not accepted[2].is_symlink()
            else None
        }

    before = safe_snapshot()
    meta = path.lstat()
    for call in (
        lambda: queue(accepted, NEXT_BOOT),
        lambda: q.load_report(accepted[0], **args(accepted)),
        lambda: acknowledge(accepted, report),
    ):
        with pytest.raises(e.EnrollmentError):
            call()
    assert safe_snapshot() == before
    after = path.lstat()
    assert (meta.st_ino, meta.st_mode, meta.st_mtime_ns, meta.st_size) == (
        after.st_ino,
        after.st_mode,
        after.st_mtime_ns,
        after.st_size,
    )


def test_concurrent_embedded_receipt_and_descriptor_release(accepted, monkeypatch):
    report = queue(accepted)
    complete(accepted)
    state(accepted, "report-accepted.json").unlink()
    before = snapshot(accepted)
    opened = []
    original = os.open

    def tracked(*a, **k):
        fd = original(*a, **k)
        opened.append(fd)
        return fd

    monkeypatch.setattr(os, "open", tracked)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert (
            list(pool.map(lambda _: acknowledge(accepted, report), range(8))) == [ack(report)] * 8
        )
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert snapshot(accepted) == before


@pytest.mark.parametrize("bad", ["version", "binding", "boot", "ack", "bound"])
def test_embedded_record_strict_validation(pure_completion, monkeypatch, bad):
    value, current, _, binding = pure_completion
    record = value["accepted_record"]
    if bad == "version":
        record["version"] = True
    elif bad == "binding":
        record["candidate_sha256"] = "0" * 64
    elif bad == "boot":
        record["report"]["boot_id"] = "invalid"
    elif bad == "ack":
        record["ack"]["accepted"] = 1
    else:
        record["report"]["extra"] = "x" * 8192

    def absent(*a):
        raise FileNotFoundError

    monkeypatch.setattr(q, "_read_private_json", absent)
    with pytest.raises(e.EnrollmentError):
        q._record(123, q._ACCEPTED, current, binding, accepted_fallback=record)


def test_real_accepted_precedence_and_io_errors_no_fallback(pure_completion, monkeypatch):
    value, current, _, binding = pure_completion
    original = value["accepted_record"]
    real = dict(
        original, report=dict(original["report"], boot_id="00000000-0000-4000-8000-000000000003")
    )
    monkeypatch.setattr(q, "_read_private_json", lambda *a: (real, b"real-file"))
    assert q._record(123, q._ACCEPTED, current, binding, accepted_fallback=original) == (
        real,
        b"real-file",
    )

    def unsafe(*a):
        raise PermissionError

    monkeypatch.setattr(q, "_read_private_json", unsafe)
    with pytest.raises(PermissionError):
        q._record(123, q._ACCEPTED, current, binding, accepted_fallback=original)


@pytest.mark.parametrize(
    "bad",
    [
        "caller",
        "current_digest",
        "current_metadata",
        "alternate_path",
        "missing_completion_pending",
        "missing_completion_journal",
    ],
)
def test_current_and_missing_completion_authority_no_writes(accepted, bad):
    original_report = queue(accepted)
    if bad.startswith("missing_completion"):
        state(accepted, "pending.json" if bad.endswith("pending") else "install.json").unlink()
    else:
        complete(accepted)
        if bad == "caller":
            accepted = dict(accepted[0], extra=True), accepted[1], accepted[2]
        elif bad in {"current_digest", "current_metadata"}:
            current = dict(accepted[0])
            current["extra" if bad == "current_digest" else "fingerprint_sha256"] = (
                True if bad == "current_digest" else "0" * 64
            )
            accepted[2].write_text(json.dumps(current))
            accepted = current, accepted[1], accepted[2]
        else:
            target = accepted[2].with_name("alternate.json")
            target.write_bytes(accepted[2].read_bytes())
            target.chmod(0o600)
            accepted = accepted[0], accepted[1], target
    before = snapshot(accepted)
    for call in (
        lambda: queue(accepted, NEXT_BOOT),
        lambda: q.load_report(accepted[0], **args(accepted)),
        lambda: acknowledge(accepted, original_report),
    ):
        with pytest.raises(e.EnrollmentError):
            call()
    assert snapshot(accepted) == before


@pytest.mark.parametrize("field", ["candidate_sha256", "credential_file", "generation_sha256"])
def test_foreign_active_outbox_cannot_hide_behind_allow_flag(accepted, field):
    complete(accepted)
    queue(accepted, NEXT_BOOT)
    path = state(accepted, "report-outbox.json")
    record = json.loads(path.read_bytes())
    record[field] = "foreign"
    path.write_text(json.dumps(record))
    refused_without_writes(accepted)


@pytest.mark.parametrize("expired", ["old_completed", "old_uncompleted", "current_completed"])
def test_real_walltime_expiry_report_authority(
    bundle, enroll_fixture, tmp_path, monkeypatch, expired
):
    # Reuse the existing genuine short-lived certificate installation and natural
    # wall-time wait. No datetime monkeypatch or ordinary validation relaxation.
    exercise_real_expiry(bundle, enroll_fixture, tmp_path, monkeypatch, expired)
    target = enroll_fixture[0]["credential_file"]
    case = json.loads(target.read_bytes()), tmp_path, target
    before = snapshot(case)
    if expired == "old_completed":
        report = queue(case)
        assert acknowledge(case, report) == ack(report)
        assert q.load_report(case[0], **args(case)) is None
        assert snapshot(case) == before
        new = queue(case, NEXT_BOOT)
        acknowledge(case, new)
        assert state(case, "completed.json").read_bytes() == before["completed.json"]
    else:
        report = json.loads(state(case, "report-accepted.json").read_bytes())["report"]
        for call in (
            lambda: queue(case, NEXT_BOOT),
            lambda: q.load_report(case[0], **args(case)),
            lambda: acknowledge(case, report),
        ):
            with pytest.raises(e.EnrollmentError):
                call()
        assert snapshot(case) == before
