"""Offline public report core; synthetic PKI, never broker proof."""

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
from tests.test_glass_rotation_install import (  # noqa: F401
    bundle,
    enroll_fixture,
    install,
    installation,
)

BOOT = "00000000-0000-4000-8000-000000000001"
NEXT_BOOT = "00000000-0000-4000-8000-000000000002"


@pytest.fixture
def installed(installation):  # noqa: F811
    install(installation)
    _, _, store, target = installation
    return json.loads(target.read_bytes()), store, target


def api():
    return importlib.import_module("repeater.glass.rotation_reports")


def args(case):
    return {"store_dir": case[1], "credential_file": case[2]}


def queue(case, boot=BOOT, **overrides):
    callback = {
        "boot_id": boot,
        "connected_serial": case[0]["cert_serial"],
        "connected_fingerprint": case[0]["fingerprint_sha256"],
    }
    callback.update(overrides)
    return api().queue_report(case[0], **args(case), **callback)


def ack(report):
    return {k: report[k] for k in ("device_id", "request_id", "cert_serial")} | {
        "accepted": True,
        "state": "node_reported",
    }


def acknowledge(case, report, response=None):
    return api().acknowledge_report(
        case[0], report, ack(report) if response is None else response, **args(case)
    )


def state(case, name):
    return case[1] / "rotation-state" / name


def snapshot(case):
    return {
        p.name: p.read_bytes()
        for p in (case[1] / "rotation-state").iterdir()
        if p.is_file() and not p.is_symlink()
    } | {"credential": case[2].read_bytes()}


def test_public_records_and_exact_boot_lifecycle(installed):
    before = snapshot(installed)
    report = queue(installed)
    assert set(report) == {
        "device_id",
        "request_id",
        "cert_serial",
        "fingerprint_sha256",
        "boot_id",
        "connected",
    }
    outbox = state(installed, "report-outbox.json")
    raw = outbox.read_bytes()
    saved = json.loads(raw)
    assert set(saved) == api()._RECORD_FIELDS
    assert saved["candidate_sha256"] == r._bundle_digest(installed[0])
    assert saved["credential_file"] == str(installed[2])
    assert len(raw) <= 4096
    assert stat.S_IMODE(outbox.stat().st_mode) == 0o600
    for secret in (
        installed[0]["operational_token"],
        installed[0]["private_key"],
        "BEGIN CERTIFICATE",
    ):
        assert secret not in raw.decode()
    assert queue(installed, NEXT_BOOT) == report
    assert outbox.read_bytes() == raw
    assert api().load_report(installed[0], **args(installed)) == report
    assert acknowledge(installed, report) == ack(report)
    assert not outbox.exists()
    accepted = state(installed, "report-accepted.json")
    accepted_raw = accepted.read_bytes()
    assert len(accepted_raw) <= 8192
    assert set(json.loads(accepted_raw)) == api()._RECORD_FIELDS | {"ack"}
    assert stat.S_IMODE(accepted.stat().st_mode) == 0o600
    assert acknowledge(installed, report) == ack(report)
    assert queue(installed) == report
    assert not outbox.exists()
    assert accepted.read_bytes() == accepted_raw
    new = queue(installed, NEXT_BOOT)
    assert new["boot_id"] == NEXT_BOOT
    frozen = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        acknowledge(installed, report)
    assert snapshot(installed) == frozen
    acknowledge(installed, new)
    assert json.loads(accepted.read_bytes())["report"] == new
    assert api().load_report(installed[0], **args(installed)) is None
    after = snapshot(installed)
    for name, raw in before.items():
        assert after[name] == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("boot_id", None),
        ("boot_id", 1),
        ("boot_id", BOOT.upper()),
        ("boot_id", "{" + BOOT + "}"),
        ("boot_id", "bad"),
        ("connected_serial", 1),
        ("connected_serial", "0"),
        ("connected_serial", "f" * 41),
        ("connected_serial", "deadbeef"),
        ("connected_fingerprint", None),
        ("connected_fingerprint", "A" * 64),
        ("connected_fingerprint", "0" * 64),
    ],
)
def test_invalid_callback_no_writes(installed, field, value):
    # BOOT contains no letters: use an actually uppercase UUID for that case.
    if field == "boot_id" and value == BOOT.upper():
        value = "AAAAAAAA-0000-4000-8000-000000000001"
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        queue(installed, **{field: value})
    assert snapshot(installed) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("device_id", NEXT_BOOT),
        ("request_id", NEXT_BOOT),
        ("cert_serial", "0"),
        ("accepted", 1),
        ("accepted", False),
        ("state", "issued"),
        ("state", True),
        ("extra", "secret-error"),
    ],
)
def test_exact_ack_no_writes(installed, field, value):
    report = queue(installed)
    response = dict(ack(report), **{field: value})
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError) as error:
        acknowledge(installed, report, response)
    assert "secret-error" not in str(error.value)
    assert error.value.__suppress_context__
    assert snapshot(installed) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("boot_id", NEXT_BOOT),
        ("connected", 1),
        ("fingerprint_sha256", "0" * 64),
        ("extra", "bad"),
        ("cert_serial", 1),
    ],
)
def test_expected_report_binding_no_writes(installed, field, value):
    report = queue(installed)
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        acknowledge(installed, dict(report, **{field: value}), ack(report))
    assert snapshot(installed) == before


@pytest.mark.parametrize("name", ["report-outbox.json", "report-accepted.json"])
@pytest.mark.parametrize(
    "bad",
    [
        "mode",
        "symlink",
        "fifo",
        "duplicate",
        "oversize",
        "version",
        "generation",
        "path",
        "digest",
        "extra",
        "acl",
    ],
)
def test_unsafe_records_fail_without_repair(installed, monkeypatch, name, bad):
    report = queue(installed)
    if name == "report-accepted.json":
        acknowledge(installed, report)
    path = state(installed, name)
    if bad == "mode":
        path.chmod(0o644)
    elif bad == "symlink":
        saved = path.with_name("saved.json")
        path.rename(saved)
        path.symlink_to(saved)
    elif bad == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif bad == "duplicate":
        raw = path.read_text()
        path.write_text(raw[:-1] + ',"version":1}')
    elif bad == "oversize":
        path.write_bytes(b" " * (8193 if name == "report-accepted.json" else 4097))
    elif bad == "acl":
        real = os.listxattr
        inode = path.stat().st_ino
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
        value = json.loads(path.read_bytes())
        key = {
            "version": "version",
            "generation": "generation_sha256",
            "path": "credential_file",
            "digest": "candidate_sha256",
            "extra": "extra",
        }[bad]
        value[key] = True if bad == "version" else "foreign"
        path.write_text(json.dumps(value))
    info = path.lstat()
    metadata = info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size
    before = snapshot(installed) if bad != "fifo" else None
    for call in (
        lambda: queue(installed),
        lambda: api().load_report(installed[0], **args(installed)),
        lambda: acknowledge(installed, report),
    ):
        with pytest.raises(e.EnrollmentError):
            call()
    info = path.lstat()
    assert (info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size) == metadata
    if before is not None:
        assert snapshot(installed) == before


@pytest.mark.parametrize(
    "bad",
    [
        "caller",
        "current",
        "pending_key",
        "journal_digest",
        "previous_context",
        "missing_pending",
        "missing_journal",
        "missing_lock",
    ],
)
def test_installed_authority_fail_closed(installed, bad):
    current, store, target = installed
    if bad == "caller":
        installed = dict(current, extra=True), store, target
    elif bad == "current":
        target.write_text(json.dumps(dict(current, extra=True)))
    elif bad == "pending_key":
        path = state(installed, "pending.json")
        value = json.loads(path.read_bytes())
        value["private_key"] = "secret-invalid"
        path.write_text(json.dumps(value))
    elif bad in ("journal_digest", "previous_context"):
        path = state(installed, "install.json")
        value = json.loads(path.read_bytes())
        if bad == "journal_digest":
            value["candidate_sha256"] = "0" * 64
        else:
            value["previous_bundle"]["base_url"] = "https://foreign.example"
            value["previous_sha256"] = r._bundle_digest(value["previous_bundle"])
        path.write_text(json.dumps(value))
    else:
        state(
            installed,
            {
                "missing_pending": "pending.json",
                "missing_journal": "install.json",
                "missing_lock": ".lock",
            }[bad],
        ).unlink()
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        queue(installed)
    assert snapshot(installed) == before


@pytest.mark.parametrize(
    "bad", ["relative", "traversal", "reserved", "rotation_parent", "alternate"]
)
def test_credential_filename_binding(installed, bad):
    current, store, target = installed
    if bad == "relative":
        path = target.name
    elif bad == "traversal":
        path = str(store) + "/../" + store.name + "/" + target.name
    elif bad == "reserved":
        path = store / "report-outbox.json"
    else:
        path = (store / "rotation-state" if bad == "rotation_parent" else store) / "alternate.json"
        path.write_bytes(target.read_bytes())
        path.chmod(0o600)
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        queue((current, store, path))
    assert snapshot(installed) == before


@pytest.mark.parametrize("phase", ["queue", "ack"])
@pytest.mark.parametrize(
    "fault", ["write", "file_fsync", "replace", "dir_fsync", "readback", "unlink"]
)
def test_publication_fault_and_retry(installed, monkeypatch, phase, fault):
    module = api()
    report = queue(installed) if phase == "ack" else None
    outbox = state(installed, "report-outbox.json")
    accepted = state(installed, "report-accepted.json")
    before = snapshot(installed)
    destination = "report-accepted.json" if phase == "ack" else "report-outbox.json"
    real_write, real_sync, real_replace, real_read, real_unlink = (
        module._write_staged,
        module._fsync,
        module._replace,
        module._read_private_json,
        module._unlink,
    )
    published = False
    with monkeypatch.context() as patch:

        def fail():
            raise OSError("secret-io-error")

        def write(fd, name, data, **kwargs):
            if fault in ("write", "file_fsync"):
                created = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                kwargs["on_create"]()
                os.write(created, data[:20])
                os.close(created)
                fail()
            return real_write(fd, name, data, **kwargs)

        def replace(src, dst, **kwargs):
            nonlocal published
            if fault == "replace":
                fail()
            result = real_replace(src, dst, **kwargs)
            published = True
            return result

        def sync(fd):
            if fault == "dir_fsync" and published:
                fail()
            return real_sync(fd)

        def read(fd, name, limit):
            if fault == "readback" and published and name == destination:
                fail()
            return real_read(fd, name, limit)

        def unlink(name, **kwargs):
            if fault == "unlink" and name == "report-outbox.json":
                fail()
            return real_unlink(name, **kwargs)

        patch.setattr(module, "_write_staged", write)
        patch.setattr(module, "_replace", replace)
        patch.setattr(module, "_fsync", sync)
        patch.setattr(module, "_read_private_json", read)
        patch.setattr(module, "_unlink", unlink)
        if fault == "unlink" and phase == "queue":
            report = queue(installed)
        else:
            with pytest.raises(e.EnrollmentError) as error:
                queue(installed) if phase == "queue" else acknowledge(installed, report)
            assert "secret-io-error" not in str(error.value)
    assert not any(p.name.startswith(".stage-") for p in outbox.parent.iterdir())
    if fault in ("write", "file_fsync", "replace"):
        assert snapshot(installed) == before
    if phase == "ack":
        assert outbox.exists()
        acknowledge(installed, report)
        assert accepted.exists() and not outbox.exists()
    else:
        assert queue(installed)["boot_id"] == BOOT


@pytest.mark.parametrize("fault", ["short_write", "flush", "fsync"])
def test_actual_stage_stream_fault(installed, monkeypatch, fault):
    module = api()
    real = os.fdopen
    before = snapshot(installed)

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
        stream = real(fd, mode)
        return Broken(stream) if mode == "wb" else stream

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "fdopen", fdopen)
        if fault == "fsync":
            patch.setattr(r, "_fsync", lambda fd: (_ for _ in ()).throw(OSError("secret-fsync")))
        with pytest.raises(e.EnrollmentError):
            queue(installed)
    assert snapshot(installed) == before
    assert queue(installed)["boot_id"] == BOOT


@pytest.mark.parametrize("fault", ["unlink", "after_unlink_fsync", "after_unlink_readback"])
def test_ack_crash_windows_and_retry(installed, monkeypatch, fault):
    module = api()
    report = queue(installed)
    real_unlink, real_sync, real_read = module._unlink, module._fsync, module._read_private_json
    deleted = False
    with monkeypatch.context() as patch:

        def unlink(name, **kwargs):
            nonlocal deleted
            if name == "report-outbox.json" and fault == "unlink":
                raise OSError("crash")
            result = real_unlink(name, **kwargs)
            if name == "report-outbox.json":
                deleted = True
            return result

        def sync(fd):
            if deleted and fault == "after_unlink_fsync":
                raise OSError("crash")
            return real_sync(fd)

        def read(fd, name, limit):
            if deleted and fault == "after_unlink_readback":
                raise OSError("crash")
            return real_read(fd, name, limit)

        patch.setattr(module, "_unlink", unlink)
        patch.setattr(module, "_fsync", sync)
        patch.setattr(module, "_read_private_json", read)
        with pytest.raises(e.EnrollmentError):
            acknowledge(installed, report)
    receipt = state(installed, "report-accepted.json").read_bytes()
    assert api().load_report(installed[0], **args(installed)) == (
        report if fault == "unlink" else None
    )
    acknowledge(installed, report)
    assert state(installed, "report-accepted.json").read_bytes() == receipt
    assert not state(installed, "report-outbox.json").exists()


def test_restart_and_concurrent_process_reuse(installed):
    report = queue(installed)
    before = snapshot(installed)
    code = (
        "import json,sys; from repeater.glass import rotation_reports as q; "
        "c=json.load(sys.stdin); print(json.dumps(q.queue_report(c,store_dir=sys.argv[1],"
        "credential_file=sys.argv[2],boot_id=sys.argv[3],connected_serial=c['cert_serial'],"
        "connected_fingerprint=c['fingerprint_sha256'])))"
    )

    def child(_):
        result = subprocess.run(
            [sys.executable, "-c", code, str(installed[1]), str(installed[2]), NEXT_BOOT],
            input=json.dumps(installed[0]),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(value == report for value in pool.map(child, range(8)))
    assert snapshot(installed) == before
    ack_code = (
        "import json,sys; from repeater.glass import rotation_reports as q; c,r,a=json.load(sys.stdin); "
        "print(json.dumps(q.acknowledge_report(c,r,a,store_dir=sys.argv[1],credential_file=sys.argv[2])))"
    )

    def ack_child(_):
        result = subprocess.run(
            [sys.executable, "-c", ack_code, str(installed[1]), str(installed[2])],
            input=json.dumps([installed[0], report, ack(report)]),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(value == ack(report) for value in pool.map(ack_child, range(8)))


def test_owned_stage_collision_and_descriptor_cleanup(installed, monkeypatch):
    module = api()
    foreign = state(installed, ".stage-" + "a" * 32)
    foreign.write_bytes(b"foreign")
    foreign.chmod(0o600)
    real_open = os.open
    opened = []

    def tracked(*values, **kwargs):
        fd = real_open(*values, **kwargs)
        opened.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(module.secrets, "token_hex", lambda _: "a" * 32)
        patch.setattr(module.os, "open", tracked)
        with pytest.raises(e.EnrollmentError):
            queue(installed)
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)
    assert foreign.read_bytes() == b"foreign"
    assert queue(installed)["boot_id"] == BOOT


@pytest.mark.parametrize("window", ["before_unlink", "after_unlink"])
def test_abrupt_process_ack_crash_and_restart(installed, window):
    report = queue(installed)
    code = (
        "import json,os,sys; from repeater.glass import rotation_reports as q; "
        "c,r,a=json.load(sys.stdin); original=q._unlink; "
        "window=sys.argv[3]; "
        'exec("def crash(name, **kw):\\n'
        " if name == 'report-outbox.json' and window == 'before_unlink': os._exit(23)\\n"
        " result=original(name, **kw)\\n"
        " if name == 'report-outbox.json': os._exit(24)\\n"
        ' return result\\n"); q._unlink=crash; '
        "q.acknowledge_report(c,r,a,store_dir=sys.argv[1],credential_file=sys.argv[2])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(installed[1]), str(installed[2]), window],
        input=json.dumps([installed[0], report, ack(report)]),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == (23 if window == "before_unlink" else 24), result.stderr
    receipt = state(installed, "report-accepted.json").read_bytes()
    assert state(installed, "report-outbox.json").exists() is (window == "before_unlink")
    retry_code = (
        "import json,sys; from repeater.glass import rotation_reports as q; c,r,a=json.load(sys.stdin); "
        "print(json.dumps(q.acknowledge_report(c,r,a,store_dir=sys.argv[1],credential_file=sys.argv[2])))"
    )
    result = subprocess.run(
        [sys.executable, "-c", retry_code, str(installed[1]), str(installed[2])],
        input=json.dumps([installed[0], report, ack(report)]),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ack(report)
    assert state(installed, "report-accepted.json").read_bytes() == receipt
    assert not state(installed, "report-outbox.json").exists()


@pytest.mark.parametrize("part", ["response", "report"])
def test_missing_exact_field_no_writes(installed, part):
    report = queue(installed)
    response = ack(report)
    if part == "response":
        response.pop("accepted")
    else:
        report.pop("connected")
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        api().acknowledge_report(installed[0], report, response, **args(installed))
    assert snapshot(installed) == before


@pytest.mark.parametrize("part", ["current", "previous"])
def test_expiry_metadata_is_not_bypassed(installed, part):
    current, store, target = installed
    if part == "current":
        current = dict(current, expires_at="2000-01-01T00:00:00Z")
        target.write_text(json.dumps(current))
    else:
        path = state(installed, "install.json")
        journal = json.loads(path.read_bytes())
        journal["previous_bundle"]["expires_at"] = "2000-01-01T00:00:00Z"
        journal["previous_sha256"] = r._bundle_digest(journal["previous_bundle"])
        path.write_text(json.dumps(journal))
    before = snapshot(installed)
    with pytest.raises(e.EnrollmentError):
        queue((current, store, target))
    assert snapshot(installed) == before


@pytest.mark.parametrize(
    "bad", ["mode", "symlink", "fifo", "duplicate", "oversize", "acl", "owner"]
)
def test_unsafe_current_file(installed, monkeypatch, bad):
    target = installed[2]
    if bad == "mode":
        target.chmod(0o644)
    elif bad == "symlink":
        real = target.with_name("real.json")
        target.rename(real)
        target.symlink_to(real)
    elif bad == "fifo":
        target.unlink()
        os.mkfifo(target, 0o600)
    elif bad == "duplicate":
        raw = target.read_text()
        target.write_text(raw[:-1] + ',"device_id":"duplicate"}')
    elif bad == "oversize":
        target.write_bytes(b" " * 65537)
    elif bad == "acl":
        real = os.listxattr
        inode = target.stat().st_ino
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
        real = os.fstat
        inode = target.stat().st_ino

        def foreign(fd):
            info = real(fd)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return info

        monkeypatch.setattr(api().os, "fstat", foreign)
    info = target.lstat()
    metadata = info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size
    with pytest.raises(e.EnrollmentError):
        queue(installed)
    info = target.lstat()
    assert (info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size) == metadata
    assert not state(installed, "report-outbox.json").exists()


def test_cleanup_error_releases_descriptors(installed, monkeypatch):
    module = api()
    real_open, real_unlink = os.open, module._unlink
    opened = []

    def tracked(*values, **kwargs):
        fd = real_open(*values, **kwargs)
        opened.append(fd)
        return fd

    def cleanup(name, **kwargs):
        if name.startswith(".stage-"):
            raise OSError("secret-cleanup")
        return real_unlink(name, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "open", tracked)
        patch.setattr(module, "_unlink", cleanup)
        patch.setattr(r, "_fsync", lambda fd: (_ for _ in ()).throw(OSError("secret-stage")))
        with pytest.raises(e.EnrollmentError) as error:
            queue(installed)
        assert "secret-" not in str(error.value)
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)
    for stage in (installed[1] / "rotation-state").glob(".stage-*"):
        stage.unlink()
    assert queue(installed)["boot_id"] == BOOT


def test_report_api_exists():
    module = importlib.import_module("repeater.glass.rotation_reports")
    for name in ("queue_report", "load_report", "acknowledge_report"):
        assert callable(getattr(module, name, None))
