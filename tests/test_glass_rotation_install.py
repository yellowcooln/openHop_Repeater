"""Inactive atomic bundle install, synthetic PKI only; no handler or transport."""

import json
import os
import stat
import subprocess
import sys

import pytest

from repeater.glass import enrollment as e
from repeater.glass import rotation_state as r
from tests.test_glass_rotation_state import (  # noqa: F401
    bundle,
    enroll_fixture,
    pending,
    renewal_response,
)


def test_install_api_exists():
    assert callable(getattr(r, "install_renewal_candidate", None))


@pytest.fixture
def installation(bundle, enroll_fixture, tmp_path):  # noqa: F811
    args, _, _ = enroll_fixture
    response = renewal_response(bundle, tmp_path)
    return bundle, response, tmp_path, args["credential_file"]


def install(case, credentials=None, response=None, path=None):
    old, issued, store, target = case
    return r.install_renewal_candidate(
        old if credentials is None else credentials,
        issued if response is None else response,
        store_dir=store,
        credential_file=target if path is None else path,
    )


def snapshots(case):
    _, _, store, target = case
    return target.read_bytes(), pending(store).read_bytes()


def test_install_receipt_backup_and_exact_retries(installation):
    old, issued, store, target = installation
    before = snapshots(installation)
    inputs = json.dumps([old, issued], sort_keys=True)
    expected = {
        field: issued[field]
        for field in ("device_id", "request_id", "cert_serial", "fingerprint_sha256", "expires_at")
    }
    expected["state"] = "bundle_installed"
    assert install(installation) == expected
    candidate = json.loads(target.read_bytes())
    journal = store / "rotation-state/install.json"
    backup = json.loads(journal.read_bytes())
    assert backup["previous_bundle"] == old
    assert backup["previous_sha256"] == r._bundle_digest(old)
    assert backup["candidate_sha256"] == r._bundle_digest(candidate)
    assert backup["credential_file"] == str(target)
    assert set(backup) == r._INSTALL_FIELDS
    assert "private_key" not in backup
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.dumps([old, issued], sort_keys=True) == inputs
    assert pending(store).read_bytes() == before[1]
    durable = target.read_bytes(), journal.read_bytes()
    for caller in (old, candidate, old, candidate):
        assert install(installation, credentials=caller) == expected
        assert (target.read_bytes(), journal.read_bytes()) == durable
    assert {p.name for p in journal.parent.iterdir()} == {"pending.json", ".lock", "install.json"}


@pytest.mark.parametrize(
    "field",
    [
        "request_id",
        "device_id",
        "client_cert",
        "ca_cert",
        "expires_at",
        "cert_serial",
        "fingerprint_sha256",
        "state",
    ],
)
def test_bad_response_no_writes(installation, field):
    before = snapshots(installation)
    bad = dict(installation[1], **{field: "secret-invalid"})
    with pytest.raises(e.EnrollmentError) as error:
        install(installation, response=bad)
    assert "secret-invalid" not in str(error.value)
    assert error.value.__suppress_context__
    assert snapshots(installation) == before
    assert not (installation[2] / "rotation-state/install.json").exists()


@pytest.mark.parametrize("bad", ["extra", "token", "origin"])
def test_foreign_current_no_journal(installation, bad):
    old, _, _, target = installation
    current = dict(old)
    field, value = {
        "extra": ("extra", "foreign"),
        "token": ("operational_token", "F" * 43),
        "origin": ("base_url", "https://foreign.example"),
    }[bad]
    current[field] = value
    target.write_text(json.dumps(current))
    before = snapshots(installation)
    with pytest.raises(e.EnrollmentError):
        install(installation)
    assert snapshots(installation) == before
    assert not (installation[2] / "rotation-state/install.json").exists()


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "base_url",
        "device_id",
        "generation_sha256",
        "request_id",
        "credential_file",
        "previous_sha256",
        "candidate_sha256",
        "previous_bundle",
        "extra",
    ],
)
def test_corrupt_existing_journal_never_repaired(installation, field):
    install(installation)
    journal = installation[2] / "rotation-state/install.json"
    value = json.loads(journal.read_bytes())
    value[field] = True if field == "version" else "secret-invalid"
    journal.write_text(json.dumps(value))
    before = snapshots(installation), journal.read_bytes()
    with pytest.raises(e.EnrollmentError) as error:
        install(installation)
    assert "secret-invalid" not in str(error.value)
    assert (snapshots(installation), journal.read_bytes()) == before


@pytest.mark.parametrize(
    "bad",
    [
        "missing",
        "mode",
        "symlink",
        "fifo",
        "acl",
        "owner",
        "duplicate",
        "corrupt",
        "oversize",
        "array",
    ],
)
def test_unsafe_existing_target_refused(installation, monkeypatch, bad):
    target = installation[3]
    if bad == "missing":
        target.unlink()
    elif bad == "mode":
        target.chmod(0o644)
    elif bad == "symlink":
        target.rename(target.with_name("real.json"))
        target.symlink_to(target.with_name("real.json"))
    elif bad == "fifo":
        target.unlink()
        os.mkfifo(target, 0o600)
    elif bad == "acl":
        real = os.listxattr
        inode = target.stat().st_ino
        monkeypatch.setattr(
            r.os,
            "listxattr",
            lambda fd: (
                ["system.posix_acl_access"]
                if isinstance(fd, int) and os.fstat(fd).st_ino == inode
                else real(fd)
            ),
        )
    elif bad == "owner":
        real = os.fstat
        inode = target.stat().st_ino

        def fake(fd):
            info = real(fd)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return info

        monkeypatch.setattr(r.os, "fstat", fake)
    else:
        raw = {
            "duplicate": '{"a":1,"a":2}',
            "corrupt": "secret-invalid",
            "oversize": " " * 65537,
            "array": "[]",
        }[bad]
        target.write_text(raw)
    with pytest.raises(e.EnrollmentError):
        install(installation)
    assert not (installation[2] / "rotation-state/install.json").exists()


@pytest.mark.parametrize(
    "bad",
    [
        "relative",
        "traversal",
        "lock",
        "pending",
        "journal",
        "stage",
        "rotation_parent",
        "symlink_parent",
        "missing_parent",
        "writable_parent",
    ],
)
def test_target_path_authority(installation, bad):
    store = installation[2]
    target = installation[3]
    if bad == "relative":
        path = "credentials.json"
    elif bad == "traversal":
        path = str(store) + "/../" + store.name + "/credentials.json"
    elif bad in ("lock", "pending", "journal", "stage"):
        name = {
            "lock": ".lock",
            "pending": "pending.json",
            "journal": "install.json",
            "stage": ".stage-foo",
        }[bad]
        path = store / name
    elif bad == "rotation_parent":
        path = store / "rotation-state/credentials.json"
        path.write_bytes(target.read_bytes())
        path.chmod(0o600)
    elif bad == "symlink_parent":
        link = store / "linked"
        link.symlink_to(store)
        path = link / target.name
    elif bad == "missing_parent":
        path = store / "missing/credentials.json"
    else:
        parent = store / "writable"
        parent.mkdir(mode=0o775)
        parent.chmod(0o775)
        path = parent / target.name
        path.write_bytes(target.read_bytes())
        path.chmod(0o600)
    before = snapshots(installation)
    with pytest.raises(e.EnrollmentError):
        install(installation, path=path)
    assert snapshots(installation) == before
    assert not (store / "rotation-state/install.json").exists()


@pytest.mark.parametrize("phase", ["journal", "credential"])
@pytest.mark.parametrize("operation", ["write", "file_fsync", "replace", "dir_fsync", "readback"])
def test_io_failure_and_durable_retry(installation, monkeypatch, phase, operation):
    old, _, store, target = installation
    before = snapshots(installation)
    state = store / "rotation-state"
    candidate = r.validate_renewal_candidate(old, installation[1], store_dir=store)
    original_write, original_sync, original_replace, original_read = (
        r._write_staged,
        r._fsync,
        r._replace,
        r._read_private_json,
    )
    directory_inode = (state if phase == "journal" else target.parent).stat().st_ino
    with monkeypatch.context() as patch:

        def failure():
            raise OSError("secret-io-error")

        def write(fd, name, data, **kwargs):
            in_phase = os.fstat(fd).st_ino == directory_inode
            if operation == "write" and in_phase:
                staged = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                kwargs["on_create"]()
                os.write(staged, data[:20])
                os.close(staged)
                failure()
            return original_write(fd, name, data, **kwargs)

        def sync(fd):
            info = os.fstat(fd)
            if operation == "dir_fsync" and info.st_ino == directory_inode:
                failure()
            if operation == "file_fsync" and stat.S_ISREG(info.st_mode):
                actual = os.readlink(f"/proc/self/fd/{fd}")
                if actual.startswith(
                    str(state if phase == "journal" else target.parent) + "/.stage-"
                ):
                    failure()
            return original_sync(fd)

        def replace(src, dst, **kwargs):
            if operation == "replace" and dst == (
                "install.json" if phase == "journal" else target.name
            ):
                failure()
            return original_replace(src, dst, **kwargs)

        def read(fd, name, limit):
            if operation == "readback":
                if phase == "journal" and name == "install.json" and (state / name).exists():
                    failure()
                if (
                    phase == "credential"
                    and name == target.name
                    and json.loads(target.read_bytes()) == candidate
                ):
                    failure()
            return original_read(fd, name, limit)

        patch.setattr(r, "_write_staged", write)
        patch.setattr(r, "_fsync", sync)
        patch.setattr(r, "_replace", replace)
        patch.setattr(r, "_read_private_json", read)
        with pytest.raises(e.EnrollmentError) as error:
            install(installation)
        assert "secret-io-error" not in str(error.value)
    assert pending(store).read_bytes() == before[1]
    if phase == "journal" or operation in ("write", "file_fsync", "replace"):
        assert target.read_bytes() == before[0]
    else:
        assert json.loads(target.read_bytes()) == candidate
    assert not any(
        p.name.startswith(".stage-") for parent in (state, target.parent) for p in parent.iterdir()
    )
    journal_before = (
        (state / "install.json").read_bytes() if (state / "install.json").exists() else None
    )
    assert install(installation)["state"] == "bundle_installed"
    if journal_before is not None:
        assert (state / "install.json").read_bytes() == journal_before


def test_candidate_stage_tamper_and_current_race(installation, monkeypatch):
    target = installation[3]
    before = target.read_bytes()
    original = r._write_staged
    for race in (False, True):
        with monkeypatch.context() as patch:

            def tamper(fd, name, data, *, race=race, **kwargs):
                original(fd, name, data, **kwargs)
                if os.fstat(fd).st_ino == target.parent.stat().st_ino:
                    if race:
                        changed = dict(installation[0], unexpected="foreign")
                        target.write_text(json.dumps(changed))
                    else:
                        staged_fd = os.open(name, os.O_WRONLY | os.O_TRUNC, dir_fd=fd)
                        os.write(staged_fd, b"{}")
                        os.close(staged_fd)

            patch.setattr(r, "_write_staged", tamper)
            with pytest.raises(e.EnrollmentError):
                install(installation)
        if not race:
            assert target.read_bytes() == before
        else:
            assert json.loads(target.read_bytes())["unexpected"] == "foreign"
        target.write_bytes(before)
    assert install(installation)["state"] == "bundle_installed"


def test_subprocess_restart_exact_retry(installation):
    old, issued, store, target = installation
    receipt = install(installation)
    journal = store / "rotation-state/install.json"
    before = target.read_bytes(), journal.read_bytes(), pending(store).read_bytes()
    code = "import json,sys; from repeater.glass.rotation_state import install_renewal_candidate; c,r=json.load(sys.stdin); print(json.dumps(install_renewal_candidate(c,r,store_dir=sys.argv[1],credential_file=sys.argv[2])))"
    for caller in (old, json.loads(target.read_bytes()), old):
        child = subprocess.run(
            [sys.executable, "-c", code, str(store), str(target)],
            input=json.dumps([caller, issued]),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert child.returncode == 0, child.stderr
        assert json.loads(child.stdout) == receipt
    assert (target.read_bytes(), journal.read_bytes(), pending(store).read_bytes()) == before


@pytest.mark.parametrize("phase", ["journal", "credential"])
@pytest.mark.parametrize("fault", ["short_write", "flush"])
def test_stream_failure_preserves_old_bytes(installation, monkeypatch, phase, fault):
    _, _, store, target = installation
    before = snapshots(installation)
    real = os.fdopen
    stage_parent = store / "rotation-state" if phase == "journal" else target.parent

    class BrokenStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def write(self, data):
            return self.stream.write(data[:20] if fault == "short_write" else data)

        def flush(self):
            if fault == "flush":
                raise OSError("secret-flush-error")
            self.stream.flush()

    def broken(fd, mode):
        actual = os.readlink(f"/proc/self/fd/{fd}")
        stream = real(fd, mode)
        if mode == "wb" and actual.startswith(str(stage_parent) + "/.stage-"):
            return BrokenStream(stream)
        return stream

    with monkeypatch.context() as patch:
        patch.setattr(r.os, "fdopen", broken)
        with pytest.raises(e.EnrollmentError) as error:
            install(installation)
        assert "secret-flush-error" not in str(error.value)
    assert snapshots(installation) == before
    assert not any(p.name.startswith(".stage-") for p in stage_parent.iterdir())
    assert install(installation)["state"] == "bundle_installed"


def test_only_owned_stages_cleaned_on_collision(installation, monkeypatch):
    state = installation[2] / "rotation-state"
    foreign = state / (".stage-" + "a" * 32)
    foreign.write_bytes(b"foreign-stage")
    foreign.chmod(0o600)
    before = snapshots(installation)
    with monkeypatch.context() as patch:
        patch.setattr(r.secrets, "token_hex", lambda _: "a" * 32)
        with pytest.raises(e.EnrollmentError):
            install(installation)
    assert foreign.read_bytes() == b"foreign-stage"
    assert snapshots(installation) == before
    assert install(installation)["state"] == "bundle_installed"


def test_cleanup_failure_releases_all_descriptors(installation, monkeypatch):
    real_open, real_unlink = os.open, os.unlink
    opened = []

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def failed_sync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("secret-stage-failure")

    def failed_cleanup(name, **kwargs):
        if str(name).startswith(".stage-"):
            raise OSError("secret-cleanup-failure")
        return real_unlink(name, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(r.os, "open", tracked_open)
        patch.setattr(r.os, "unlink", failed_cleanup)
        patch.setattr(r, "_fsync", failed_sync)
        with pytest.raises(e.EnrollmentError) as error:
            install(installation)
        assert "secret-" not in str(error.value)
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)
    for stage in (installation[2] / "rotation-state").glob(".stage-*"):
        stage.unlink()
    assert install(installation)["state"] == "bundle_installed"


@pytest.mark.parametrize(
    "bad",
    [
        "caller",
        "current",
        "path",
        "response",
        "generation",
        "request",
        "backup_context",
        "backup_digest",
    ],
)
def test_existing_journal_foreign_retry_refused(installation, bad):
    old, response, store, target = installation
    install(installation)
    journal_path = store / "rotation-state/install.json"
    caller, issued, path = old, response, target
    if bad == "caller":
        caller = dict(old, extra="foreign")
    elif bad == "current":
        target.write_text(json.dumps(dict(old, extra="foreign")))
    elif bad == "path":
        path = store / "another.json"
        path.write_bytes(target.read_bytes())
        path.chmod(0o600)
    elif bad == "response":
        # Equivalent expiry spelling remains a different candidate JSON digest.
        issued = dict(response, expires_at=response["expires_at"].replace("+00:00", "Z"))
    elif bad in ("generation", "request"):
        state_path = pending(store)
        state = json.loads(state_path.read_bytes())
        state["generation_sha256" if bad == "generation" else "request_id"] = (
            "f" * 64 if bad == "generation" else "00000000-0000-4000-8000-000000000003"
        )
        state_path.write_text(json.dumps(state))
    else:
        journal = json.loads(journal_path.read_bytes())
        journal["previous_bundle"] = dict(old, base_url="https://foreign.example")
        if bad == "backup_context":
            journal["previous_sha256"] = r._bundle_digest(journal["previous_bundle"])
        journal_path.write_text(json.dumps(journal))
    before = snapshots(installation), journal_path.read_bytes()
    with pytest.raises(e.EnrollmentError):
        install(installation, credentials=caller, response=issued, path=path)
    assert (snapshots(installation), journal_path.read_bytes()) == before


def test_other_safe_parent_and_immutable_mqtt_untouched(installation):
    old, _, store, target = installation
    other = store / "other"
    other.mkdir(mode=0o700)
    path = other / target.name
    path.write_bytes(target.read_bytes())
    path.chmod(0o600)
    mqtt = store / "mqtt-credentials/old-fingerprint"
    mqtt.mkdir(parents=True, mode=0o700)
    key = mqtt / "client.key"
    key.write_bytes(b"immutable-existing-key")
    before = key.read_bytes(), target.read_bytes()
    assert install(installation, credentials=old, path=path)["state"] == "bundle_installed"
    assert (key.read_bytes(), target.read_bytes()) == before


def test_full_json_identity_not_python_boolean_equality(installation):
    old, _, _, target = installation
    caller = dict(old, extra=1)
    target.write_text(json.dumps(dict(old, extra=True)))
    before = snapshots(installation)
    with pytest.raises(e.EnrollmentError):
        install(installation, credentials=caller)
    assert snapshots(installation) == before


@pytest.mark.parametrize("bad", ["mode", "symlink", "fifo", "duplicate", "oversize"])
def test_existing_unsafe_journal_never_repaired(installation, bad):
    install(installation)
    journal = installation[2] / "rotation-state/install.json"
    if bad == "mode":
        journal.chmod(0o644)
    elif bad == "symlink":
        saved = journal.with_name("saved.json")
        journal.rename(saved)
        journal.symlink_to(saved)
    elif bad == "fifo":
        journal.unlink()
        os.mkfifo(journal, 0o600)
    elif bad == "duplicate":
        data = journal.read_text()
        journal.write_text(data[:-1] + ',"version":1}')
    else:
        journal.write_bytes(b" " * 131073)
    info = journal.lstat()
    metadata = info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size
    before = snapshots(installation)
    with pytest.raises(e.EnrollmentError):
        install(installation)
    assert snapshots(installation) == before
    info = journal.lstat()
    assert (info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size) == metadata


def test_abrupt_process_exit_after_replace_then_retry(installation):
    old, issued, store, target = installation
    code = (
        "import json,os,sys; from repeater.glass import rotation_state as r; "
        "c,response=json.load(sys.stdin); original=r._fsync; "
        "inode=os.stat(os.path.dirname(sys.argv[2])).st_ino; "
        "r._fsync=lambda fd: os._exit(23) if os.fstat(fd).st_ino==inode else original(fd); "
        "r.install_renewal_candidate(c,response,store_dir=sys.argv[1],credential_file=sys.argv[2])"
    )
    child = subprocess.run(
        [sys.executable, "-c", code, str(store), str(target)],
        input=json.dumps([old, issued]),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert child.returncode == 23, child.stderr
    assert json.loads(target.read_bytes())["fingerprint_sha256"] == issued["fingerprint_sha256"]
    journal = store / "rotation-state/install.json"
    before = snapshots(installation), journal.read_bytes()
    assert install(installation)["state"] == "bundle_installed"
    assert (snapshots(installation), journal.read_bytes()) == before


def test_inherited_acl_stripped_from_credential_stage(installation):
    import struct

    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perm, uid)
        for tag, perm, uid in [
            (1, 7, 0xFFFFFFFF),
            (2, 7, os.geteuid() + 1),
            (4, 0, 0xFFFFFFFF),
            (16, 7, 0xFFFFFFFF),
            (32, 0, 0xFFFFFFFF),
        ]
    )
    _, _, store, target = installation
    os.setxattr(target.parent, "system.posix_acl_default", acl)
    assert install(installation)["state"] == "bundle_installed"
    for path in (target, store / "rotation-state/install.json"):
        assert not any(name.startswith("system.posix_acl_") for name in os.listxattr(path))
