"""Offline pending CSR durability; no issuance, installation or activation."""

import hashlib
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from repeater.glass import enrollment as e
from repeater.glass import rotation_state as r
from tests.test_glass_enrollment import DEVICE, enroll_fixture  # noqa: F401


@pytest.fixture
def bundle(enroll_fixture):  # noqa: F811
    args, _options, _ = enroll_fixture
    e.enroll_device(**args)
    return e.load_credentials(args["credential_file"], base_url=args["base_url"], device_id=DEVICE)


def prepare(bundle, tmp_path):
    return r.prepare_rotation(bundle, store_dir=tmp_path)


def pending(tmp_path):
    return tmp_path / "rotation-state" / "pending.json"


def test_durable_public_only_new_key_reused(bundle, tmp_path):
    result = prepare(bundle, tmp_path)
    assert set(result) == {"device_id", "request_id", "csr_pem"}
    state = json.loads(pending(tmp_path).read_text())
    assert set(state) == {
        "version",
        "base_url",
        "device_id",
        "generation_sha256",
        "request_id",
        "private_key",
        "csr_pem",
    }
    assert (
        state["generation_sha256"]
        == hashlib.sha256(bundle["operational_token"].encode("ascii")).hexdigest()
    )
    assert state["private_key"] != bundle["private_key"]
    assert bundle["operational_token"] not in pending(tmp_path).read_text()
    assert bundle["client_cert"] not in pending(tmp_path).read_text()
    assert stat.S_IMODE(pending(tmp_path).stat().st_mode) == 0o600
    assert stat.S_IMODE(pending(tmp_path).parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((pending(tmp_path).parent / ".lock").stat().st_mode) == 0o600
    csr = x509.load_pem_x509_csr(result["csr_pem"].encode())
    assert csr.is_signature_valid and csr.public_key().key_size == 2048
    assert isinstance(csr.signature_hash_algorithm, hashes.SHA256)
    assert csr.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device:" + DEVICE)])
    before = pending(tmp_path).read_bytes()
    assert prepare(bundle, tmp_path) == result
    assert pending(tmp_path).read_bytes() == before


@pytest.mark.parametrize("bad", ["token", "device", "origin", "key", "expiry"])
def test_invalid_loaded_bundle_creates_no_state(bundle, tmp_path, bad):
    bundle = dict(bundle)
    field, value = {
        "token": ("operational_token", "secret-invalid"),
        "device": ("device_id", "bad"),
        "origin": ("base_url", "http://glass.example"),
        "key": ("private_key", "secret-invalid"),
        "expiry": ("expires_at", "2000-01-01T00:00:00Z"),
    }[bad]
    bundle[field] = value
    with pytest.raises(e.EnrollmentError) as error:
        prepare(bundle, tmp_path)
    assert "secret-invalid" not in str(error.value)
    assert not (tmp_path / "rotation-state").exists()


@pytest.mark.parametrize(
    "bad",
    [
        "extra",
        "bool",
        "version",
        "request",
        "request_type",
        "generation",
        "origin",
        "device",
        "key",
        "csr",
        "mismatch",
        "weak",
        "cn",
        "signature",
        "oversize",
        "duplicate",
    ],
)
def test_malformed_existing_state_never_overwritten(bundle, tmp_path, bad):
    prepare(bundle, tmp_path)
    path = pending(tmp_path)
    state = json.loads(path.read_text())
    if bad == "extra":
        state["token"] = "secret-invalid"
    elif bad == "bool":
        state["version"] = True
    elif bad == "version":
        state["version"] = 2
    elif bad == "request":
        state["request_id"] = "{" + state["request_id"] + "}"
    elif bad == "request_type":
        state["request_id"] = 1
    elif bad == "generation":
        state["generation_sha256"] = "0" * 64
    elif bad == "origin":
        state["base_url"] += "/other"
    elif bad == "device":
        state["device_id"] = "00000000-0000-4000-8000-000000000002"
    elif bad in ("key", "csr"):
        state["private_key" if bad == "key" else "csr_pem"] = "secret-invalid"
    elif bad in ("mismatch", "weak", "cn"):
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024 if bad == "weak" else 2048
        )
        state["private_key"] = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        if bad != "mismatch":
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, "wrong" if bad == "cn" else "device:" + DEVICE
                            )
                        ]
                    )
                )
                .sign(key, hashes.SHA256())
            )
            state["csr_pem"] = csr.public_bytes(serialization.Encoding.PEM).decode()
    elif bad == "signature":
        csr = x509.load_pem_x509_csr(state["csr_pem"].encode())
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        state["csr_pem"] = (
            x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM).decode()
        )
    raw = json.dumps(state)
    if bad == "oversize":
        raw = " " * 32769
    if bad == "duplicate":
        raw = raw[:-1] + ',"version":1}'
    path.write_text(raw)
    before = path.read_bytes()
    with pytest.raises(e.EnrollmentError) as error:
        prepare(bundle, tmp_path)
    assert "secret-invalid" not in str(error.value)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "target", ["rotation-state", "rotation-state/.lock", "rotation-state/pending.json"]
)
@pytest.mark.parametrize("bad", ["mode", "symlink", "fifo", "acl", "owner"])
def test_existing_unsafe_never_repaired(bundle, tmp_path, monkeypatch, target, bad):
    prepare(bundle, tmp_path)
    path = tmp_path / target
    if bad == "mode":
        path.chmod(0o755 if path.is_dir() else 0o644)
    elif bad == "symlink":
        moved = path.with_name(path.name + "-real")
        path.rename(moved)
        path.symlink_to(moved)
    elif bad == "fifo":
        if path.is_dir():
            pytest.skip("FIFO tested on fixed files")
        path.unlink()
        os.mkfifo(path, 0o600)
    elif bad == "acl":
        real = os.listxattr
        ino = path.stat().st_ino
        monkeypatch.setattr(
            r.os,
            "listxattr",
            lambda fd: (
                ["system.posix_acl_access"]
                if isinstance(fd, int) and os.fstat(fd).st_ino == ino
                else real(fd)
            ),
        )
    else:
        real = os.fstat
        ino = path.stat().st_ino

        def fake(fd):
            info = real(fd)
            if info.st_ino != ino:
                return info
            values = list(info)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)

        monkeypatch.setattr(r.os, "fstat", fake)
    before = path.lstat()
    with pytest.raises(e.EnrollmentError):
        prepare(bundle, tmp_path)
    assert path.lstat() == before


@pytest.mark.parametrize("bad", ["missing", "writable", "symlink", "traversal"])
def test_strict_provisioned_ancestry(bundle, tmp_path, bad):
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    if bad == "missing":
        store = store / "missing"
    elif bad == "writable":
        store.chmod(0o775)
    elif bad == "symlink":
        link = tmp_path / "link"
        link.symlink_to(store)
        store = link
    else:
        store = store / ".."
    with pytest.raises(e.EnrollmentError):
        r.prepare_rotation(bundle, store_dir=store)
    assert not (tmp_path / "rotation-state").exists()


@pytest.mark.parametrize("stage", ["write", "file_fsync", "replace", "dir_fsync", "readback"])
def test_io_failure_cleanup_and_published_retry(bundle, tmp_path, monkeypatch, stage):
    # Initialize directory/lock without publishing a CSR.
    root = tmp_path / "rotation-state"
    root.mkdir(mode=0o700)
    lock = root / ".lock"
    lock.touch(mode=0o600)
    original_read = r._read_pending
    original_fsync = r._fsync
    with monkeypatch.context() as patch:

        def fail(*args, **kwargs):
            raise OSError("secret-library-error")

        if stage == "write":

            def partial(fd, name, data):
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                os.write(target, data[:20])
                os.close(target)
                fail()

            patch.setattr(r, "_write_staged", partial)
        elif stage == "replace":
            patch.setattr(r, "_replace", fail)
        elif stage in ("file_fsync", "dir_fsync"):

            def sync(fd):
                info = os.fstat(fd)
                if stage == "dir_fsync" and info.st_ino == root.stat().st_ino:
                    fail()
                if stage == "file_fsync" and stat.S_ISREG(info.st_mode) and info.st_size > 0:
                    fail()
                original_fsync(fd)

            patch.setattr(r, "_fsync", sync)
        else:

            def read(fd, context):
                if pending(tmp_path).exists():
                    fail()
                return original_read(fd, context)

            patch.setattr(r, "_read_pending", read)
        with pytest.raises(e.EnrollmentError) as error:
            prepare(bundle, tmp_path)
        assert "secret-library-error" not in str(error.value)
    assert not list(root.glob(".stage-*"))
    published = pending(tmp_path).read_bytes() if pending(tmp_path).exists() else None
    result = prepare(bundle, tmp_path)
    if stage in ("dir_fsync", "readback"):
        assert published is not None and pending(tmp_path).read_bytes() == published
        assert result["request_id"] == json.loads(published)["request_id"]
    else:
        assert published is None


def test_generation_token_not_serial(bundle, tmp_path):
    result = prepare(bundle, tmp_path)
    changed = dict(bundle, operational_token="X" * 43)
    before = pending(tmp_path).read_bytes()
    with pytest.raises(e.EnrollmentError):
        prepare(changed, tmp_path)
    assert pending(tmp_path).read_bytes() == before
    assert prepare(bundle, tmp_path) == result


def test_actual_expired_certificate_rejected_before_state(enroll_fixture, tmp_path):  # noqa: F811
    args, options, _ = enroll_fixture
    e.enroll_device(**args)
    bundle = e.load_credentials(
        args["credential_file"], base_url=args["base_url"], device_id=DEVICE
    )
    key = serialization.load_pem_private_key(bundle["private_key"].encode(), password=None)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device:" + DEVICE)]))
        .sign(key, hashes.SHA256())
    )
    options["expired"] = True
    issued = e.post_verified_json(
        args["base_url"] + "/enroll",
        {"csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()},
    )
    bundle.update(issued)
    with pytest.raises(e.EnrollmentError):
        prepare(bundle, tmp_path)
    assert not (tmp_path / "rotation-state").exists()


def test_in_memory_generated_state_crypto_and_strict_scalars(bundle):
    context = r._context(bundle)
    state = r._new_pending(context)
    assert r._validate_pending(state, context) == state
    for field in state:
        changed = dict(state)
        changed[field] = True if field == "version" else 1
        with pytest.raises(e.EnrollmentError):
            r._validate_pending(changed, context)
    for field in context:
        changed = dict(state)
        changed[field] = "0" * 64 if field == "generation_sha256" else "wrong"
        with pytest.raises(e.EnrollmentError):
            r._validate_pending(changed, context)
    with pytest.raises(e.EnrollmentError):
        r._unique_pairs([("version", 1), ("version", 1)])


def test_private_staging_and_readback_without_ancestry_claim(bundle, tmp_path):
    # Exercise real file persistence in the designated scratch location even
    # when the host's ancestor permissions block the public entry point.
    context = r._context(bundle)
    state = r._new_pending(context)
    fd = os.open(tmp_path, r.m._DIR_FLAGS)
    try:
        r._write_staged(fd, ".stage-test", json.dumps(state).encode())
        r._replace(".stage-test", "pending.json", src_dir_fd=fd, dst_dir_fd=fd)
        r._fsync(fd)
        assert r._read_pending(fd, context) == state
        assert not os.listxattr(pending_file := tmp_path / "pending.json")
        assert stat.S_IMODE(pending_file.stat().st_mode) == 0o600
    finally:
        os.close(fd)


def test_fresh_process_concurrency_and_abrupt_exit(bundle, tmp_path):
    code = "import json,sys; from repeater.glass.rotation_state import prepare_rotation; print(json.dumps(prepare_rotation(json.loads(sys.stdin.read()),store_dir=sys.argv[1])))"
    children = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    results = []
    for child in children:
        out, err = child.communicate(json.dumps(bundle), timeout=30)
        assert child.returncode == 0, err
        results.append(json.loads(out))
    assert all(value == results[0] for value in results)
    before = pending(tmp_path).read_bytes()
    abrupt = "import os; " + code + "; os._exit(0)"
    exited = subprocess.run(
        [sys.executable, "-c", abrupt, str(tmp_path)],
        input=json.dumps(bundle),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert exited.returncode == 0, exited.stderr
    assert prepare(bundle, tmp_path) == results[0]
    assert pending(tmp_path).read_bytes() == before


def test_inherited_real_acl_stripped(bundle, tmp_path):
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
    os.setxattr(tmp_path, "system.posix_acl_default", acl)
    prepare(bundle, tmp_path)
    for path in (tmp_path / "rotation-state", tmp_path / "rotation-state/.lock", pending(tmp_path)):
        assert not any(name.startswith("system.posix_acl_") for name in os.listxattr(path))


def test_threads_and_process_restart_exact_reuse(bundle, tmp_path):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: prepare(bundle, tmp_path), range(16)))
    assert all(value == results[0] for value in results)
    code = "import json,sys; from repeater.glass.rotation_state import prepare_rotation; print(json.dumps(prepare_rotation(json.loads(sys.stdin.read()),store_dir=sys.argv[1])))"
    children = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    for child in children:
        out, err = child.communicate(json.dumps(bundle), timeout=30)
        assert child.returncode == 0, err
        assert json.loads(out) == results[0]
    child = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)],
        input=json.dumps(bundle),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == results[0]
