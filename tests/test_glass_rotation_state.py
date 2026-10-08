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

            def partial(fd, name, data, *, on_create=None):
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                if on_create is not None:
                    on_create()
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


# c2 remains offline: the fixture signs the public CSR without any transport.
def renewal_response(bundle, tmp_path):
    request = prepare(bundle, tmp_path)
    response = e.post_verified_json(bundle["base_url"] + "/renew", request)
    leaf = x509.load_pem_x509_certificate(response["client_cert"].encode("ascii"))
    return dict(
        response,
        request_id=request["request_id"],
        fingerprint_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
        state="issued",
    )


def test_renewal_candidate_api_exists():
    assert callable(getattr(r, "validate_renewal_candidate", None))


def test_renewal_candidate_preserves_inputs_and_files(bundle, enroll_fixture, tmp_path):  # noqa: F811
    args, _, _ = enroll_fixture
    response = renewal_response(bundle, tmp_path)
    old_bundle, old_response = dict(bundle), dict(response)
    credential_bytes = args["credential_file"].read_bytes()
    pending_bytes = pending(tmp_path).read_bytes()
    state = json.loads(pending_bytes)
    # Arbitrary caller fields must not flow into the explicitly built candidate.
    credentials = dict(bundle, ignored="not-part-of-candidate")
    for _ in range(2):
        candidate = r.validate_renewal_candidate(credentials, response, store_dir=tmp_path)
        assert candidate == {
            **{
                field: bundle[field]
                for field in ("base_url", "device_id", "pubkey", "operational_token")
            },
            **{
                field: response[field]
                for field in (
                    "client_cert",
                    "ca_cert",
                    "cert_serial",
                    "expires_at",
                    "fingerprint_sha256",
                )
            },
            "private_key": state["private_key"],
            "rotation_request_id": state["request_id"],
        }
        assert candidate["private_key"] != bundle["private_key"]
        e._validate_certificate(candidate)
    assert bundle == old_bundle and response == old_response
    assert credentials == dict(old_bundle, ignored="not-part-of-candidate")
    assert pending(tmp_path).read_bytes() == pending_bytes
    assert args["credential_file"].read_bytes() == credential_bytes
    assert {p.name for p in pending(tmp_path).parent.iterdir()} == {".lock", "pending.json"}


@pytest.mark.parametrize(
    "field",
    [
        "device_id",
        "request_id",
        "client_cert",
        "ca_cert",
        "cert_serial",
        "expires_at",
        "fingerprint_sha256",
        "state",
    ],
)
@pytest.mark.parametrize("value", [None, True, 1, [], {}])
def test_renewal_candidate_strict_response_types(bundle, tmp_path, field, value):
    response = renewal_response(bundle, tmp_path)
    before = pending(tmp_path).read_bytes()
    changed = dict(response, **{field: value})
    with pytest.raises(e.EnrollmentError):
        r.validate_renewal_candidate(bundle, changed, store_dir=tmp_path)
    assert changed[field] == value
    assert pending(tmp_path).read_bytes() == before
    assert r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)


@pytest.mark.parametrize(
    "bad",
    [
        "extra",
        "missing",
        "not_dict",
        "stale",
        "device",
        "state",
        "zero_serial",
        "upper_serial",
        "long_serial",
        "serial",
        "fingerprint",
        "upper_fingerprint",
        "short_fingerprint",
        "expiry",
        "naive_expiry",
        "long_expiry",
        "empty_expiry",
        "long_leaf",
        "long_ca",
        "leaf_suffix",
        "ca_suffix",
        "leaf_chain",
        "ca_chain",
        "nonascii",
        "changed_ca",
        "old_leaf",
    ],
)
def test_renewal_candidate_response_rejection_no_writes(bundle, tmp_path, bad):
    response = renewal_response(bundle, tmp_path)
    changed = dict(response)
    if bad == "extra":
        changed["private_key"] = "secret-invalid"
    elif bad == "missing":
        del changed["state"]
    elif bad == "not_dict":
        changed = []
    elif bad in ("leaf_suffix", "ca_suffix", "leaf_chain", "ca_chain", "long_leaf", "long_ca"):
        field = "client_cert" if "leaf" in bad else "ca_cert"
        changed[field] = (
            "x" * 14001
            if bad.startswith("long")
            else changed[field] + (changed[field] if bad.endswith("chain") else "secret-invalid")
        )
    elif bad == "changed_ca":
        # A canonical, independently signed CA must still fail the exact DER pin.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        original = x509.load_pem_x509_certificate(response["ca_cert"].encode())
        changed["ca_cert"] = (
            x509.CertificateBuilder()
            .subject_name(original.subject)
            .issuer_name(original.issuer)
            .public_key(key.public_key())
            .serial_number(3)
            .not_valid_before(original.not_valid_before_utc)
            .not_valid_after(original.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )
    elif bad == "old_leaf":
        changed["client_cert"] = bundle["client_cert"]
        changed["fingerprint_sha256"] = (
            x509.load_pem_x509_certificate(bundle["client_cert"].encode())
            .fingerprint(hashes.SHA256())
            .hex()
        )
    else:
        field, value = {
            "stale": ("request_id", "00000000-0000-4000-8000-000000000002"),
            "device": ("device_id", "00000000-0000-4000-8000-000000000002"),
            "state": ("state", "node_reported"),
            "zero_serial": ("cert_serial", "0"),
            "upper_serial": ("cert_serial", "A"),
            "long_serial": ("cert_serial", "a" * 41),
            "serial": ("cert_serial", "3"),
            "fingerprint": ("fingerprint_sha256", "0" * 64),
            "upper_fingerprint": ("fingerprint_sha256", "A" * 64),
            "short_fingerprint": ("fingerprint_sha256", "a" * 63),
            "expiry": ("expires_at", "2000-01-01T00:00:00Z"),
            "naive_expiry": ("expires_at", response["expires_at"].split("+")[0]),
            "long_expiry": ("expires_at", "x" * 65),
            "empty_expiry": ("expires_at", ""),
            "nonascii": ("client_cert", "\u2603"),
        }[bad]
        changed[field] = value
    before = pending(tmp_path).read_bytes()
    with pytest.raises(e.EnrollmentError) as error:
        r.validate_renewal_candidate(bundle, changed, store_dir=tmp_path)
    assert "secret-invalid" not in str(error.value)
    assert pending(tmp_path).read_bytes() == before
    assert r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)


@pytest.mark.parametrize(
    "option",
    [
        "mismatch",
        "expired",
        "is_ca",
        "bad_signature",
        "wrong_identity",
        "wrong_usage",
        "bad_serial",
        "bad_expiry",
    ],
)
def test_renewal_candidate_issued_leaf_validation(bundle, enroll_fixture, tmp_path, option):  # noqa: F811
    _, options, _ = enroll_fixture
    good = renewal_response(bundle, tmp_path)
    before = pending(tmp_path).read_bytes()
    options[option] = True
    response = renewal_response(bundle, tmp_path)
    with pytest.raises(e.EnrollmentError):
        r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
    assert pending(tmp_path).read_bytes() == before
    assert r.validate_renewal_candidate(bundle, good, store_dir=tmp_path)


@pytest.mark.parametrize(
    "target", ["rotation-state", "rotation-state/.lock", "rotation-state/pending.json"]
)
def test_renewal_candidate_missing_state_never_created(bundle, tmp_path, target):
    response = renewal_response(bundle, tmp_path)
    path = tmp_path / target
    if path.is_dir():
        for child in path.iterdir():
            child.unlink()
        path.rmdir()
    else:
        path.unlink()
    remaining = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    with pytest.raises(e.EnrollmentError):
        r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
    assert not path.exists()
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == remaining


@pytest.mark.parametrize(
    "target", ["rotation-state", "rotation-state/.lock", "rotation-state/pending.json"]
)
@pytest.mark.parametrize("bad", ["mode", "symlink", "fifo", "acl", "owner"])
def test_renewal_candidate_unsafe_state(bundle, tmp_path, monkeypatch, target, bad):
    response = renewal_response(bundle, tmp_path)
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
        real, ino = os.listxattr, path.stat().st_ino
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
        real, ino = os.fstat, path.stat().st_ino

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
        r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
    assert path.lstat() == before


@pytest.mark.parametrize("bad", ["partial", "generation", "csr", "key"])
def test_renewal_candidate_invalid_pending_unchanged(bundle, tmp_path, bad):
    response = renewal_response(bundle, tmp_path)
    state = json.loads(pending(tmp_path).read_text())
    if bad != "partial":
        state[{"generation": "generation_sha256", "csr": "csr_pem", "key": "private_key"}[bad]] = (
            "secret-invalid"
        )
    raw = b'{"version":' if bad == "partial" else json.dumps(state).encode()
    pending(tmp_path).write_bytes(raw)
    with pytest.raises(e.EnrollmentError) as error:
        r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
    assert "secret-invalid" not in str(error.value)
    assert pending(tmp_path).read_bytes() == raw


@pytest.mark.parametrize("bad", ["missing", "writable", "symlink", "traversal"])
def test_renewal_candidate_strict_ancestry(bundle, tmp_path, bad):
    response = renewal_response(bundle, tmp_path)
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
    before = pending(tmp_path).read_bytes()
    with pytest.raises(e.EnrollmentError):
        r.validate_renewal_candidate(bundle, response, store_dir=store)
    assert pending(tmp_path).read_bytes() == before
    assert not (tmp_path / "store" / "rotation-state").exists()


@pytest.mark.parametrize("offset,accepted", [(-1, True), (0, False), (1, False)])
def test_renewal_candidate_leaf_expiry_boundary(bundle, tmp_path, monkeypatch, offset, accepted):
    from datetime import datetime, timedelta

    response = renewal_response(bundle, tmp_path)
    leaf = x509.load_pem_x509_certificate(response["client_cert"].encode())
    real_read = r._read_pending

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return leaf.not_valid_after_utc + timedelta(seconds=offset)

    def read(fd, context):
        state = real_read(fd, context)
        # Current context was checked against real time, then exercise the
        # candidate's notAfter exclusive boundary with a deterministic clock.
        monkeypatch.setattr(e, "datetime", Clock)
        return state

    monkeypatch.setattr(r, "_read_pending", read)
    before = pending(tmp_path).read_bytes()
    if accepted:
        assert r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
    else:
        with pytest.raises(e.EnrollmentError):
            r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
    assert pending(tmp_path).read_bytes() == before


@pytest.mark.parametrize("style", ["z", "offset"])
def test_renewal_candidate_equivalent_expiry_instants(bundle, tmp_path, style):
    from datetime import datetime, timedelta, timezone

    response = renewal_response(bundle, tmp_path)
    expiry = datetime.fromisoformat(response["expires_at"])
    response["expires_at"] = (
        expiry.isoformat().replace("+00:00", "Z")
        if style == "z"
        else expiry.astimezone(timezone(timedelta(hours=5))).isoformat()
    )
    assert (
        r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)["expires_at"]
        == response["expires_at"]
    )


def test_renewal_response_total_json_bound_without_ancestry():
    # ASCII control characters fit the scalar bound but exceed the JSON byte
    # budget when escaped. This tests the total bound before any PEM parser.
    response = {
        "device_id": DEVICE,
        "request_id": DEVICE,
        "client_cert": "\x00" * 14000,
        "ca_cert": "\x00" * 14000,
        "cert_serial": "1",
        "expires_at": "2030-01-01T00:00:00Z",
        "fingerprint_sha256": "a" * 64,
        "state": "issued",
    }
    with pytest.raises(e.EnrollmentError, match="too large"):
        r._renewal_response(response)


def test_renewal_response_and_single_pem_without_ancestry(bundle):
    response = {
        field: bundle[field]
        for field in ("device_id", "client_cert", "ca_cert", "cert_serial", "expires_at")
    }
    response.update(request_id=DEVICE, fingerprint_sha256="a" * 64, state="issued")
    assert r._renewal_response(response) == response
    for field in ("client_cert", "ca_cert"):
        certificate = r._single_certificate(response[field])
        assert certificate.public_bytes(serialization.Encoding.PEM).decode() == response[field]
        for changed in (
            "prefix" + response[field],
            response[field] + "suffix",
            response[field] * 2,
        ):
            with pytest.raises(ValueError):
                r._single_certificate(changed)
    # Scalar upper bounds pass this syntactic helper; cryptographic validation
    # is deliberately a separate subsequent gate in the public API.
    expiry = response["expires_at"].replace("+00:00", "." + "0" * 38 + "+00:00")
    assert len(expiry) == 64
    bounded = dict(
        response,
        client_cert="A" * 14000,
        ca_cert="A" * 14000,
        cert_serial="a" * 40,
        expires_at=expiry,
    )
    assert r._renewal_response(bounded) == bounded


@pytest.mark.parametrize("bad", [None, [], {}, "expiry", "token", "key"])
def test_renewal_candidate_invalid_current_before_files(bundle, tmp_path, monkeypatch, bad):
    credentials = bad if bad is None or isinstance(bad, (list, dict)) else dict(bundle)
    if isinstance(bad, str):
        field, value = {
            "expiry": ("expires_at", "2000-01-01T00:00:00Z"),
            "token": ("operational_token", "secret-invalid"),
            "key": ("private_key", "secret-invalid"),
        }[bad]
        credentials[field] = value
    touched = []

    def forbidden(*args, **kwargs):
        touched.append(True)
        raise AssertionError("unexpected filesystem operation")

    monkeypatch.setattr(r.m, "_open_directory", forbidden)
    with pytest.raises(e.EnrollmentError) as error:
        r.validate_renewal_candidate(credentials, {}, store_dir=tmp_path)
    assert "secret-invalid" not in str(error.value)
    assert not touched
    assert not (tmp_path / "rotation-state").exists()


def test_renewal_candidate_no_writes_and_descriptor_cleanup(bundle, tmp_path, monkeypatch):
    import fcntl

    response = renewal_response(bundle, tmp_path)
    real_open, real_read = os.open, r._read_pending
    opened = []

    def tracked(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def forbidden(*args, **kwargs):
        raise AssertionError("secret-invalid-write")

    monkeypatch.setattr(r.os, "open", tracked)
    for name in ("_new_pending", "_write_staged", "_fsync", "_replace"):
        monkeypatch.setattr(r, name, forbidden)
    monkeypatch.setattr(r.m, "_strip_acls", forbidden)
    for fail in (False, True, False):
        opened.clear()
        monkeypatch.setattr(r, "_read_pending", forbidden if fail else real_read)
        if fail:
            with pytest.raises(e.EnrollmentError) as error:
                r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
            assert "secret-invalid" not in str(error.value)
        else:
            assert r.validate_renewal_candidate(bundle, response, store_dir=tmp_path)
        for fd in set(opened):
            with pytest.raises(OSError):
                os.fstat(fd)
        fd = real_open(pending(tmp_path).parent / ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
