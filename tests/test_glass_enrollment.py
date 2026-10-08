"""Synthetic HTTPS enrollment; real CSR and certificate validation, no live network."""

import io
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from repeater.glass import enrollment as e

DEVICE = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
def enroll_fixture(tmp_path, monkeypatch):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic CA")])
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    options = {}
    captured = {}

    def post(url, payload, **kwargs):
        captured.update(payload)
        csr = x509.load_pem_x509_csr(payload["csr_pem"].encode())
        assert csr.is_signature_valid
        key = csr.public_key()
        if options.get("mismatch"):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        expiry = now + timedelta(
            days=-1 if options.get("expired") else options.get("lifetime_days", 7)
        )
        signing_key = ca_key
        if options.get("bad_signature"):
            signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cn = "device:" + (DEVICE if not options.get("wrong_identity") else "wrong")
        usage = (
            ExtendedKeyUsageOID.SERVER_AUTH
            if options.get("wrong_usage")
            else ExtendedKeyUsageOID.CLIENT_AUTH
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(name)
            .public_key(key)
            .serial_number(options.get("serial", 2))
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(expiry)
            .add_extension(
                x509.BasicConstraints(ca=options.get("is_ca", False), path_length=None), True
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier("urn:openhop:device:" + DEVICE)]
                ),
                False,
            )
            .sign(signing_key, hashes.SHA256())
        )
        result = {
            "device_id": DEVICE,
            "client_cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_cert": ca.public_bytes(serialization.Encoding.PEM).decode(),
            "cert_serial": format(options.get("serial", 2), "x"),
            "expires_at": expiry.isoformat(),
        }
        if options.get("bad_serial"):
            result["cert_serial"] = "3"
        if options.get("bad_expiry"):
            result["expires_at"] = (expiry + timedelta(seconds=1)).isoformat()
        if options.get("remote_key"):
            result["client_key"] = "forbidden"
        return result

    monkeypatch.setattr(e, "post_verified_json", post)
    args = {
        "base_url": "https://glass.example",
        "device_id": DEVICE,
        "node_name": "synthetic-node",
        "pubkey": "0x" + "ab" * 32,
        "enrollment_token": "E" * 43,
        "credential_file": tmp_path / "credentials.json",
    }
    return args, options, captured


def test_enroll_node_owned_key_atomic_private_bundle(enroll_fixture):
    args, _, captured = enroll_fixture
    config = e.enroll_device(**args)
    path = args["credential_file"]
    assert os.stat(path).st_mode & 0o777 == 0o600
    bundle = e.load_credentials(path, base_url=args["base_url"], device_id=DEVICE)
    assert bundle["operational_token"] == captured["operational_token"]
    assert len(captured["operational_token"]) == 43
    assert set(captured) == {
        "device_id",
        "node_name",
        "pubkey",
        "enrollment_token",
        "operational_token",
        "csr_pem",
    }
    assert "PRIVATE KEY" not in json.dumps(captured)
    assert "enrollment_token" not in path.read_text()
    assert config == {"device_id": DEVICE, "operational_credential_file": str(path)}


@pytest.mark.parametrize(
    "option",
    [
        "mismatch",
        "expired",
        "is_ca",
        "bad_serial",
        "bad_expiry",
        "remote_key",
        "bad_signature",
        "wrong_identity",
        "wrong_usage",
    ],
)
def test_invalid_certificate_never_stages(enroll_fixture, option):
    args, options, _ = enroll_fixture
    options[option] = True
    with pytest.raises(e.EnrollmentError):
        e.enroll_device(**args)
    assert not args["credential_file"].exists()


def test_failed_replace_preserves_old_credentials(enroll_fixture, monkeypatch):
    args, _, _ = enroll_fixture
    e.enroll_device(**args)
    old = args["credential_file"].read_bytes()

    def fail(*args):
        raise OSError("synthetic failure")

    monkeypatch.setattr(e.os, "replace", fail)
    with pytest.raises(e.EnrollmentError):
        e.enroll_device(**args)
    assert args["credential_file"].read_bytes() == old
    assert list(args["credential_file"].parent.iterdir()) == [args["credential_file"]]


def test_permissions_and_origin_fail_closed(enroll_fixture):
    args, _, _ = enroll_fixture
    e.enroll_device(**args)
    with pytest.raises(e.EnrollmentError):
        e.load_credentials(
            args["credential_file"], base_url="https://other.example", device_id=DEVICE
        )
    os.chmod(args["credential_file"], 0o644)
    with pytest.raises(e.EnrollmentError):
        e.load_credentials(args["credential_file"], base_url=args["base_url"], device_id=DEVICE)


@pytest.mark.parametrize(
    "url",
    ["http://glass.example", "https://user:pass@glass.example", "https://glass.example/?token=x"],
)
def test_refuse_unsafe_endpoint(url):
    with pytest.raises(e.EnrollmentError):
        e.validate_https_url(url)


def test_transport_bounded_verified_no_redirect(monkeypatch):
    class Opener:
        def open(self, req, timeout):
            assert timeout == 10
            return io.BytesIO(b"{}")

    monkeypatch.setattr(e.request, "build_opener", lambda *handlers: Opener())
    assert e.post_verified_json("https://glass.example/enroll", {}, timeout=10) == {}
    with pytest.raises(e.EnrollmentError):
        e.post_verified_json("https://glass.example/enroll", {"x": "a" * 16384})

    class LargeOpener:
        def open(self, req, timeout):
            return io.BytesIO(b"a" * 65537)

    monkeypatch.setattr(e.request, "build_opener", lambda *handlers: LargeOpener())
    with pytest.raises(e.EnrollmentError):
        e.post_verified_json("https://glass.example/enroll", {})


@pytest.mark.parametrize("stage", ["fsync", "dump"])
def test_partial_write_never_publishes(enroll_fixture, monkeypatch, stage):
    args, _, _ = enroll_fixture
    e.enroll_device(**args)
    old = args["credential_file"].read_bytes()

    def fail(*args, **kwargs):
        raise OSError("synthetic partial-write failure")

    if stage == "fsync":
        monkeypatch.setattr(e.os, "fsync", fail)
    else:
        monkeypatch.setattr(e.json, "dump", fail)
    with pytest.raises(e.EnrollmentError):
        e.enroll_device(**args)
    assert args["credential_file"].read_bytes() == old
    assert len(list(args["credential_file"].parent.iterdir())) == 1


def _handler_class():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "repeater/data_acquisition/glass_handler.py"
    spec = importlib.util.spec_from_file_location("enrollment_glass_handler", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.GlassHandler


def test_enrolled_handler_binds_v1_token_no_v2(enroll_fixture, monkeypatch):
    args, _, _ = enroll_fixture
    settings = e.enroll_device(**args)
    handler = _handler_class()(
        {
            "glass": dict(
                settings,
                base_url=args["base_url"],
                verify_tls=True,
                cert_store_dir=str(args["credential_file"].parent),
            )
        }
    )
    seen = {}

    def post(url, payload, **kwargs):
        seen.update(payload)
        assert kwargs["token"] == handler.api_token
        assert url == "https://glass.example/inform"
        return {"type": "noop"}

    monkeypatch.setattr(e, "post_verified_json", post)
    assert handler._post_inform_sync({"version": 1, "pubkey": args["pubkey"]}) == {"type": "noop"}
    assert seen["device_id"] == DEVICE and seen["version"] == 1
    assert "operational_token" not in seen
    before = args["credential_file"].read_bytes()
    ok, _ = handler._apply_cert_renewal(
        {"client_cert": "foreign", "client_key": "foreign", "ca_cert": "foreign"}
    )
    assert not ok and args["credential_file"].read_bytes() == before
    with pytest.raises(ValueError):
        handler._post_inform_sync({"version": 2})
    os.chmod(args["credential_file"], 0o644)
    with pytest.raises(e.EnrollmentError):
        handler._post_inform_sync({"version": 1, "pubkey": args["pubkey"]})


@pytest.mark.parametrize(
    "url,verify", [("http://glass.example", True), ("https://glass.example", False)]
)
def test_handler_refuses_insecure_operational_config(enroll_fixture, url, verify):
    args, _, _ = enroll_fixture
    settings = e.enroll_device(**args)
    with pytest.raises(ValueError):
        _handler_class()({"glass": dict(settings, base_url=url, verify_tls=verify)})
