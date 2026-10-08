"""Verified renewal orchestration; HTTPS is mocked, not broker proof."""

# ruff: noqa: F811 - imported pytest fixtures are injected by name
import importlib
import json
import os

import pytest

from repeater.glass import enrollment as e
from repeater.glass import rotation_transport as t
from tests.test_glass_rotation_state import (  # noqa: F401
    bundle,
    enroll_fixture,
    pending,
    renewal_response,
)


def renew(args, store, **kwargs):
    return t.renew_credentials(
        credential_file=args["credential_file"],
        base_url=args["base_url"],
        device_id=args["device_id"],
        store_dir=store,
        **kwargs,
    )


def test_exact_transport_and_installed_retry(bundle, enroll_fixture, tmp_path, monkeypatch):
    args, _, _ = enroll_fixture
    issued = renewal_response(bundle, tmp_path)
    saved = pending(tmp_path).read_bytes()
    calls = []

    def post(url, payload, **options):
        assert pending(tmp_path).read_bytes() == saved
        state = json.loads(saved)
        assert payload == {k: state[k] for k in ("device_id", "request_id", "csr_pem")}
        assert url == args["base_url"] + "/device/certificates/renew"
        assert options == {
            "token": bundle["operational_token"],
            "timeout": 17,
            "https_ca_file": "configured-https-ca.pem",
            "max_request": 16384,
        }
        calls.append(payload)
        return issued

    monkeypatch.setattr(t, "post_verified_json", post)
    receipt = renew(args, tmp_path, timeout=17, https_ca_file="configured-https-ca.pem")
    assert receipt["state"] == "bundle_installed"
    installed = args["credential_file"].read_bytes()
    assert renew(args, tmp_path) == receipt
    assert len(calls) == 1
    assert args["credential_file"].read_bytes() == installed
    assert pending(tmp_path).read_bytes() == saved


def test_lost_response_reuses_exact_request(bundle, enroll_fixture, tmp_path, monkeypatch):
    args, _, _ = enroll_fixture
    calls = []

    def lost(url, payload, **options):
        assert pending(tmp_path).exists()
        calls.append((payload, pending(tmp_path).read_bytes()))
        raise RuntimeError(bundle["operational_token"] + bundle["private_key"])

    monkeypatch.setattr(t, "post_verified_json", lost)
    old = args["credential_file"].read_bytes()
    for _ in range(2):
        with pytest.raises(e.EnrollmentError) as error:
            renew(args, tmp_path)
        assert bundle["operational_token"] not in str(error.value)
        assert error.value.__suppress_context__
    assert calls[0] == calls[1]
    assert args["credential_file"].read_bytes() == old


@pytest.mark.parametrize("field", ["client_cert", "ca_cert", "request_id", "expires_at"])
def test_bad_response_preserves_old(bundle, enroll_fixture, tmp_path, monkeypatch, field):
    args, _, _ = enroll_fixture
    issued = renewal_response(bundle, tmp_path)
    old = args["credential_file"].read_bytes(), pending(tmp_path).read_bytes()
    monkeypatch.setattr(
        t, "post_verified_json", lambda *a, **k: dict(issued, **{field: "secret-bad"})
    )
    with pytest.raises(e.EnrollmentError):
        renew(args, tmp_path)
    assert (args["credential_file"].read_bytes(), pending(tmp_path).read_bytes()) == old


def test_malformed_current_precedes_http(enroll_fixture, tmp_path, monkeypatch):
    args, _, _ = enroll_fixture
    args["credential_file"].write_text("{}")
    monkeypatch.setattr(t, "post_verified_json", lambda *a, **k: pytest.fail("HTTP called"))
    with pytest.raises(e.EnrollmentError):
        renew(args, tmp_path)
    assert not (tmp_path / "rotation-state").exists()


def test_probe_read_only_absent_and_present(bundle, tmp_path):
    assert not t.rotation_pending(tmp_path)
    assert not (tmp_path / "rotation-state").exists()
    renewal_response(bundle, tmp_path)
    before = {p.name: p.read_bytes() for p in (tmp_path / "rotation-state").iterdir()}
    assert t.rotation_pending(tmp_path)
    assert {p.name: p.read_bytes() for p in (tmp_path / "rotation-state").iterdir()} == before


@pytest.mark.parametrize(
    "bad", ["fifo", "symlink", "mode", "duplicate", "array", "oversize", "missing-lock"]
)
def test_probe_rejects_unsafe_without_repair(bundle, tmp_path, bad):
    renewal_response(bundle, tmp_path)
    path = pending(tmp_path)
    if bad in {"fifo", "symlink"}:
        path.unlink()
        if bad == "fifo":
            os.mkfifo(path, 0o600)
        else:
            path.symlink_to(tmp_path / "nonexistent")
    elif bad == "mode":
        path.chmod(0o644)
    elif bad == "missing-lock":
        (path.parent / ".lock").unlink()
    else:
        path.write_text({"duplicate": '{"x":1,"x":2}', "array": "[]", "oversize": "x" * 32769}[bad])
    before = path.lstat()
    with pytest.raises(e.EnrollmentError):
        t.rotation_pending(tmp_path)
    after = path.lstat()
    assert (after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns) == (
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    )


@pytest.mark.parametrize("fault", ["wrong-key", "changed-ca", "partial-write"])
def test_crypto_and_staging_failures_preserve_current(
    bundle, enroll_fixture, tmp_path, monkeypatch, fault
):
    from repeater.glass import rotation_state as r

    args, options, _ = enroll_fixture
    issued = renewal_response(bundle, tmp_path)
    before = args["credential_file"].read_bytes(), pending(tmp_path).read_bytes()
    if fault == "wrong-key":
        options["mismatch"] = True
        issued = renewal_response(bundle, tmp_path)
    elif fault == "changed-ca":
        issued = dict(issued, ca_cert=issued["client_cert"])
    else:

        def partial(directory, name, data, **kwargs):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            try:
                if kwargs.get("on_create"):
                    kwargs["on_create"]()
                os.write(fd, data[:24])
            finally:
                os.close(fd)
            raise OSError("secret-partial-write")

        monkeypatch.setattr(r, "_write_staged", partial)
    monkeypatch.setattr(t, "post_verified_json", lambda *a, **k: issued)
    with pytest.raises(e.EnrollmentError):
        renew(args, tmp_path)
    assert (args["credential_file"].read_bytes(), pending(tmp_path).read_bytes()) == before


def test_postreplace_uncertainty_resolves_without_http(
    bundle, enroll_fixture, tmp_path, monkeypatch
):
    from repeater.glass import rotation_state as r

    args, _, _ = enroll_fixture
    issued = renewal_response(bundle, tmp_path)
    monkeypatch.setattr(t, "post_verified_json", lambda *a, **k: issued)
    original = r._fsync

    def fail_after_replace(fd):
        current = json.loads(args["credential_file"].read_bytes())
        if current.get("rotation_request_id") == issued["request_id"]:
            raise OSError("secret-postreplace")
        original(fd)

    monkeypatch.setattr(r, "_fsync", fail_after_replace)
    with pytest.raises(e.EnrollmentError):
        renew(args, tmp_path)
    installed = args["credential_file"].read_bytes()
    monkeypatch.setattr(r, "_fsync", original)
    monkeypatch.setattr(t, "post_verified_json", lambda *a, **k: pytest.fail("reissue"))
    assert renew(args, tmp_path)["state"] == "bundle_installed"
    assert args["credential_file"].read_bytes() == installed


def test_transport_api_exists():
    module = importlib.import_module("repeater.glass.rotation_transport")
    assert callable(module.renew_credentials)
    assert callable(module.rotation_pending)
