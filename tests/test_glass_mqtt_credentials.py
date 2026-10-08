"""Real certificate validation and local atomic storage; no broker/network."""

import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from repeater.glass import enrollment as e
from repeater.glass import mqtt_credentials as m
from tests.test_glass_enrollment import DEVICE, _handler_class, enroll_fixture  # noqa: F401


@pytest.fixture
def enrolled(enroll_fixture):  # noqa: F811 - imported pytest fixture
    args, options, _captured = enroll_fixture
    settings = e.enroll_device(**args)
    return args, settings, options


def materialize(args):
    return m.materialize_credentials(
        args["credential_file"],
        base_url=args["base_url"],
        device_id=DEVICE,
        store_dir=args["credential_file"].parent,
    )


def test_complete_private_immutable_materialization(enrolled):
    args, _, _ = enrolled
    result = materialize(args)
    bundle = e.load_credentials(
        args["credential_file"], base_url=args["base_url"], device_id=DEVICE
    )
    directory = Path(result.client_cert_path).parent
    assert directory.name == result.fingerprint
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(directory.parent.stat().st_mode) == 0o700
    for field, name in [
        ("ca_cert", "ca_cert_path"),
        ("client_cert", "client_cert_path"),
        ("private_key", "client_key_path"),
    ]:
        path = Path(getattr(result, name))
        assert path.read_text() == bundle[field]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert result.expires_at == bundle["expires_at"]
    assert result.cert_serial == bundle["cert_serial"]
    assert materialize(args) == result
    assert len(list(directory.parent.iterdir())) == 1


@pytest.mark.parametrize("bad", ["key", "expiry", "mode", "symlink"])
def test_invalid_bundle_preserves_last_good(enrolled, bad):
    args, _, _ = enrolled
    good = materialize(args)
    path = args["credential_file"]
    bundle = json.loads(path.read_text())
    if bad == "key":
        bundle["private_key"] = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        e._save_bundle(path, bundle)
    elif bad == "expiry":
        bundle["expires_at"] = "2000-01-01T00:00:00Z"
        e._save_bundle(path, bundle)
    elif bad == "mode":
        path.chmod(0o644)
    else:
        path.rename(path.with_suffix(".real"))
        path.symlink_to(path.with_suffix(".real"))
    with pytest.raises(e.EnrollmentError):
        materialize(args)
    assert Path(good.client_cert_path).read_text() == bundle["client_cert"]
    assert len(list(Path(good.client_cert_path).parent.parent.iterdir())) == 1


@pytest.mark.parametrize("stage", ["write", "fsync", "rename"])
def test_stage_failure_preserves_previous_bundle(enrolled, monkeypatch, stage):
    args, _, _ = enrolled
    previous = materialize(args)
    e.enroll_device(**args)  # new node-owned key and issued leaf

    def fail(*values, **kwargs):
        if stage == "write":
            fd, name, value = values
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
            try:
                os.write(target, value.encode()[:32])
            finally:
                os.close(target)
        raise OSError("synthetic partial storage failure")

    monkeypatch.setattr(
        m,
        "_write_private" if stage == "write" else "_fsync" if stage == "fsync" else "_rename",
        fail,
    )
    with pytest.raises(e.EnrollmentError):
        materialize(args)
    assert Path(previous.client_key_path).exists()
    assert [p.name for p in Path(previous.client_key_path).parent.parent.iterdir()] == [
        previous.fingerprint
    ]


@pytest.mark.parametrize(
    "bad", ["directory_mode", "file_mode", "file_symlink", "root_symlink", "acl"]
)
def test_existing_material_is_never_trusted_blindly(enrolled, monkeypatch, bad):
    args, _, _ = enrolled
    result = materialize(args)
    directory = Path(result.client_key_path).parent
    if bad == "directory_mode":
        directory.chmod(0o755)
    elif bad == "file_mode":
        Path(result.client_key_path).chmod(0o644)
    elif bad == "file_symlink":
        Path(result.client_key_path).unlink()
        Path(result.client_key_path).symlink_to(args["credential_file"])
    elif bad == "root_symlink":
        root = directory.parent
        root.rename(root.with_name("moved"))
        root.symlink_to(root.with_name("moved"), target_is_directory=True)
    else:
        original = m.os.listxattr
        monkeypatch.setattr(
            m.os,
            "listxattr",
            lambda fd: (
                ["system.posix_acl_access"] if stat.S_ISDIR(os.fstat(fd).st_mode) else original(fd)
            ),
        )
    with pytest.raises(e.EnrollmentError):
        materialize(args)


def handler_for(args, settings, managed):
    (args["credential_file"].parent / "managed.json").write_text(json.dumps(managed))
    return _handler_class()(
        {
            "repeater": {"node_name": "display name"},
            "glass": dict(
                settings,
                enabled=True,
                base_url=args["base_url"],
                verify_tls=True,
                cert_store_dir=str(args["credential_file"].parent),
                ca_cert_path="/provisioned/https-roots.pem",
            ),
        }
    )


@pytest.mark.parametrize("record", ["packet", "advert", "noise_floor"])
def test_enrolled_topic_and_v2_envelope(enrolled, record):
    from unittest.mock import Mock

    args, settings, _ = enrolled
    handler = handler_for(args, settings, {"mqtt_enabled": True, "mqtt_tls_enabled": True})
    handler._mqtt_client = Mock()
    handler._mqtt_ready = True
    handler.publish_telemetry(record, {"timestamp": "2026-01-01T00:00:00Z"})
    topic, message = handler._mqtt_client.publish.call_args.args
    assert topic == f"glass/device:{DEVICE}/" + (
        record if record in ("packet", "advert") else "event/" + record
    )
    envelope = json.loads(message)
    assert envelope["version"] == 2 and envelope["device_id"] == DEVICE
    assert envelope["topic"] == topic and envelope["node_name"] == "display name"
    handler.config["repeater"]["node_name"] = "renamed"
    assert handler._mqtt_topic_for_record(node_name="renamed", record_type=record) == topic
    assert handler.ca_cert_path == "/provisioned/https-roots.pem"


@pytest.mark.parametrize(
    "managed",
    [
        {"mqtt_tls_enabled": False},
        {"mqtt_base_topic": "glass/other"},
        {"mqtt_username": "override"},
        {"mqtt_password": "override"},
    ],
)
def test_enrolled_mqtt_rejects_unsafe_overrides(enrolled, managed):
    args, settings, _ = enrolled
    with pytest.raises(ValueError):
        handler_for(
            args, settings, dict({"mqtt_enabled": True, "mqtt_tls_enabled": True}, **managed)
        )


def test_real_leaf_renewal_reinitializes_paho_and_waits_for_callback(enrolled, monkeypatch):
    from unittest.mock import Mock

    args, settings, _ = enrolled
    handler = handler_for(args, settings, {"mqtt_enabled": True, "mqtt_tls_enabled": True})
    namespace = handler._init_mqtt_publisher.__globals__
    clients = [Mock(), Mock()]
    mqtt = Mock()
    mqtt.Client.side_effect = clients
    monkeypatch.setitem(namespace, "mqtt", mqtt)
    handler._sync_mqtt_publisher()
    first = handler._mqtt_credentials
    assert handler._cert_expires_at is None and not handler._mqtt_ready
    assert clients[0].tls_set.call_args.kwargs["ca_certs"] == first.ca_cert_path
    assert clients[0].tls_set.call_args.kwargs["cert_reqs"] == namespace["ssl"].CERT_REQUIRED
    clients[0].username_pw_set.assert_not_called()
    handler._on_mqtt_connect(clients[0], None, None, 0)
    assert handler._cert_expires_at == first.expires_at
    old_signature = handler._current_mqtt_signature()
    e.enroll_device(**args)  # same credential JSON path, distinct actual certificate
    handler._reload_runtime_settings()
    assert handler._current_mqtt_signature() != old_signature
    assert handler._current_mqtt_signature()[-1] == handler._mqtt_credentials.fingerprint
    handler._sync_mqtt_publisher()
    clients[0].disconnect.assert_called_once()
    assert handler._mqtt_client is clients[1] and not handler._mqtt_ready
    assert handler._cert_expires_at == first.expires_at
    handler._on_mqtt_connect(clients[0], None, None, 0)  # stale callback
    assert not handler._mqtt_ready
    handler._on_mqtt_connect(clients[1], None, None, 5)
    assert not handler._mqtt_ready
    handler._on_mqtt_connect(clients[1], None, None, 0)
    assert handler._mqtt_ready and handler._cert_expires_at == handler._mqtt_credentials.expires_at


def test_actual_expired_signed_leaf_preserves_last_good(enrolled):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    args, _, options = enrolled
    good = materialize(args)
    bundle = json.loads(args["credential_file"].read_text())
    key = serialization.load_pem_private_key(bundle["private_key"].encode(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device:" + DEVICE)]))
        .sign(key, hashes.SHA256())
    )
    options["expired"] = True
    issued = e.post_verified_json(
        args["base_url"] + "/enroll",
        {
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        },
    )
    bundle.update(issued)
    e._save_bundle(args["credential_file"], bundle)
    with pytest.raises(e.EnrollmentError):
        materialize(args)
    assert Path(good.client_cert_path).exists()


def test_fingerprint_alone_forces_reinit_even_if_tls_paths_equal(enrolled, monkeypatch):
    from dataclasses import replace
    from unittest.mock import Mock

    args, settings, _ = enrolled
    handler = handler_for(args, settings, {"mqtt_enabled": True, "mqtt_tls_enabled": True})
    material = handler._mqtt_credentials
    e.enroll_device(**args)
    renewed = materialize(args)
    assert renewed.fingerprint != material.fingerprint
    handler._mqtt_client = Mock()
    handler._mqtt_runtime_signature = handler._current_mqtt_signature()
    # Equal paths isolate the content-fingerprint term from filename changes.
    handler._mqtt_credentials = replace(material, fingerprint=renewed.fingerprint)
    old_client = handler._mqtt_client
    initialize = Mock()
    monkeypatch.setattr(handler, "_init_mqtt_publisher", initialize)
    monkeypatch.setitem(handler._sync_mqtt_publisher.__globals__, "mqtt", Mock())
    handler._sync_mqtt_publisher()
    old_client.disconnect.assert_called_once()
    initialize.assert_called_once()


def test_reload_invalid_credentials_closes_active_publisher(enrolled):
    from unittest.mock import Mock

    args, settings, _ = enrolled
    handler = handler_for(args, settings, {"mqtt_enabled": True, "mqtt_tls_enabled": True})
    old_client = Mock()
    handler._mqtt_client = old_client
    handler._mqtt_ready = True
    args["credential_file"].chmod(0o644)
    with pytest.raises(e.EnrollmentError):
        handler._reload_runtime_settings()
    old_client.disconnect.assert_called_once()
    assert handler._mqtt_client is None and not handler._mqtt_ready


def test_inherited_real_acl_is_removed_before_tls_publish(enrolled):
    import struct

    args, _, _ = enrolled
    # Linux POSIX ACL: owner, named user, group, mask, other.
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
    os.setxattr(args["credential_file"].parent, "system.posix_acl_default", acl)
    result = materialize(args)
    for path in [
        Path(result.client_key_path).parent.parent,
        Path(result.client_key_path).parent,
        Path(result.client_key_path),
        Path(result.client_cert_path),
        Path(result.ca_cert_path),
    ]:
        assert not any(x.startswith("system.posix_acl_") for x in os.listxattr(path))


@pytest.mark.parametrize("location", ["store", "ancestor"])
def test_writable_ancestry_rejected_before_readback(enrolled, monkeypatch, location):
    args, _, _ = enrolled
    store = args["credential_file"].parent
    if location == "ancestor":
        store = store / "unsafe" / "store"
        store.mkdir(parents=True)
        unsafe = store.parent
    else:
        unsafe = store
    unsafe.chmod(0o777)
    from unittest.mock import Mock

    verify = Mock(wraps=m._readback)
    monkeypatch.setattr(m, "_readback", verify)
    try:
        fd = os.open(unsafe, m._DIR_FLAGS)
        try:
            with pytest.raises(e.EnrollmentError):
                m._check_ancestor(fd)
        finally:
            os.close(fd)
        with pytest.raises(e.EnrollmentError):
            m.materialize_credentials(
                args["credential_file"],
                base_url=args["base_url"],
                device_id=DEVICE,
                store_dir=store,
            )
        verify.assert_not_called()
        assert stat.S_IMODE(unsafe.stat().st_mode) == 0o777
    finally:
        unsafe.chmod(0o700)


@pytest.mark.parametrize("mask", [0, 7])
def test_ancestor_named_writer_acl_rejected_even_when_masked(tmp_path, mask):
    import struct

    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perm, uid)
        for tag, perm, uid in [
            (1, 7, 0xFFFFFFFF),
            (2, 7, os.geteuid() + 1),
            (4, 0, 0xFFFFFFFF),
            (16, mask, 0xFFFFFFFF),
            (32, 0, 0xFFFFFFFF),
        ]
    )
    os.setxattr(tmp_path, "system.posix_acl_access", acl)
    fd = os.open(tmp_path, m._DIR_FLAGS)
    try:
        with pytest.raises(e.EnrollmentError):
            m._check_ancestor(fd)
    finally:
        os.close(fd)
    assert os.getxattr(tmp_path, "system.posix_acl_access") == acl


def test_trusted_sticky_ancestor_is_allowed(tmp_path):
    tmp_path.chmod(0o1777)
    fd = os.open(tmp_path, m._DIR_FLAGS)
    try:
        m._check_ancestor(fd)
    finally:
        os.close(fd)
        tmp_path.chmod(0o700)


def test_symlink_parent_traversal_rejected_without_normalizing(tmp_path):
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(e.EnrollmentError):
        m._open_directory(tmp_path / "link" / "..")


@pytest.mark.parametrize("stage", ["interval", "port", "materialize", "managed"])
def test_failed_identity_reload_is_transactional_and_closes_publisher(enrolled, monkeypatch, stage):
    from unittest.mock import Mock

    args, settings, _ = enrolled
    handler = handler_for(args, settings, {"mqtt_enabled": True, "mqtt_tls_enabled": True})
    old_identity = handler._operational_credentials
    old_material = handler._mqtt_credentials
    client = Mock()
    handler._mqtt_client = client
    handler._mqtt_ready = True
    handler._mqtt_runtime_signature = handler._current_mqtt_signature()
    # A -> B is a distinct, valid issued identity, not a mock certificate.
    from tests import test_glass_enrollment

    device_b = "00000000-0000-4000-8000-000000000002"
    monkeypatch.setattr(test_glass_enrollment, "DEVICE", device_b)
    new_args = dict(args, device_id=device_b)
    e.enroll_device(**new_args)
    handler.config["glass"]["device_id"] = device_b
    if stage == "interval":
        handler.config["glass"]["inform_interval_seconds"] = "secret-invalid-interval"
    elif stage == "port":
        (args["credential_file"].parent / "managed.json").write_text(
            json.dumps(
                {
                    "mqtt_enabled": True,
                    "mqtt_tls_enabled": True,
                    "mqtt_broker_port": "secret-invalid-port",
                }
            )
        )
    else:

        def fail(*args, **kwargs):
            raise RuntimeError("secret-stage-error")

        if stage == "materialize":
            monkeypatch.setattr(m, "materialize_credentials", fail)
        else:
            monkeypatch.setattr(handler, "_load_managed_settings", fail)
    with pytest.raises(ValueError) as error:
        handler._reload_runtime_settings()
    assert "secret" not in str(error.value)
    assert handler._operational_credentials is old_identity
    assert handler._mqtt_credentials is old_material
    client.loop_stop.assert_called_once()
    client.disconnect.assert_called_once()
    assert handler._mqtt_client is None and not handler._mqtt_ready
    assert handler._mqtt_runtime_signature is None
    handler._on_mqtt_connect(client, None, None, 0)
    handler.publish_telemetry("packet", {})
    client.publish.assert_not_called()


def test_protected_http_keeps_original_https_ca(enrolled, monkeypatch):
    args, settings, _ = enrolled
    handler = handler_for(args, settings, {"mqtt_enabled": True, "mqtt_tls_enabled": True})
    calls = []

    def post(url, payload, **kwargs):
        calls.append(kwargs)
        return {"type": "noop"}

    monkeypatch.setattr(e, "post_verified_json", post)
    handler._post_inform_sync({"version": 1, "pubkey": args["pubkey"]})
    assert calls[0]["https_ca_file"] == "/provisioned/https-roots.pem"
    assert calls[0]["https_ca_file"] != handler._mqtt_credentials.ca_cert_path
