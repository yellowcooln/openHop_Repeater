"""Current-client assertions + real c1-c5a state. No live broker/proxy proof."""

# ruff: noqa: F811 - pytest injects imported fixtures by name
import asyncio
import copy
import fcntl
import hashlib
import json
import os
import threading
import uuid
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import Mock

import pytest

import repeater.data_acquisition.glass_handler as h
from repeater.data_acquisition.glass_handler import GlassHandler
from repeater.glass import enrollment as e
from repeater.glass import rotation_reports as q
from repeater.glass.mqtt_credentials import MqttCredentials
from tests.test_glass_rotation_install import install
from tests.test_glass_rotation_reports import (  # noqa: F401
    BOOT,
    NEXT_BOOT,
    ack,
    args,
    bundle,
    enroll_fixture,
    installation,
    installed,
    queue,
    state,
)


class MockPaho:
    """Callbacks bind to the canonical actual GlassHandler, not a fixture module."""

    def __init__(self, fast=False):
        self.fast = fast
        self.loop_stop = Mock()
        self.disconnect = Mock()
        self.tls_set = Mock()
        self.tls_insecure_set = Mock()
        self.username_pw_set = Mock()
        self.connect_async = Mock()
        self.publish = Mock()

    def loop_start(self):
        if self.fast:
            self.on_connect(self, None, None, 0)


@pytest.fixture
def paho(monkeypatch):
    clients = []

    def create():
        client = MockPaho()
        clients.append(client)
        return client

    monkeypatch.setattr(h, "mqtt", Mock(Client=create))
    return clients


def configured(current, store, target):
    return {
        "glass": {
            "enabled": True,
            "base_url": current["base_url"],
            "verify_tls": True,
            "device_id": current["device_id"],
            "operational_credential_file": str(target),
            "cert_store_dir": str(store),
            "ca_cert_path": "/provisioned/https-ca.pem",
            "request_timeout_seconds": 9,
        }
    }


def real_handler(case, enabled=True):
    current, store, target = case
    (store / "managed.json").write_text(
        json.dumps(
            {
                "mqtt_enabled": enabled,
                "mqtt_tls_enabled": True,
            }
        )
    )
    handler = GlassHandler(configured(current, store, target))
    handler._sync_mqtt_publisher()
    return handler


@pytest.fixture
def unit_handler(monkeypatch, paho):
    """No filesystem: exercise callback/start/cleanup seams independently."""
    handler = GlassHandler({})
    current = {
        "base_url": "https://glass.example",
        "device_id": BOOT,
        "operational_token": "T" * 43,
        "rotation_request_id": NEXT_BOOT,
        "cert_serial": "abcd",
        "fingerprint_sha256": "a" * 64,
    }
    handler.config = configured(current, "/private/store", "/private/store/current.json")
    handler.enabled = handler.verify_tls = handler.mqtt_enabled = handler.mqtt_tls_enabled = True
    handler.base_url = current["base_url"]
    handler.operational_credential_file = "/private/store/current.json"
    handler.cert_store_dir = "/private/store"
    handler.ca_cert_path = "/provisioned/https-ca.pem"
    handler.request_timeout_seconds = 9
    handler._operational_credentials = current
    handler._mqtt_credentials = MqttCredentials("ca", "cert", "key", "a" * 64, "abcd", "expiry")
    monkeypatch.setattr(handler, "_require_ssl_file", lambda path, name: path)
    handler._sync_mqtt_publisher()
    return handler


def connect(handler):
    client = handler._mqtt_client
    client.on_connect(client, None, None, 0)
    return client


def flush(handler):
    asyncio.run(handler._flush_operational_certificate_report())


@pytest.mark.parametrize("stage", ["construct", "auth", "tls"])
@pytest.mark.parametrize("replacement", ["unchanged", "newer_empty", "newer_client"])
def test_prepublication_failure_respects_epoch_and_clears_old_proof(
    unit_handler, monkeypatch, stage, replacement
):
    handler = unit_handler
    old_client = connect(handler)
    old_proof = handler._mqtt_connection_proof
    old_signature = handler._mqtt_runtime_signature
    material = handler._mqtt_connecting_credentials
    handler._close_mqtt_publisher()
    # Simulate stale readiness left with no currently published client.
    handler._mqtt_ready = True
    handler._mqtt_connection_proof = old_proof
    handler._mqtt_runtime_signature = old_signature
    handler._mqtt_connecting_credentials = material
    if stage == "auth":
        handler._operational_credentials = None
        handler.mqtt_username = "test-user"
    epoch = handler._mqtt_epoch
    failed, newer = MockPaho(), MockPaho()
    newer_proof = (newer, handler._report_binding(), handler._boot_id)

    def fail(*args, **kwargs):
        if replacement != "unchanged":
            with handler._mqtt_lock:
                handler._mqtt_epoch += 1
                if replacement == "newer_client":
                    handler._mqtt_client = newer
                    handler._mqtt_connection_proof = newer_proof
        raise RuntimeError("private-startup-error")

    if stage == "construct":
        factory = fail
    else:
        factory = lambda: failed
        getattr(failed, "username_pw_set" if stage == "auth" else "tls_set").side_effect = fail
    monkeypatch.setattr(h, "mqtt", Mock(Client=factory))
    cleanup_checked = []

    def stop_failed():
        # Another thread must acquire the mutex while cleanup is running.
        acquired = threading.Event()

        def take_lock():
            with handler._mqtt_lock:
                acquired.set()

        worker = threading.Thread(target=take_lock)
        worker.start()
        try:
            cleanup_checked.append(acquired.wait(2))
        finally:
            worker.join(2)

    failed.loop_stop.side_effect = stop_failed
    handler._init_mqtt_publisher()
    if replacement == "unchanged":
        assert handler._mqtt_client is None
        assert not handler._mqtt_ready
        assert handler._mqtt_runtime_signature is None
        assert handler._mqtt_connecting_credentials is None
        assert handler._mqtt_connection_proof is None
    else:
        assert handler._mqtt_epoch == epoch + 1
        assert handler._mqtt_client is (newer if replacement == "newer_client" else None)
        assert handler._mqtt_ready
        assert handler._mqtt_runtime_signature == old_signature
        assert handler._mqtt_connecting_credentials is material
        assert handler._mqtt_connection_proof is (
            newer_proof if replacement == "newer_client" else old_proof
        )
    if stage == "construct":
        failed.loop_stop.assert_not_called()
        failed.disconnect.assert_not_called()
        assert cleanup_checked == []
    else:
        failed.loop_stop.assert_called_once()
        failed.disconnect.assert_called_once()
        assert cleanup_checked == [True]
    newer.loop_stop.assert_not_called()
    newer.disconnect.assert_not_called()
    assert old_client is not handler._mqtt_client


def test_reporting_api_exists():
    assert callable(getattr(GlassHandler, "_flush_operational_certificate_report", None))


def test_boot_lifetime():
    first = GlassHandler({})
    boot = first._boot_id
    assert uuid.UUID(boot).version == 4
    first._reload_runtime_settings()
    asyncio.run(first.start())
    asyncio.run(first.stop())
    assert first._boot_id == boot
    assert GlassHandler({})._boot_id != boot


@pytest.mark.parametrize("enabled", [False, True])
def test_legacy_no_report(monkeypatch, enabled):
    monkeypatch.setattr(q, "load_report", lambda *a, **k: pytest.fail("report probe"))
    flush(GlassHandler({"glass": {"enabled": enabled}}))


def test_callback_exact_detached_binding(unit_handler, monkeypatch):
    handler = unit_handler
    assert handler._mqtt_connection_proof is None
    monkeypatch.setattr(e, "load_credentials", lambda *a, **k: pytest.fail("callback filesystem"))
    client = connect(handler)
    proof = handler._mqtt_connection_proof
    assert proof[0] is client and proof[1] == handler._report_binding()
    assert proof[2] == handler._boot_id
    assert proof[1][4] == hashlib.sha256(b"T" * 43).hexdigest()
    assert "T" * 43 not in repr(proof)
    handler._operational_credentials = dict(handler._operational_credentials, cert_serial="ef")
    assert proof[1][10] == "abcd"  # detached metadata, not the live mutable bundle


@pytest.mark.parametrize(
    "bad",
    [
        "failed",
        "old",
        "disconnect",
        "material",
        "signature",
        "initial",
        "invalid",
        "disabled",
        "tls",
        "verify",
        "config",
    ],
)
def test_false_claims(unit_handler, bad):
    handler = unit_handler
    client = handler._mqtt_client
    if bad == "failed":
        client.on_connect(client, None, None, 5)
    elif bad == "old":
        client.on_connect(MockPaho(), None, None, 0)
    elif bad == "disconnect":
        connect(handler)
        client.on_disconnect(client, None, 1)
    else:
        if bad == "material":
            handler._mqtt_connecting_credentials = replace(
                handler._mqtt_credentials, fingerprint="b" * 64
            )
        elif bad == "signature":
            handler._mqtt_runtime_signature = ()
        elif bad == "initial":
            handler._operational_credentials.pop("rotation_request_id")
        elif bad == "invalid":
            handler._runtime_settings_valid = False
        elif bad == "disabled":
            handler.enabled = False
        elif bad == "tls":
            handler.mqtt_tls_enabled = False
        elif bad == "verify":
            handler.verify_tls = False
        elif bad == "config":
            handler.config["glass"]["base_url"] = "https://foreign.example"
        connect(handler)
    assert handler._mqtt_connection_proof is None


def test_same_path_new_material_stale_callback(unit_handler):
    handler = unit_handler
    old = connect(handler)
    boot = handler._boot_id
    handler._mqtt_credentials = replace(handler._mqtt_credentials, fingerprint="b" * 64)
    handler._operational_credentials = dict(
        handler._operational_credentials, fingerprint_sha256="b" * 64
    )
    handler._sync_mqtt_publisher()
    new = handler._mqtt_client
    assert new is not old and handler._mqtt_connection_proof is None
    old.on_connect(old, None, None, 0)
    assert not handler._mqtt_ready
    connect(handler)
    proof = handler._mqtt_connection_proof
    old.on_disconnect(old, None, 1)
    assert handler._mqtt_connection_proof == proof and handler._mqtt_ready
    assert proof[1][11] == "b" * 64 and proof[2] == boot


def test_fast_start_callback(unit_handler, monkeypatch):
    handler = unit_handler
    handler._close_mqtt_publisher()
    monkeypatch.setattr(h, "mqtt", Mock(Client=lambda: MockPaho(fast=True)))
    handler._sync_mqtt_publisher()
    assert handler._mqtt_connection_proof[0] is handler._mqtt_client
    assert handler._mqtt_ready


def test_cleanup_does_not_hold_callback_mutex(unit_handler):
    handler = unit_handler
    client = connect(handler)
    finished = threading.Event()

    def stop():
        def callback():
            client.on_disconnect(client, None, 1)
            finished.set()

        thread = threading.Thread(target=callback)
        thread.start()
        thread.join(1)
        assert finished.is_set(), "loop_stop joined a callback blocked by MQTT mutex"

    client.loop_stop.side_effect = stop
    handler._close_mqtt_publisher()
    assert finished.is_set()
    assert handler._mqtt_client is None and handler._mqtt_connection_proof is None


def test_close_during_fast_start_never_revives(unit_handler, monkeypatch):
    handler = unit_handler
    handler._close_mqtt_publisher()
    client = MockPaho()

    def start():
        handler._close_mqtt_publisher()
        client.on_connect(client, None, None, 0)

    client.loop_start = start
    monkeypatch.setattr(h, "mqtt", Mock(Client=lambda: client))
    handler._sync_mqtt_publisher()
    assert handler._mqtt_client is None and handler._mqtt_connection_proof is None


def test_close_before_client_publication_never_revives(unit_handler, monkeypatch):
    handler = unit_handler
    handler._close_mqtt_publisher()
    client = MockPaho()
    client.tls_set.side_effect = lambda **k: handler._close_mqtt_publisher()
    monkeypatch.setattr(h, "mqtt", Mock(Client=lambda: client))
    handler._sync_mqtt_publisher()
    assert handler._mqtt_client is None and handler._mqtt_connection_proof is None
    client.connect_async.assert_not_called()
    client.loop_stop.assert_called_once()


def test_ready_alone_never_queues(unit_handler, monkeypatch):
    handler = unit_handler
    handler._mqtt_ready = True
    monkeypatch.setattr(
        e, "load_credentials", lambda *a, **k: dict(handler._operational_credentials)
    )
    monkeypatch.setattr(q, "load_report", lambda *a, **k: None)
    monkeypatch.setattr(q, "queue_report", lambda *a, **k: pytest.fail("fabricated assertion"))
    monkeypatch.setattr(e, "post_verified_json", lambda *a, **k: pytest.fail("HTTP"))
    flush(handler)


def test_disconnect_immediately_before_decision_no_fresh_claim(unit_handler, monkeypatch):
    handler = unit_handler
    client = connect(handler)
    monkeypatch.setattr(
        e, "load_credentials", lambda *a, **k: dict(handler._operational_credentials)
    )

    def load(*a, **k):
        client.on_disconnect(client, None, 1)

    monkeypatch.setattr(q, "load_report", load)
    monkeypatch.setattr(q, "queue_report", lambda *a, **k: pytest.fail("stale assertion"))
    monkeypatch.setattr(e, "post_verified_json", lambda *a, **k: pytest.fail("HTTP"))
    flush(handler)


@pytest.mark.parametrize("change", ["signature", "material", "mqtt_disabled", "tls_disabled"])
def test_fresh_decision_rechecks_current_mqtt_material(unit_handler, monkeypatch, change):
    handler = unit_handler
    connect(handler)
    if change == "signature":
        handler.mqtt_broker_host = "other.example"
    elif change == "material":
        handler._mqtt_credentials = replace(
            handler._mqtt_credentials, client_cert_path="other-cert"
        )
    elif change == "mqtt_disabled":
        handler.mqtt_enabled = False
    else:
        handler.mqtt_tls_enabled = False
    monkeypatch.setattr(
        e, "load_credentials", lambda *a, **k: dict(handler._operational_credentials)
    )
    monkeypatch.setattr(q, "load_report", lambda *a, **k: None)
    monkeypatch.setattr(q, "queue_report", lambda *a, **k: pytest.fail("stale current material"))
    monkeypatch.setattr(e, "post_verified_json", lambda *a, **k: pytest.fail("HTTP"))
    flush(handler)


def test_unit_producer_delivery_contract_outside_mutex(unit_handler, monkeypatch):
    """Unit seams only; durable c5a authority is exercised by real_* tests."""
    handler = unit_handler
    client = connect(handler)
    current = dict(handler._operational_credentials)
    saved = []
    acknowledged = []

    def outside():
        assert not handler._mqtt_lock._is_owned()

    def load_credentials(*a, **k):
        outside()
        assert a == (handler.operational_credential_file,)
        assert k == {"base_url": handler.base_url, "device_id": BOOT}
        return dict(current)

    def load_report(credentials, **options):
        outside()
        assert credentials == current
        return None if not saved else dict(saved[0])

    def queue_report(credentials, **options):
        outside()
        assert credentials == current
        assert options == {
            "store_dir": handler.cert_store_dir,
            "credential_file": handler.operational_credential_file,
            "boot_id": handler._boot_id,
            "connected_serial": "abcd",
            "connected_fingerprint": "a" * 64,
        }
        saved.append(
            {
                "device_id": BOOT,
                "request_id": NEXT_BOOT,
                "cert_serial": "abcd",
                "fingerprint_sha256": "a" * 64,
                "boot_id": handler._boot_id,
                "connected": True,
            }
        )
        return dict(saved[0])

    def post(url, report, **options):
        outside()
        assert url == "https://glass.example/device/certificates/report"
        assert report == saved[0]
        assert options == {
            "token": "T" * 43,
            "timeout": 9,
            "https_ca_file": "/provisioned/https-ca.pem",
            "max_request": 2048,
        }
        client.on_disconnect(client, None, 1)
        return ack(report)

    def acknowledge(credentials, report, response, **options):
        outside()
        assert credentials == current and report == saved[0] and response == ack(saved[0])
        guard = options.pop("commit_guard")
        assert callable(guard)
        guard()
        assert options == {
            "store_dir": handler.cert_store_dir,
            "credential_file": handler.operational_credential_file,
        }
        acknowledged.append(dict(report))

    monkeypatch.setattr(e, "load_credentials", load_credentials)
    monkeypatch.setattr(q, "load_report", load_report)
    monkeypatch.setattr(q, "queue_report", queue_report)
    monkeypatch.setattr(e, "post_verified_json", post)
    monkeypatch.setattr(q, "acknowledge_report", acknowledge)
    flush(handler)
    assert acknowledged == saved and handler._mqtt_connection_proof is None


def test_candidate_reload_does_not_clear_active_proof(unit_handler, monkeypatch):
    handler = unit_handler
    connect(handler)
    proof = handler._mqtt_connection_proof
    candidate = copy.copy(handler)
    monkeypatch.setattr(candidate, "_parse_runtime_settings", lambda: None)
    candidate._reload_runtime_settings()
    assert handler._mqtt_connection_proof is proof


@pytest.mark.parametrize(
    "mode", ["before_callback", "disabled", "invalid", "disconnected", "failed"]
)
def test_real_no_new_assertion(installed, paho, monkeypatch, mode):
    handler = real_handler(installed)
    if mode == "disabled":
        handler.enabled = False
    elif mode == "invalid":
        handler._runtime_settings_valid = False
    elif mode == "disconnected":
        client = connect(handler)
        client.on_disconnect(client, None, 1)
    elif mode == "failed":
        handler._on_mqtt_connect(handler._mqtt_client, None, None, 5)
    monkeypatch.setattr(e, "post_verified_json", lambda *a, **k: pytest.fail("HTTP"))
    flush(handler)
    assert not state(installed, "report-outbox.json").exists()


def test_real_initial_no_rotation_state(bundle, enroll_fixture, paho, monkeypatch):
    args_, _, _ = enroll_fixture
    handler = real_handler((bundle, args_["credential_file"].parent, args_["credential_file"]))
    connect(handler)
    assert handler._mqtt_connection_proof is None
    monkeypatch.setattr(q, "load_report", lambda *a, **k: pytest.fail("initial report probe"))
    flush(handler)


def test_real_install_same_path_requires_new_current_callback(installation, paho, monkeypatch):
    old_bundle, _, store, target = installation
    handler = real_handler((old_bundle, store, target))
    old = connect(handler)
    boot = handler._boot_id
    assert handler._mqtt_connection_proof is None
    install(installation)
    handler._reload_runtime_settings()
    handler._sync_mqtt_publisher()
    new = handler._mqtt_client
    assert new is not old and handler._mqtt_connection_proof is None
    old.on_connect(old, None, None, 0)
    assert not handler._mqtt_ready
    connect(handler)
    proof = handler._mqtt_connection_proof
    old.on_disconnect(old, None, 1)
    handler._reload_runtime_settings()
    assert handler._mqtt_connection_proof is proof
    assert handler._boot_id == boot and proof[0] is new
    assert proof[1][10:12] == (
        handler._operational_credentials["cert_serial"],
        handler._operational_credentials["fingerprint_sha256"],
    )
    monkeypatch.setattr(e, "post_verified_json", lambda url, report, **k: ack(report))
    flush(handler)
    assert (
        json.loads((store / "rotation-state/report-accepted.json").read_bytes())["report"][
            "boot_id"
        ]
        == boot
    )


def test_real_exact_route_body_trust_ack(installed, paho, monkeypatch):
    handler = real_handler(installed)
    connect(handler)
    calls = []
    before = {
        name: state(installed, name).read_bytes() for name in ("pending.json", "install.json")
    }

    def post(url, report, **options):
        calls.append(dict(report))
        assert url == installed[0]["base_url"] + "/device/certificates/report"
        assert report == {
            "device_id": installed[0]["device_id"],
            "request_id": installed[0]["rotation_request_id"],
            "cert_serial": installed[0]["cert_serial"],
            "fingerprint_sha256": installed[0]["fingerprint_sha256"],
            "boot_id": handler._boot_id,
            "connected": True,
        }
        assert options == {
            "token": installed[0]["operational_token"],
            "timeout": 9,
            "https_ca_file": "/provisioned/https-ca.pem",
            "max_request": 2048,
        }
        assert options["https_ca_file"] != handler._mqtt_credentials.ca_cert_path
        return ack(report)

    monkeypatch.setattr(e, "post_verified_json", post)
    flush(handler)
    assert not state(installed, "report-outbox.json").exists()
    assert json.loads(state(installed, "report-accepted.json").read_bytes())["report"] == calls[0]
    flush(handler)
    assert len(calls) == 1  # already accepted callback doesn't create more HTTP
    # Integrated lifecycle retires exactly the acknowledged installed request.
    assert not state(installed, "pending.json").exists()
    assert not state(installed, "install.json").exists()
    completed = json.loads(state(installed, "completed.json").read_bytes())
    assert completed["request_id"] == installed[0]["rotation_request_id"]
    assert completed["install_journal"] == json.loads(before["install.json"])
    assert (
        completed["pending_sha256"]
        == hashlib.sha256(
            q.r._canonical_json(json.loads(before["pending.json"]), q.r._LIMIT)
        ).hexdigest()
    )


@pytest.mark.parametrize("current_callback", [False, True])
def test_historical_retry_without_new_claim(installed, paho, monkeypatch, current_callback):
    historical = queue(installed)
    handler = real_handler(installed)
    if current_callback:
        connect(handler)
    calls = []

    def post(url, report, **options):
        calls.append(dict(report))
        return ack(report)

    monkeypatch.setattr(e, "post_verified_json", post)
    flush(handler)
    assert calls == [historical]
    flush(handler)
    assert len(calls) == (2 if current_callback else 1)
    if current_callback:
        assert calls[1]["boot_id"] == handler._boot_id
    else:
        assert handler._mqtt_connection_proof is None


@pytest.mark.parametrize("response", ["lost", "malformed", "stale", "extra", "false"])
def test_lost_or_wrong_response_retains_exact_retry(installed, paho, monkeypatch, caplog, response):
    handler = real_handler(installed)
    client = connect(handler)
    sent = []

    def post(url, report, **options):
        sent.append(dict(report))
        if response == "lost":
            raise OSError("secret-worker-error")
        value = ack(report)
        if response == "malformed":
            return None
        if response == "stale":
            value["request_id"] = NEXT_BOOT
        if response == "extra":
            value["secret"] = "secret-worker-error"
        if response == "false":
            value["accepted"] = False
        return value

    monkeypatch.setattr(e, "post_verified_json", post)
    flush(handler)
    saved = state(installed, "report-outbox.json").read_bytes()
    client.on_disconnect(client, None, 1)
    flush(handler)
    assert sent[0] == sent[1]
    assert state(installed, "report-outbox.json").read_bytes() == saved
    monkeypatch.setattr(e, "post_verified_json", lambda url, report, **k: ack(report))
    flush(handler)
    assert not state(installed, "report-outbox.json").exists()
    assert "secret-worker-error" not in caplog.text


@pytest.mark.parametrize("moment", ["before_queue", "before_http", "during_http"])
@pytest.mark.parametrize(
    "change",
    ["origin", "device", "generation", "path", "store", "ca", "disabled", "verify", "leaf"],
)
def test_changed_binding_never_sends_or_acknowledges(installed, paho, monkeypatch, moment, change):
    handler = real_handler(installed)
    connect(handler)
    sent = []
    real_load, real_queue = q.load_report, q.queue_report

    def mutate():
        cfg = handler.config["glass"]
        if change in ("generation", "leaf"):
            current = json.loads(installed[2].read_bytes())
            current["operational_token" if change == "generation" else "fingerprint_sha256"] = (
                "Z" * 43 if change == "generation" else "b" * 64
            )
            installed[2].write_text(json.dumps(current))
        else:
            key, value = {
                "origin": ("base_url", "https://foreign.example"),
                "device": ("device_id", NEXT_BOOT),
                "path": ("operational_credential_file", "/other/credentials.json"),
                "store": ("cert_store_dir", "/other/store"),
                "ca": ("ca_cert_path", "/other/ca.pem"),
                "disabled": ("enabled", False),
                "verify": ("verify_tls", False),
            }[change]
            cfg[key] = value

    if moment == "before_queue":

        def load(*a, **k):
            result = real_load(*a, **k)
            mutate()
            return result

        monkeypatch.setattr(q, "load_report", load)
    if moment == "before_http":

        def queue_then_change(*a, **k):
            result = real_queue(*a, **k)
            mutate()
            return result

        monkeypatch.setattr(q, "queue_report", queue_then_change)

    def post(url, report, **options):
        sent.append(dict(report))
        if moment == "during_http":
            mutate()
        return ack(report)

    monkeypatch.setattr(e, "post_verified_json", post)
    flush(handler)
    assert len(sent) == (1 if moment == "during_http" else 0)
    assert not state(installed, "report-accepted.json").exists()
    if moment != "before_queue":
        assert state(installed, "report-outbox.json").exists()


def test_disconnect_after_queue_can_ack_history(installed, paho, monkeypatch):
    handler = real_handler(installed)
    client = connect(handler)
    real_queue = q.queue_report

    def decision_then_disconnect(*a, **k):
        client.on_disconnect(client, None, 1)
        return real_queue(*a, **k)

    monkeypatch.setattr(q, "queue_report", decision_then_disconnect)
    monkeypatch.setattr(e, "post_verified_json", lambda url, report, **k: ack(report))
    flush(handler)
    assert state(installed, "report-accepted.json").exists()
    assert handler._mqtt_connection_proof is None


def test_response_cannot_ack_other_boot_outbox(installed, paho, monkeypatch):
    first = queue(installed)
    handler = real_handler(installed)

    def post(url, report, **options):
        assert report == first
        q.acknowledge_report(installed[0], first, ack(first), **args(installed))
        queue(installed, NEXT_BOOT)
        return ack(first)

    monkeypatch.setattr(e, "post_verified_json", post)
    flush(handler)
    assert q.load_report(installed[0], **args(installed))["boot_id"] == NEXT_BOOT


@pytest.mark.parametrize("worker_error", [False, True])
def test_cancelled_report_drains_serializes_and_sanitizes(
    unit_handler, monkeypatch, caplog, worker_error
):
    handler = unit_handler
    connect(handler)
    current = dict(handler._operational_credentials)
    report = {
        "device_id": BOOT,
        "request_id": NEXT_BOOT,
        "cert_serial": "abcd",
        "fingerprint_sha256": "a" * 64,
        "boot_id": handler._boot_id,
        "connected": True,
    }
    entered, release, finished = (threading.Event() for _ in range(3))
    calls, acknowledgments = [], []
    monkeypatch.setattr(e, "load_credentials", lambda *a, **k: dict(current))
    monkeypatch.setattr(q, "load_report", lambda *a, **k: dict(report))
    monkeypatch.setattr(q, "acknowledge_report", lambda *a, **k: acknowledgments.append(a))

    def post(*a, **k):
        calls.append(a)
        entered.set()
        try:
            assert release.wait(5)
            if worker_error:
                raise RuntimeError("secret-cancelled-worker-error")
            return ack(report)
        finally:
            finished.set()

    monkeypatch.setattr(e, "post_verified_json", post)

    async def run():
        errors = []
        asyncio.get_running_loop().set_exception_handler(
            lambda loop, context: errors.append(context)
        )
        first = asyncio.create_task(handler._flush_operational_certificate_report())
        second = None
        try:
            for _ in range(200):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert entered.is_set()  # blocked HTTP did not block the event loop
            first.cancel()
            await asyncio.sleep(0)
            second = asyncio.create_task(handler._flush_operational_certificate_report())
            for _ in range(3):
                first.cancel()
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                assert not first.done() and not second.done()
                assert handler._rotation_lock.locked()
                assert len(calls) == 1
                assert not handler._runtime_settings_valid and handler._mqtt_client is None
            # A settings reload may race the blocked worker; cancellation must
            # invalidate again AFTER draining, not just on its first delivery.
            handler._runtime_settings_valid = True
            handler._mqtt_client = MockPaho()
            handler._mqtt_ready = True
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(first, 2)
            await asyncio.wait_for(second, 2)
            assert finished.is_set() and not handler._rotation_lock.locked()
            assert not errors
        finally:
            release.set()
            await asyncio.gather(
                *(t for t in (first, second) if t is not None), return_exceptions=True
            )

    asyncio.run(run())
    assert len(calls) == 1 and not acknowledgments
    assert handler._mqtt_connection_proof is None and not handler._runtime_settings_valid
    assert "secret-cancelled-worker-error" not in caplog.text


async def wait_event(event):
    for _ in range(300):
        if event.is_set():
            return
        await asyncio.sleep(0.01)
    pytest.fail("worker did not reach controlled acknowledgment boundary")


@pytest.mark.parametrize("change", ["cancel", "config"])
@pytest.mark.parametrize("admitted", [False, True])
def test_ack_admission_wait_boundary(unit_handler, monkeypatch, caplog, change, admitted):
    """Real acknowledgment algorithm, controlled authority wait; no disk/PKI claim."""
    handler = unit_handler
    connect(handler)
    current = dict(handler._operational_credentials)
    report = {
        "device_id": BOOT,
        "request_id": NEXT_BOOT,
        "cert_serial": "abcd",
        "fingerprint_sha256": "a" * 64,
        "boot_id": BOOT,  # historical assertion, not a fresh current-boot claim
        "connected": True,
    }
    records = {q._OUTBOX: {"report": report}}
    waiting, release, finished = (threading.Event() for _ in range(3))
    mutations, guards, posts = [], [], []
    real_ack = q.acknowledge_report

    @contextmanager
    def authority(*a):
        assert not handler._mqtt_lock._is_owned()
        if not admitted:
            waiting.set()
            assert release.wait(5)
        yield 123, current, {}, None, False

    def record(directory, name, *a, accepted_fallback=None):
        assert accepted_fallback is None
        assert not handler._mqtt_lock._is_owned()
        return records.get(name), b"exact-outbox" if name == q._OUTBOX else None

    def publish(directory, name, value, *a):
        assert not handler._mqtt_lock._is_owned()
        mutations.append("publish")
        records[name] = value

    def unlink(name, **k):
        mutations.append("unlink")
        del records[name]

    def guarded_ack(*a, **k):
        guard = k.pop("commit_guard", None)

        def admission():
            guards.append("attempt")
            assert guard is not None
            guard()
            guards.append("admitted")
            if admitted:
                waiting.set()
                assert release.wait(5)

        try:
            # Before the extension exists, exercise the original API so RED
            # demonstrates actual late writes, not just a missing keyword.
            if guard is None:
                return real_ack(*a, **k)
            return real_ack(*a, **k, commit_guard=admission)
        finally:
            finished.set()

    monkeypatch.setattr(e, "load_credentials", lambda *a, **k: dict(current))
    monkeypatch.setattr(q, "load_report", lambda *a, **k: dict(report))
    monkeypatch.setattr(q, "queue_report", lambda *a, **k: pytest.fail("new claim"))
    monkeypatch.setattr(q, "_authority", authority)
    monkeypatch.setattr(q, "_record", record)
    monkeypatch.setattr(q, "_publish", publish)
    monkeypatch.setattr(q, "_unlink", unlink)
    monkeypatch.setattr(q, "_fsync", lambda *a: mutations.append("fsync"))
    monkeypatch.setattr(q, "acknowledge_report", guarded_ack)

    def post(*a, **k):
        posts.append(a)
        return ack(report)

    monkeypatch.setattr(e, "post_verified_json", post)

    async def run():
        errors = []
        asyncio.get_running_loop().set_exception_handler(lambda loop, ctx: errors.append(ctx))
        first = asyncio.create_task(handler._flush_operational_certificate_report())
        second = None
        try:
            await wait_event(waiting)
            assert not mutations
            if change == "cancel":
                for _ in range(3):
                    first.cancel()
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                    assert not first.done() and handler._rotation_lock.locked()
                second = asyncio.create_task(handler._flush_operational_certificate_report())
                await asyncio.sleep(0)
                assert not second.done()
            else:
                with handler._mqtt_lock:
                    handler.config["glass"]["base_url"] = "https://foreign.example"
                assert not first.done() and handler._rotation_lock.locked()
            assert len(posts) == 1 and not finished.is_set()
            release.set()
            if change == "cancel":
                with pytest.raises(asyncio.CancelledError):
                    await first
                await second
                assert not handler._runtime_settings_valid and handler._mqtt_client is None
                assert handler._mqtt_connection_proof is None
            else:
                await first
            assert finished.is_set() and not handler._rotation_lock.locked()
            assert not errors
        finally:
            release.set()
            await asyncio.gather(*(t for t in (first, second) if t), return_exceptions=True)

    asyncio.run(run())
    assert len(posts) == 1
    if admitted:
        assert records == {q._ACCEPTED: {"report": report, "ack": ack(report)}}
        assert mutations == ["publish", "unlink", "fsync"]
    else:
        assert records == {q._OUTBOX: {"report": report}}
        assert mutations == []
    assert guards == (["attempt", "admitted"] if admitted else ["attempt"])
    assert "Glass report binding changed" not in caplog.text


@pytest.mark.parametrize("change", ["cancel", "config"])
@pytest.mark.parametrize("admitted", [False, True])
def test_real_ack_durable_lock_admission(installed, paho, monkeypatch, change, admitted):
    """Actual private PKI/core + flock wait after HTTP; no broker/proxy claim."""
    historical = queue(installed)
    outbox = state(installed, "report-outbox.json")
    raw = outbox.read_bytes()
    before = {
        name: state(installed, name).read_bytes() for name in ("pending.json", "install.json")
    }
    credential = installed[2].read_bytes()
    handler = real_handler(installed)
    connect(handler)
    lock_path = state(installed, ".lock")
    waiting, release, finished = (threading.Event() for _ in range(3))
    holder, guards, posts = [], [], []
    real_flock, real_ack = fcntl.flock, q.acknowledge_report

    def unlock():
        if holder:
            fd = holder.pop()
            real_flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def flock(fd, operation):
        assert not handler._mqtt_lock._is_owned()
        if holder and fd != holder[0] and operation == fcntl.LOCK_EX:
            waiting.set()
        return real_flock(fd, operation)

    def post(url, report, **options):
        posts.append(dict(report))
        assert report == historical
        if not admitted:
            fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            real_flock(fd, fcntl.LOCK_EX)
            holder.append(fd)
        return ack(report)

    def guarded_ack(*a, **k):
        guard = k.pop("commit_guard")

        def admission():
            guards.append("attempt")
            assert not handler._mqtt_lock._is_owned()
            assert outbox.read_bytes() == raw
            assert not state(installed, "report-accepted.json").exists()
            # The guard really runs under the cross-descriptor durable lock.
            fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                with pytest.raises(BlockingIOError):
                    real_flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            guard()
            guards.append("admitted")
            if admitted:
                waiting.set()
                assert release.wait(5)

        try:
            return real_ack(*a, **k, commit_guard=admission)
        finally:
            finished.set()

    monkeypatch.setattr(fcntl, "flock", flock)
    monkeypatch.setattr(e, "post_verified_json", post)
    monkeypatch.setattr(q, "acknowledge_report", guarded_ack)
    monkeypatch.setattr(q, "queue_report", lambda *a, **k: pytest.fail("new claim"))

    async def run():
        errors = []
        asyncio.get_running_loop().set_exception_handler(lambda loop, ctx: errors.append(ctx))
        first = asyncio.create_task(handler._flush_operational_certificate_report())
        second = None
        try:
            await wait_event(waiting)
            assert outbox.read_bytes() == raw
            assert not state(installed, "report-accepted.json").exists()
            if change == "cancel":
                for _ in range(3):
                    first.cancel()
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                    assert not first.done() and handler._rotation_lock.locked()
                second = asyncio.create_task(handler._flush_operational_certificate_report())
                await asyncio.sleep(0)
                assert not second.done()
            else:
                with handler._mqtt_lock:
                    handler.config["glass"]["base_url"] = "https://foreign.example"
            assert not finished.is_set() and len(posts) == 1
            assert guards == (["attempt", "admitted"] if admitted else [])
            unlock()
            release.set()
            if change == "cancel":
                with pytest.raises(asyncio.CancelledError):
                    await first
                assert second is not None
                await second
                assert handler._mqtt_client is None and not handler._runtime_settings_valid
                assert handler._mqtt_connection_proof is None
            else:
                await first
            assert finished.is_set() and not handler._rotation_lock.locked()
            assert not errors
        finally:
            unlock()
            release.set()
            await asyncio.gather(*(t for t in (first, second) if t), return_exceptions=True)

    asyncio.run(run())
    assert guards == (["attempt", "admitted"] if admitted else ["attempt"])
    if admitted:
        assert not outbox.exists()
        accepted = json.loads(state(installed, "report-accepted.json").read_bytes())
        assert accepted["report"] == historical and accepted["ack"] == ack(historical)
    else:
        assert outbox.read_bytes() == raw
        assert not state(installed, "report-accepted.json").exists()
    assert installed[2].read_bytes() == credential
    assert all(state(installed, name).read_bytes() == value for name, value in before.items())
    assert posts == [historical]


def test_report_failure_preserves_inform_result(unit_handler, monkeypatch, caplog):
    handler = unit_handler
    monkeypatch.setattr(handler, "_reload_runtime_settings", lambda: None)

    async def payload():
        return {}

    async def post(value):
        return {"type": "noop", "interval": 42}

    async def maintain():
        return None

    monkeypatch.setattr(handler, "_build_inform_payload", payload)
    monkeypatch.setattr(handler, "_post_inform", post)
    monkeypatch.setattr(handler, "_maintain_operational_certificate", maintain)
    monkeypatch.setattr(
        e,
        "load_credentials",
        lambda *a, **k: (_ for _ in ()).throw(OSError("secret-report-failure")),
    )
    assert asyncio.run(handler._inform_once()) == 42
    assert "report failed" in caplog.text and "secret-report-failure" not in caplog.text
