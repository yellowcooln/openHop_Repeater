"""Renewal maintenance lifecycle, without a live broker."""

# ruff: noqa: F811 - imported pytest fixtures are injected by name
import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from repeater.data_acquisition.glass_handler import GlassHandler
from repeater.glass import rotation_transport as t
from tests.test_glass_rotation_state import (  # noqa: F401
    bundle,
    enroll_fixture,
    renewal_response,
)


def make_handler(args, mqtt_enabled=False):
    # Use the canonical module so MQTT and clock patches bind to this handler.
    (args["credential_file"].parent / "managed.json").write_text(
        json.dumps({"mqtt_enabled": mqtt_enabled, "mqtt_tls_enabled": True})
    )
    return GlassHandler(
        {
            "repeater": {"node_name": "display name"},
            "glass": {
                "device_id": args["device_id"],
                "operational_credential_file": str(args["credential_file"]),
                "enabled": True,
                "base_url": args["base_url"],
                "verify_tls": True,
                "cert_store_dir": str(args["credential_file"].parent),
                "ca_cert_path": "/provisioned/https-roots.pem",
            },
        }
    )


@pytest.mark.parametrize("enabled", [True, False])
def test_legacy_and_disabled_do_not_probe(monkeypatch, enabled):
    handler = GlassHandler({"glass": {"enabled": enabled}})
    monkeypatch.setattr(t, "rotation_pending", lambda *a: pytest.fail("probe"))
    asyncio.run(handler._maintain_operational_certificate())


def test_not_due_no_transport(bundle, enroll_fixture, monkeypatch):
    args, _, _ = enroll_fixture
    handler = make_handler(args)
    monkeypatch.setattr(t, "renew_credentials", lambda **k: pytest.fail("renew"))
    asyncio.run(handler._maintain_operational_certificate())


def test_pending_real_install_replaces_fingerprint_client(
    bundle, enroll_fixture, tmp_path, monkeypatch
):
    import repeater.data_acquisition.glass_handler as h

    args, _, _ = enroll_fixture
    issued = renewal_response(bundle, tmp_path)
    clients = []

    def client():
        value = Mock()
        clients.append(value)
        return value

    monkeypatch.setattr(h, "mqtt", Mock(Client=client))
    handler = make_handler(args, True)
    handler._sync_mqtt_publisher()
    old = handler._mqtt_client
    old_material = handler._mqtt_credentials
    handler._on_mqtt_connect(old, None, None, 0)
    assert handler._mqtt_ready
    old_expiry = handler._cert_expires_at

    def post(url, payload, **options):
        assert options["https_ca_file"] == "/provisioned/https-roots.pem"
        return issued

    monkeypatch.setattr(t, "post_verified_json", post)
    asyncio.run(handler._maintain_operational_certificate())
    new = handler._mqtt_client
    assert new is not old and len(clients) == 2
    assert not handler._mqtt_ready
    assert handler._cert_expires_at == old_expiry
    assert handler._mqtt_credentials.fingerprint != old_material.fingerprint
    old.disconnect.assert_called_once()
    old.loop_stop.assert_called_once()
    handler._on_mqtt_connect(old, None, None, 0)
    assert not handler._mqtt_ready
    handler._on_mqtt_connect(new, None, None, 0)
    assert handler._mqtt_ready
    handler._on_mqtt_disconnect(old, None, 1)
    assert handler._mqtt_ready
    handler._on_mqtt_disconnect(new, None, 1)
    assert not handler._mqtt_ready
    assert handler.ca_cert_path == "/provisioned/https-roots.pem"
    assert handler.operational_credential_file == str(args["credential_file"])
    assert handler._pending_command_results == []
    handler._close_mqtt_publisher()


def test_due_uses_leaf_not_metadata(bundle, enroll_fixture, monkeypatch):
    import repeater.data_acquisition.glass_handler as h

    args, _, _ = enroll_fixture
    handler = make_handler(args)
    calls = []
    clock = Mock()
    clock.now.return_value = datetime.now(timezone.utc) + timedelta(days=6, hours=1)
    monkeypatch.setattr(h, "datetime", clock)
    monkeypatch.setattr(t, "renew_credentials", lambda **k: calls.append(k))
    asyncio.run(handler._maintain_operational_certificate())
    assert len(calls) == 1


def test_changed_config_worker_does_not_reactivate(
    bundle, enroll_fixture, tmp_path, monkeypatch, caplog
):
    args, _, _ = enroll_fixture
    issued = renewal_response(bundle, tmp_path)
    handler = make_handler(args)
    handler._mqtt_client = Mock()
    old = handler._mqtt_client
    entered, release = threading.Event(), threading.Event()

    def post(*a, **k):
        entered.set()
        assert release.wait(5)
        return issued

    monkeypatch.setattr(t, "post_verified_json", post)

    async def run():
        task = asyncio.create_task(handler._maintain_operational_certificate())
        for _ in range(200):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set()  # Event loop stayed responsive while HTTPS blocked.
        handler.config["glass"]["enabled"] = False
        release.set()
        await task

    asyncio.run(run())
    assert handler._mqtt_client is None and not handler._runtime_settings_valid
    old.disconnect.assert_called_once()
    assert "maintenance failed" in caplog.text
    assert "bundle installed" not in caplog.text


def test_successful_inform_survives_maintenance_error(monkeypatch, caplog):
    handler = GlassHandler({"glass": {"enabled": True}})
    handler._operational_credentials = {"private_key": "secret"}
    monkeypatch.setattr(handler, "_reload_runtime_settings", lambda: None)

    async def payload():
        return {}

    async def post(value):
        return {"type": "noop", "interval": 42}

    monkeypatch.setattr(handler, "_build_inform_payload", payload)
    monkeypatch.setattr(handler, "_post_inform", post)
    assert asyncio.run(handler._inform_once()) == 42
    assert "maintenance failed" in caplog.text
    assert "secret" not in caplog.text


def test_loop_reload_failure_is_contained(monkeypatch, caplog):
    handler = GlassHandler({"glass": {"enabled": True}})
    handler.config["glass"]["operational_credential_file"] = "bound"

    def fail():
        handler._stop_event.set()
        raise RuntimeError("secret-runtime-error")

    monkeypatch.setattr(handler, "_reload_runtime_settings", fail)

    async def run():
        handler._stop_event = asyncio.Event()
        await handler._run_loop()

    asyncio.run(run())
    assert "runtime reload failed" in caplog.text
    assert "secret-runtime-error" not in caplog.text


def test_disabled_enrolled_does_not_probe(bundle, enroll_fixture, monkeypatch):
    args, _, _ = enroll_fixture
    handler = make_handler(args)
    handler.config["glass"]["enabled"] = False
    handler._reload_runtime_settings()
    monkeypatch.setattr(t, "rotation_pending", lambda *a: pytest.fail("probe"))
    asyncio.run(handler._maintain_operational_certificate())


@pytest.mark.parametrize("worker_error", [False, True])
@pytest.mark.parametrize("changed_config", [False, True])
def test_cancelled_maintenance_owns_worker_until_completion(
    monkeypatch, caplog, worker_error, changed_config
):
    """Exercise the real executor, without credential files or HTTPS."""
    from cryptography import x509

    monkeypatch.setattr(GlassHandler, "_load_managed_settings", lambda self: {})
    handler = GlassHandler({"glass": {"enabled": True}})
    handler.operational_credential_file = "mock-bound-credentials"
    handler._operational_credentials = {"device_id": "mock-device", "client_cert": "mock-leaf"}
    handler._mqtt_client = old = Mock()
    handler._mqtt_ready = True
    old_expiry = handler._cert_expires_at = "old-expiry"
    activations = []

    def reload_settings(self, *, _candidate=None):
        if _candidate is not None:
            activations.append(_candidate)

    monkeypatch.setattr(GlassHandler, "_reload_runtime_settings", reload_settings)
    monkeypatch.setattr(handler, "_sync_mqtt_publisher", lambda: activations.append("sync"))
    monkeypatch.setattr(
        x509,
        "load_pem_x509_certificate",
        lambda value: Mock(not_valid_after_utc=datetime.now(timezone.utc) + timedelta(hours=1)),
    )
    monkeypatch.setattr(t, "rotation_pending", lambda store: False)
    entered, release, finished, second_entered = (threading.Event() for _ in range(4))
    calls = []

    def renew(**options):
        calls.append(options)
        if len(calls) == 1:
            entered.set()
            try:
                assert release.wait(5), "test did not release executor worker"
                if worker_error:
                    raise RuntimeError("secret-worker-error")
            finally:
                finished.set()
        else:
            second_entered.set()
            assert finished.is_set(), "overlapping renewal workers"
            raise RuntimeError("secret-second-error")

    monkeypatch.setattr(t, "renew_credentials", renew)

    async def wait_event(event):
        for _ in range(200):
            if event.is_set():
                return
            await asyncio.sleep(0.01)
        pytest.fail("executor event was not reached")

    async def run():
        first = asyncio.create_task(handler._maintain_operational_certificate())
        second = None
        try:
            await wait_event(entered)
            first.cancel()
            await asyncio.sleep(0)
            if changed_config:
                handler.config["glass"]["base_url"] = "https://changed.invalid"
            assert not first.done(), "cancellation abandoned a running executor worker"
            assert handler._rotation_lock.locked()
            assert not handler._runtime_settings_valid
            assert handler._mqtt_client is None and not handler._mqtt_ready
            second = asyncio.create_task(handler._maintain_operational_certificate())
            for _ in range(3):
                first.cancel()
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                assert not first.done()
                assert handler._rotation_lock.locked()
                assert not second_entered.is_set()
                assert len(calls) == 1
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(first, timeout=2)
            await asyncio.wait_for(second, timeout=2)
            assert finished.is_set() and second_entered.is_set()
            assert not handler._rotation_lock.locked()
        finally:
            release.set()
            await asyncio.wait_for(
                asyncio.gather(
                    *(task for task in (first, second) if task is not None), return_exceptions=True
                ),
                timeout=3,
            )

    asyncio.run(run())
    assert len(calls) == 2
    assert activations == []  # Never install or reconnect the cancelled candidate.
    assert handler._mqtt_client is None and not handler._mqtt_ready
    assert not handler._runtime_settings_valid
    assert handler._cert_expires_at == old_expiry
    old.loop_stop.assert_called_once()
    old.disconnect.assert_called_once()
    assert "bundle installed" not in caplog.text
    assert "secret-worker-error" not in caplog.text
    assert "secret-second-error" not in caplog.text


def test_handler_maintenance_api_exists():
    assert callable(getattr(GlassHandler, "_maintain_operational_certificate", None))
