"""MQTT partial-start regressions; no broker or credential materialization."""

import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_glass_handler import _MODULE, GlassHandler, _make_config


@pytest.mark.parametrize("stage", ["construct", "auth", "tls", "connect", "loop"])
@pytest.mark.parametrize("cleanup_failure", [None, "loop_stop", "disconnect", "both"])
def test_mqtt_partial_start_detaches_cleans_and_sanitizes(
    monkeypatch, caplog, stage, cleanup_failure
):
    handler = GlassHandler(_make_config())
    handler.enabled = True
    handler.mqtt_enabled = True
    handler.mqtt_tls_enabled = True
    handler.mqtt_username = "test-user"
    handler.mqtt_password = "secret-password-marker"
    material = SimpleNamespace(
        ca_cert_path="/fake/ca",
        client_cert_path="/fake/cert",
        client_key_path="/fake/key",
        expires_at="future",
        fingerprint="test-fingerprint",
    )
    handler._mqtt_credentials = material
    monkeypatch.setattr(handler, "_require_ssl_file", lambda path, name: path)
    secret = "secret-password-marker PRIVATE KEY exception payload"
    client = Mock()
    resources: dict[str, object | None] = {"connection": None, "loop": None}
    cleanup = []

    def connect(*args):
        resources["connection"] = object()  # partial connection before failure
        if stage == "connect":
            raise RuntimeError(secret)

    def start_loop():
        resources["loop"] = object()  # a partial start is not a no-op mock
        handler._on_mqtt_connect(client, None, None, 0)
        assert handler._mqtt_ready
        if stage == "loop":
            raise RuntimeError(secret)

    def stop_loop():
        cleanup.append("loop_stop")
        assert handler._mqtt_client is None
        assert not handler._mqtt_ready
        handler._on_mqtt_connect(client, None, None, 0)
        resources["loop"] = None
        if cleanup_failure in ("loop_stop", "both"):
            raise RuntimeError(secret)

    def disconnect():
        cleanup.append("disconnect")
        resources["connection"] = None
        if cleanup_failure in ("disconnect", "both"):
            raise RuntimeError(secret)

    client.connect_async.side_effect = connect
    client.loop_start.side_effect = start_loop
    client.loop_stop.side_effect = stop_loop
    client.disconnect.side_effect = disconnect
    if stage in ("auth", "tls"):
        getattr(
            client, "username_pw_set" if stage == "auth" else "tls_set"
        ).side_effect = RuntimeError(secret)
    factory = Mock(return_value=client)
    if stage == "construct":
        factory.side_effect = RuntimeError(secret)
    monkeypatch.setattr(_MODULE, "mqtt", SimpleNamespace(Client=factory))
    # Stale state must be reset even if constructing a replacement fails.
    handler._mqtt_ready = True
    handler._mqtt_runtime_signature = ("stale",)
    handler._mqtt_connecting_credentials = material
    with caplog.at_level(logging.DEBUG, logger="GlassHandler"):
        handler._init_mqtt_publisher()
    assert handler._mqtt_client is None
    assert handler._mqtt_ready is False
    assert handler._mqtt_runtime_signature is None
    assert handler._mqtt_connecting_credentials is None
    assert resources == {"connection": None, "loop": None}
    if stage == "construct":
        assert cleanup == []
    else:
        assert cleanup == ["loop_stop", "disconnect"]
        client.loop_stop.assert_called_once()
        client.disconnect.assert_called_once()
    handler._on_mqtt_connect(client, None, None, 0)
    handler.publish_telemetry("packet", {})
    client.publish.assert_not_called()
    assert not handler._mqtt_ready
    assert handler._cert_expires_at is None or stage == "loop"
    assert "Failed to start Glass MQTT telemetry publisher" in caplog.text
    assert "secret-password-marker" not in caplog.text
    assert "PRIVATE KEY" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
