"""Safe configured inventory uses the real manager without optional sensor imports."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import yaml

from repeater.sensors.manager import SensorManager


def make_manager(definitions, monkeypatch):
    registry = Mock()

    def create(sensor_type, *, name, config):
        if name == "failed":
            raise ValueError("private-token at https://private.example")
        return SimpleNamespace(name=name, sensor_type=str(sensor_type).strip().lower())

    registry.create.side_effect = create
    monkeypatch.setattr(SensorManager, "_load_sensor_module", lambda self, sensor_type: None)
    return SensorManager(
        {"sensors": {"enabled": True, "poll_interval_seconds": 15, "definitions": definitions}},
        registry=registry,
    )


def test_inventory_covers_disabled_failed_and_awaiting_without_secrets(monkeypatch):
    definitions = [
        {"name": "disabled", "type": "test", "enabled": False},
        {"name": "failed", "type": "test"},
        {"name": "awaiting", "type": "test"},
        {"name": "other", "type": "test"},
    ]
    for definition in definitions:
        definition.update(
            settings={"token": "private-token", "url": "https://private.example"},
            password="private-password",
            error="private-error",
        )
    manager = make_manager(definitions, monkeypatch)
    summary = manager.get_summary()
    assert summary.pop("inventory") == [
        {"name": "disabled", "type": "test", "enabled": False, "loaded": False},
        {"name": "failed", "type": "test", "enabled": True, "loaded": False},
        {"name": "awaiting", "type": "test", "enabled": True, "loaded": True},
        {"name": "other", "type": "test", "enabled": True, "loaded": True},
    ]
    assert summary == {
        "enabled": True,
        "poll_interval_seconds": 15.0,
        "configured": 4,
        "loaded": 2,
        "running": False,
        "readings": [],
    }
    assert "private" not in json.dumps(manager.get_summary())
    assert manager.registry.create.call_count == 3


def test_inventory_identity_matches_reload_and_registry_normalization(monkeypatch):
    manager = make_manager(
        [
            {"type": " TEST ", "name": ""},
            {"type": " TEST ", "name": " exact name "},
            {"name": "missing-type"},
        ],
        monkeypatch,
    )
    assert manager.get_summary()["inventory"] == [
        {"name": " TEST ", "type": "test", "enabled": True, "loaded": True},
        {"name": " exact name ", "type": "test", "enabled": True, "loaded": True},
        {"name": "missing-type", "type": "", "enabled": True, "loaded": False},
    ]
    assert [sensor.name for sensor in manager.sensors] == [" TEST ", " exact name "]


def test_inventory_loaded_is_independent_of_readings_and_alias_type(monkeypatch):
    manager = make_manager([{"type": "pymc_modem", "name": "legacy"}], monkeypatch)
    # Alias factories may instantiate a sensor with the canonical type.
    manager.sensors[0].sensor_type = "openhop_modem"
    reading = {"name": "legacy", "type": "openhop_modem", "ok": False, "data": {}}
    manager._latest_readings = [reading]
    summary = manager.get_summary()
    assert summary["readings"] == [reading]
    assert summary["inventory"] == [
        {"name": "legacy", "type": "pymc_modem", "enabled": True, "loaded": True}
    ]
    summary["inventory"][0]["loaded"] = False
    summary["inventory"].clear()
    assert manager.get_summary()["inventory"][0]["loaded"] is True


def test_reload_refreshes_inventory_without_stale_loaded_entries(monkeypatch):
    manager = make_manager([{"type": "test", "name": "awaiting"}], monkeypatch)
    manager.config["sensors"]["definitions"] = [
        {"type": "test", "name": "failed"},
        {"type": "test", "name": "disabled", "enabled": False},
    ]
    manager.reload()
    assert manager.get_summary()["inventory"] == [
        {"name": "failed", "type": "test", "enabled": True, "loaded": False},
        {"name": "disabled", "type": "test", "enabled": False, "loaded": False},
    ]
    assert manager.get_summary()["loaded"] == 0


def test_malformed_identity_cannot_smuggle_nested_settings(monkeypatch):
    manager = make_manager(
        [
            {"type": {"token": "private-token"}, "enabled": False},
            {"type": "test", "name": {"url": "https://private.example"}, "enabled": False},
        ],
        monkeypatch,
    )
    assert manager.get_summary()["inventory"] == [
        {"name": "sensor", "type": "", "enabled": False, "loaded": False},
        {"name": "sensor", "type": "test", "enabled": False, "loaded": False},
    ]
    assert "private" not in json.dumps(manager.get_summary())


def test_empty_inventory_and_legacy_definitions_key(monkeypatch):
    manager = make_manager([], monkeypatch)
    assert manager.get_summary()["inventory"] == []
    manager.config["sensors"]["sensors"] = [{"type": "test"}]
    manager.reload()
    assert manager.get_summary()["inventory"] == [
        {"name": "test", "type": "test", "enabled": True, "loaded": True}
    ]


def test_modem_inventory_has_only_safe_loaded_origin_and_effective_cadence(monkeypatch):
    from repeater.sensors.openhop_modem import OpenHopModemSensor

    registry = Mock()
    registry.create.side_effect = lambda sensor_type, name, config: OpenHopModemSensor(name, config)
    monkeypatch.setattr(SensorManager, "_load_sensor_module", lambda self, sensor_type: None)
    manager = SensorManager(
        {
            "sensors": {
                "enabled": True,
                "definitions": [
                    {
                        "type": "openhop_modem",
                        "name": "ether",
                        "settings": {
                            "base_url": "https://user:private-password@MODEM.local:80/private-path?private-query",
                            "token": "private-token",
                            "poll_interval_seconds": 7,
                        },
                    }
                ],
            }
        },
        registry=registry,
    )
    entry = manager.get_summary()["inventory"][0]
    assert entry["source_host"] == "modem.local"
    assert entry["poll_interval_seconds"] == 7
    assert "private" not in json.dumps(manager.get_summary())
    assert manager.get_summary()["readings"] == []


def test_modem_inventory_canonicalizes_ipv6_without_brackets(monkeypatch):
    registry = Mock()
    registry.create.return_value = SimpleNamespace(
        url="http://[2001:0DB8:0:0:0:0:0:1]:80/private?token=private",
        poll_interval_seconds=5,
    )
    monkeypatch.setattr(SensorManager, "_load_sensor_module", lambda self, sensor_type: None)
    manager = SensorManager(
        {"sensors": {"enabled": True, "definitions": [{"type": "openhop_modem", "name": "v6"}]}},
        registry=registry,
    )
    assert manager.get_summary()["inventory"][0]["source_host"] == "2001:db8::1"
    assert "private" not in json.dumps(manager.get_summary())


def test_stats_openapi_inventory_is_an_allowlisted_additive_field():
    path = Path(__file__).resolve().parents[1] / "repeater/web/openapi.yaml"
    document = yaml.safe_load(path.read_text())
    stats = document["paths"]["/stats"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    assert stats["properties"]["sensors"]["$ref"] == "#/components/schemas/SensorSummary"
    schemas = document["components"]["schemas"]
    inventory = schemas["SensorSummary"]["properties"]["inventory"]
    assert inventory["type"] == "array"
    assert inventory["items"]["$ref"] == "#/components/schemas/SensorInventoryEntry"
    entry = schemas["SensorInventoryEntry"]
    assert entry["additionalProperties"] is False
    assert set(entry["required"]) == {"name", "type", "enabled", "loaded"}
    assert {key: value["type"] for key, value in entry["properties"].items()} == {
        "name": "string",
        "type": "string",
        "enabled": "boolean",
        "loaded": "boolean",
        "source_host": "string",
        "poll_interval_seconds": "number",
    }
