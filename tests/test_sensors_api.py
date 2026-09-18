

# ---------------------------------------------------------------------------
# API endpoint tests for sensors_config, update_sensors_config, sensors_restart
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch

import pytest

import repeater.web.api_endpoints as api_module


class _MockConfigManager:
    """Minimal ConfigManager stub that records saves."""

    def __init__(self, config: dict):
        self.config = config
        self.saved = False
        self.save_error = None

    def save_to_file(self) -> bool:
        if self.save_error:
            return False
        self.saved = True
        return True


def _make_handler(config: dict | None = None) -> api_module.APIEndpoints:
    """Create an APIEndpoints handler with mocked dependencies."""
    cfg = config or {}
    cm = _MockConfigManager(cfg)

    handler = api_module.APIEndpoints()
    handler.config = cfg
    handler.config_manager = cm
    handler._config_path = "/tmp/test_config.yaml"
    handler.event_loop = None

    # Mock _set_cors_headers and _require_post
    handler._set_cors_headers = MagicMock()
    handler._require_post = MagicMock()

    # Mock _success and _error to return dicts directly
    handler._success = lambda data, **kw: {"success": True, "data": data}
    handler._error = lambda error: {"success": False, "error": str(error)}

    return handler


def _make_cherrypy_mock(method: str = "GET"):
    """Create a cherrypy mock with proper request/response attributes."""
    cherrypy_mock = MagicMock()
    cherrypy_mock.request.method = method
    cherrypy_mock.request.json = None
    cherrypy_mock.request.params = {}
    cherrypy_mock.response = MagicMock()
    cherrypy_mock.HTTPError = Exception
    return cherrypy_mock


# -- GET /api/sensors_config --

def test_sensors_config_returns_config():
    cfg = {
        "sensors": {
            "enabled": True,
            "poll_interval_seconds": 15.0,
            "auto_install_packages": False,
            "definitions": [
                {"type": "hardware_stats", "name": "system-health", "enabled": True},
            ],
        }
    }
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("GET")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.sensors_config()

    assert result["success"] is True
    assert result["data"]["enabled"] is True
    assert result["data"]["poll_interval_seconds"] == 15.0
    assert result["data"]["auto_install_packages"] is False
    assert len(result["data"]["definitions"]) == 1
    assert result["data"]["definitions"][0]["type"] == "hardware_stats"


def test_sensors_config_missing_section():
    cfg = {}
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("GET")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.sensors_config()

    assert result["success"] is True
    assert result["data"]["enabled"] is False
    assert result["data"]["poll_interval_seconds"] == 30.0
    assert result["data"]["definitions"] == []


def test_sensors_config_non_get():
    cfg = {}
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("POST")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        with pytest.raises(Exception) as exc_info:
            handler.sensors_config()
        assert "405" in str(exc_info.value)


# -- POST /api/sensors_config --

def test_update_sensors_config_success():
    cfg = {
        "sensors": {
            "enabled": True,
            "poll_interval_seconds": 10.0,
            "auto_install_packages": True,
            "definitions": [
                {"type": "hardware_stats", "name": "system-health", "enabled": True},
            ],
        }
    }
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("POST")
    cherrypy_mock.request.json = {
        "enabled": True,
        "poll_interval_seconds": 20.0,
        "auto_install_packages": True,
        "definitions": [
            {"type": "hardware_stats", "name": "system-health", "enabled": True},
            {"type": "bme280", "name": "room-temp", "enabled": True, "settings": {"i2c_address": 76, "bus_number": 1}},
        ],
    }

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.update_sensors_config()

    assert result["success"] is True
    assert handler.config_manager.saved is True
    assert cfg["sensors"]["poll_interval_seconds"] == 20.0
    assert len(cfg["sensors"]["definitions"]) == 2


def test_update_sensors_config_missing_definitions():
    cfg = {"sensors": {"enabled": True, "definitions": []}}
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("POST")
    cherrypy_mock.request.json = {"enabled": True}

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.update_sensors_config()

    assert result["success"] is False
    assert "definitions" in result["error"].lower()


def test_update_sensors_config_missing_type():
    cfg = {"sensors": {"enabled": True, "definitions": []}}
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("POST")
    cherrypy_mock.request.json = {
        "enabled": True,
        "definitions": [{"name": "my-sensor"}],  # missing type
    }

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.update_sensors_config()

    assert result["success"] is False
    assert "type" in result["error"].lower()


def test_update_sensors_config_missing_name():
    cfg = {"sensors": {"enabled": True, "definitions": []}}
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("POST")
    cherrypy_mock.request.json = {
        "enabled": True,
        "definitions": [{"type": "hardware_stats"}],  # missing name
    }

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.update_sensors_config()

    assert result["success"] is False
    assert "name" in result["error"].lower()


def test_update_sensors_config_non_post():
    cfg = {"sensors": {"enabled": True, "definitions": []}}
    handler = _make_handler(cfg)
    cherrypy_mock = _make_cherrypy_mock("GET")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        with pytest.raises(Exception) as exc_info:
            handler.update_sensors_config()
        assert "405" in str(exc_info.value)


def test_update_sensors_config_save_failure():
    cfg = {"sensors": {"enabled": True, "definitions": []}}
    handler = _make_handler(cfg)
    handler.config_manager.save_error = IOError("disk full")

    cherrypy_mock = _make_cherrypy_mock("POST")
    cherrypy_mock.request.json = {
        "enabled": True,
        "definitions": [],
    }

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        result = handler.update_sensors_config()

    assert result["success"] is False
    assert "Failed to save" in result["error"]


# -- POST /api/sensors_restart --

def test_sensors_restart_success():
    handler = _make_handler({})
    cherrypy_mock = _make_cherrypy_mock("POST")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        with patch("repeater.service_utils.restart_service") as mock_restart:
            mock_restart.return_value = (True, "Service restarted")
            result = handler.sensors_restart()

    assert result["success"] is True
    mock_restart.assert_called_once()


def test_sensors_restart_failure():
    handler = _make_handler({})
    cherrypy_mock = _make_cherrypy_mock("POST")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        with patch("repeater.service_utils.restart_service") as mock_restart:
            mock_restart.return_value = (False, "Restart failed")
            result = handler.sensors_restart()

    assert result["success"] is False
    assert "Restart failed" in result["error"]


def test_sensors_restart_non_post():
    handler = _make_handler({})
    cherrypy_mock = _make_cherrypy_mock("GET")

    with patch("repeater.web.api_endpoints.cherrypy", cherrypy_mock):
        with pytest.raises(Exception) as exc_info:
            handler.sensors_restart()
        assert "405" in str(exc_info.value)
