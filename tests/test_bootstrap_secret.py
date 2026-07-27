import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import cherrypy
import pytest
import yaml

from repeater.setup_state import BootstrapSecretManager
from repeater.web.api_endpoints import APIEndpoints

TOKEN = "local-bootstrap-secret"


def _first_run_config():
    return {
        "setup": {"completed": False},
        "repeater": {
            "node_name": "mesh-repeater-01",
            "security": {"admin_password": "admin123"},
        },
        "radio_type": "none",
    }


def _manager(tmp_path, config):
    config_manager = MagicMock()
    config_manager.save_to_file.return_value = True
    manager = BootstrapSecretManager(
        config=config,
        config_manager=config_manager,
        storage_dir=tmp_path,
        token_factory=lambda: TOKEN,
    )
    return manager, config_manager


def _set_request(monkeypatch, *, headers=None, body=None, user=None):
    request = SimpleNamespace(
        method="POST",
        headers=headers or {},
        json=body or {},
        user=user,
        params={},
    )
    response = SimpleNamespace(status=200, headers={})
    monkeypatch.setattr(cherrypy, "request", request, raising=False)
    monkeypatch.setattr(cherrypy, "response", response, raising=False)
    monkeypatch.setattr(cherrypy, "config", {}, raising=False)
    return request, response


def test_bootstrap_secret_is_generated_once_stored_as_digest_and_delivered_privately(tmp_path):
    config = _first_run_config()
    manager, config_manager = _manager(tmp_path, config)

    assert manager.ensure() is True

    digest = config["setup"]["bootstrap_secret_hash"]
    assert digest.startswith("sha256:")
    assert TOKEN not in yaml.safe_dump(config)
    assert manager.delivery_path.read_text(encoding="utf-8").strip() == TOKEN
    assert os.stat(manager.delivery_path).st_mode & 0o777 == 0o600
    config_manager.save_to_file.assert_called_once_with()

    second = BootstrapSecretManager(
        config=config,
        config_manager=config_manager,
        storage_dir=tmp_path,
        token_factory=lambda: "must-not-rotate",
    )
    assert second.ensure() is True
    assert second.delivery_path.read_text(encoding="utf-8").strip() == TOKEN
    config_manager.save_to_file.assert_called_once_with()


def test_bootstrap_claim_is_constant_time_single_holder_and_releasable(tmp_path):
    config = _first_run_config()
    manager, _ = _manager(tmp_path, config)
    manager.ensure()

    assert manager.claim("wrong") is None
    claim = manager.claim(TOKEN)
    assert claim is not None
    assert manager.claim(TOKEN) is None

    manager.release(claim)
    retry = manager.claim(TOKEN)
    assert retry is not None
    manager.retire(retry)
    assert not manager.delivery_path.exists()


def test_completed_setup_does_not_generate_bootstrap_secret(tmp_path):
    config = _first_run_config()
    config["setup"]["completed"] = True
    manager, config_manager = _manager(tmp_path, config)

    assert manager.ensure() is False
    assert "bootstrap_secret_hash" not in config["setup"]
    assert not manager.delivery_path.exists()
    config_manager.save_to_file.assert_not_called()


def test_setup_wizard_requires_bootstrap_token_before_validating_payload(tmp_path, monkeypatch):
    config = _first_run_config()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    manager, _ = _manager(tmp_path, config)
    manager.ensure()
    api = APIEndpoints(
        config=config,
        config_path=str(config_path),
        bootstrap_secret_manager=manager,
    )

    _set_request(monkeypatch, body={})
    with pytest.raises(cherrypy.HTTPError) as missing:
        api.setup_wizard()
    assert missing.value.status == 401

    _set_request(monkeypatch, headers={"X-Bootstrap-Token": "wrong"}, body={})
    with pytest.raises(cherrypy.HTTPError) as invalid:
        api.setup_wizard()
    assert invalid.value.status == 401

    _set_request(monkeypatch, headers={"X-Bootstrap-Token": TOKEN}, body={})
    result = api.setup_wizard()
    assert result == {"success": False, "error": "Node name is required"}
    # Validation failures release the one-at-a-time claim so the operator can retry.
    assert manager.claim(TOKEN) is not None


def test_needs_setup_advertises_bootstrap_requirement_without_secret_metadata(tmp_path):
    config = _first_run_config()
    config_path = tmp_path / "config.yaml"
    manager, _ = _manager(tmp_path, config)
    manager.ensure()
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    api = APIEndpoints(
        config=config,
        config_path=str(config_path),
        bootstrap_secret_manager=manager,
    )

    result = api.needs_setup()

    assert result["needs_setup"] is True
    assert result["bootstrap_required"] is True
    serialized = yaml.safe_dump(result)
    assert TOKEN not in serialized
    assert "bootstrap_secret_hash" not in serialized
    assert "bootstrap-token" not in serialized


def test_anonymous_bootstrap_import_filters_privileged_sections(tmp_path, monkeypatch):
    config = _first_run_config()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    manager, _ = _manager(tmp_path, config)
    manager.ensure()
    api = APIEndpoints(
        config=config,
        config_path=str(config_path),
        bootstrap_secret_manager=manager,
    )
    api.config_manager.save_to_file = MagicMock(return_value=True)
    api.config_manager.update_and_save = MagicMock(return_value={"success": True})
    _set_request(
        monkeypatch,
        headers={"X-Bootstrap-Token": TOKEN},
        body={
            "config": {
                "repeater": {
                    "node_name": "restored-name",
                    "latitude": 42.1,
                    "longitude": -71.2,
                    "security": {"admin_password": "attacker-password"},
                    "identity_key": "AA" * 32,
                },
                "web": {"auth": {"mode": "local"}},
                "pymc_tcp": {"host": "attacker", "token": "attacker-token"},
                "radio": {"tx_power": 22},
                "identities": {"companions": [{"name": "attacker"}]},
            }
        },
    )

    result = api.config_import()

    assert result["success"] is True
    assert result["sections_updated"] == ["repeater"]
    assert config["repeater"]["node_name"] == "restored-name"
    assert config["repeater"]["latitude"] == 42.1
    assert config["repeater"]["longitude"] == -71.2
    assert config["repeater"]["security"]["admin_password"] == "admin123"
    assert "identity_key" not in config["repeater"]
    assert "web" not in config
    assert "pymc_tcp" not in config
    assert "radio" not in config
    assert "identities" not in config
    assert config["setup"]["completed"] is False


def test_bootstrap_import_never_marks_setup_complete_from_legacy_values(tmp_path, monkeypatch):
    config = _first_run_config()
    config["repeater"]["node_name"] = "configured-name"
    config["repeater"]["security"]["admin_password"] = "configured-password"
    config["radio_type"] = "pymc_tcp"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    manager, _ = _manager(tmp_path, config)
    manager.ensure()
    api = APIEndpoints(
        config=config,
        config_path=str(config_path),
        bootstrap_secret_manager=manager,
    )
    api.config_manager.save_to_file = MagicMock(return_value=True)
    api.config_manager.update_and_save = MagicMock(return_value={"success": True})
    _set_request(
        monkeypatch,
        headers={"X-Bootstrap-Token": TOKEN},
        body={"config": {"repeater": {"node_name": "restored-name"}}},
    )

    result = api.config_import()

    assert result["success"] is True
    assert config["setup"]["completed"] is False
    assert "bootstrap_secret_hash" in config["setup"]
    assert manager.delivery_path.exists()


def test_anonymous_config_import_requires_bootstrap_token(tmp_path, monkeypatch):
    config = _first_run_config()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    manager, _ = _manager(tmp_path, config)
    manager.ensure()
    api = APIEndpoints(
        config=config,
        config_path=str(config_path),
        bootstrap_secret_manager=manager,
    )
    _set_request(monkeypatch, body={"config": {"repeater": {"node_name": "x"}}})

    with pytest.raises(cherrypy.HTTPError) as missing:
        api.config_import()

    assert missing.value.status == 401
