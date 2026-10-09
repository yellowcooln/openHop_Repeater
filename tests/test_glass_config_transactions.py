"""Glass optimistic writes use the real persistence path and temporary config only."""

import asyncio
import copy
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from repeater.config_manager import ConfigManager
from tests import test_glass_job_handler as protocol_tests
from tests.test_glass_job_store import delivery

private_store = protocol_tests.private_store


def test_stale_revision_rejects_without_persisting_or_applying(tmp_path, monkeypatch):
    config = {"repeater": {"mode": "monitor", "node_name": "fixture"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    original = path.read_bytes()
    before = copy.deepcopy(config)
    manager = ConfigManager(str(path), config)
    live = Mock()
    monkeypatch.setattr(manager, "live_update_daemon", live)

    result = manager.update_and_save({"repeater": {"mode": "no_tx"}}, expected_revision="0" * 64)

    assert result["saved"] is False
    assert result["success"] is False
    assert result["error_code"] == "revision_conflict"
    assert path.read_bytes() == original
    assert config == before
    live.assert_not_called()


def test_external_file_change_is_not_overwritten_by_cached_revision(tmp_path, monkeypatch):
    config = {"repeater": {"mode": "monitor", "node_name": "fixture"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    manager = ConfigManager(str(path), config)
    revision = hashlib.sha256(
        yaml.safe_dump(config, sort_keys=True, allow_unicode=True).encode("utf-8")
    ).hexdigest()
    external = {"repeater": {"mode": "monitor", "node_name": "external-edit"}}
    path.write_text(yaml.safe_dump(external))
    before = path.read_bytes()
    live = Mock()
    monkeypatch.setattr(manager, "live_update_daemon", live)

    result = manager.update_and_save({"repeater": {"mode": "no_tx"}}, expected_revision=revision)

    assert result["saved"] is False
    assert result["error_code"] == "revision_conflict"
    assert path.read_bytes() == before
    live.assert_not_called()


def test_configuration_snapshot_uses_persisted_data_not_desired_memory(tmp_path):
    config = {"repeater": {"mode": "monitor", "node_name": "cached"}}
    saved = {"repeater": {"mode": "no_tx", "node_name": "saved"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(saved))
    manager = ConfigManager(str(path), config)
    snapshot = manager.configuration_snapshot()
    assert snapshot["saved"] == saved
    assert snapshot["revision"] != snapshot["memory_revision"]
    snapshot["saved"]["repeater"]["mode"] = "forward"
    assert yaml.safe_load(path.read_text()) == saved
    assert config["repeater"]["mode"] == "monitor"


def test_bad_saved_yaml_does_not_echo_private_values(tmp_path, caplog):
    config = {"repeater": {"mode": "monitor"}}
    path = tmp_path / "config.yaml"
    path.write_text("repeater: !synthetic-secret-marker {}\n")
    manager = ConfigManager(str(path), config)
    result = manager.update_and_save({"repeater": {"mode": "no_tx"}}, expected_revision="0" * 64)
    assert "synthetic-secret-marker" not in repr(result) + caplog.text
    assert result["error_code"] == "configuration_unavailable"
    assert result["saved"] is False


def mode_fixture(private_store, monkeypatch):
    value = protocol_tests.handler(private_store, monkeypatch)
    value.daemon_instance.config = copy.deepcopy(value.config)
    reload = Mock()
    value.daemon_instance.repeater_handler = SimpleNamespace(
        config=value.daemon_instance.config, reload_runtime_config=reload
    )
    path = private_store / "config.yaml"
    path.write_text(yaml.safe_dump(value.config))
    path.chmod(0o600)
    manager = ConfigManager(str(path), value.config, value.daemon_instance)
    value.config_manager = manager
    return value, manager, path, reload


def test_v2_mode_job_persists_applies_and_does_not_reexecute(private_store, monkeypatch):
    value, manager, path, reload = mode_fixture(private_store, monkeypatch)
    job = delivery()
    job["params"] = {"mode": "no_tx"}
    job["expected_revision"] = manager.configuration_snapshot()["revision"]

    sent = []

    def post(url, payload, *args):
        sent.append(payload)
        jobs = [job] if payload["capabilities"].get("set_mode") == 1 else []
        return protocol_tests.response(payload, jobs=jobs)

    monkeypatch.setattr(value, "_post_job_json", post)
    asyncio.run(value._inform_once())
    assert sent[0]["capabilities"].get("set_mode") == 1
    results = protocol_tests.ledger(value).pending_results()
    assert len(results) == 1
    assert results[0]["status"] == "succeeded"
    assert results[0]["persisted"] is True
    assert results[0]["applied"] is True
    assert results[0]["restart_required"] is False
    assert yaml.safe_load(path.read_text())["repeater"]["mode"] == "no_tx"
    assert value.daemon_instance.repeater_handler.config["repeater"]["mode"] == "no_tx"
    assert reload.call_count == 1
    asyncio.run(value._inform_once())
    assert protocol_tests.ledger(value).pending_results() == results
    assert reload.call_count == 1


def test_v2_config_read_reports_saved_and_effective_without_secrets(private_store, monkeypatch):
    value, manager, path, _ = mode_fixture(private_store, monkeypatch)
    saved = copy.deepcopy(value.config)
    saved["repeater"].update(mode="no_tx", password="never-export-synthetic-secret")
    saved["unknown_plugin"] = {"opaque": "never-export-synthetic-secret"}
    path.write_text(yaml.safe_dump(saved))
    query = delivery(False)
    query["action"] = "config.read"
    sent = []

    def post(url, payload, *args):
        sent.append(payload)
        queries = [query] if payload["capabilities"].get("config.read") == 1 else []
        return protocol_tests.response(payload, queries=queries)

    monkeypatch.setattr(value, "_post_job_json", post)
    asyncio.run(value._inform_once())
    assert sent[0]["capabilities"].get("config.read") == 1
    result = protocol_tests.ledger(value).pending_results()[0]
    assert result["status"] == "succeeded"
    details = result["details"]
    assert details["scope"] == "repeater.mode"
    assert details["saved_mode"] == "no_tx"
    assert details["configured_mode"] == "monitor"
    assert details["effective_mode"] == "monitor"
    assert details["revision"] == manager.configuration_snapshot()["revision"]
    assert "never-export-synthetic-secret" not in repr(result)


@pytest.mark.parametrize(
    "failure", ["save", "live", "stale", "missing", "readback", "daemon_mismatch", "superseded"],
)
def test_mode_failures_preserve_truthful_outcomes(private_store, monkeypatch, failure):
    value, manager, path, reload = mode_fixture(private_store, monkeypatch)
    job = delivery()
    job["params"] = {"mode": "no_tx"}
    job["expected_revision"] = manager.configuration_snapshot()["revision"]
    original = path.read_bytes()
    if failure == "save":
        monkeypatch.setattr(manager, "_persist_config", lambda _: False)
    elif failure == "live":
        monkeypatch.setattr(manager, "live_update_daemon", lambda _: False)
    elif failure == "daemon_mismatch":
        value.daemon_instance.repeater_handler.config = copy.deepcopy(value.daemon_instance.config)

        def partial_apply(_):
            value.daemon_instance.repeater_handler.config["repeater"]["mode"] = "no_tx"
            return True

        monkeypatch.setattr(manager, "live_update_daemon", partial_apply)
    elif failure == "stale":
        job["expected_revision"] = "0" * 64
    elif failure == "missing":
        job["expected_revision"] = None
    elif failure in {"readback", "superseded"}:
        real = manager.configuration_snapshot
        calls = 0

        def fail_after_save():
            nonlocal calls
            calls += 1
            if calls > 1:
                if failure == "readback":
                    raise ValueError("Configuration readback unavailable")
                changed = yaml.safe_load(path.read_text())
                changed["repeater"]["mode"] = "monitor"
                path.write_text(yaml.safe_dump(changed))
            return real()

        monkeypatch.setattr(manager, "configuration_snapshot", fail_after_save)
    monkeypatch.setattr(
        value,
        "_post_job_json",
        lambda _, payload, *args: protocol_tests.response(payload, jobs=[job]),
    )
    asyncio.run(value._inform_once())
    result = protocol_tests.ledger(value).pending_results()[0]
    if failure in {"save", "stale", "missing"}:
        assert result["persisted"] is False and result["applied"] is False
        assert path.read_bytes() == original
        assert reload.call_count == 0
    elif failure in {"live", "daemon_mismatch"}:
        assert result["status"] == "failed"
        assert result["persisted"] is True and result["applied"] is False
        assert result["restart_required"] is True
    elif failure == "superseded":
        assert result["status"] == "conflict"
        assert result["details"]["saved_mode"] == "monitor"
        assert result["details"]["effective_mode"] == "no_tx"
    else:
        assert result["status"] == "unknown"
        assert result["persisted"] is True
        assert result["error_code"] == "readback_unavailable"
