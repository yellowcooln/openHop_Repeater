"""First-run setup state and legacy migration helpers."""

from __future__ import annotations


def legacy_setup_status(config: dict) -> tuple[bool, dict]:
    """Return the pre-flag setup decision for backward compatibility."""
    repeater = config.get("repeater", {}) if isinstance(config, dict) else {}
    repeater = repeater if isinstance(repeater, dict) else {}
    security = repeater.get("security", {})
    security = security if isinstance(security, dict) else {}

    node_name = repeater.get("node_name", "")
    has_default_name = node_name in ("mesh-repeater-01", "")
    admin_password = security.get("admin_password", "")
    has_default_password = admin_password in ("admin123", "")

    radio_type_raw = config.get("radio_type") if isinstance(config, dict) else None
    radio_type = "" if radio_type_raw is None else str(radio_type_raw).lower().strip()
    radio_not_configured = radio_type in ("", "none", "null", "disabled", "off", "no_radio")

    reasons = {
        "default_name": has_default_name,
        "default_password": has_default_password,
        "radio_not_configured": radio_not_configured,
    }
    return has_default_name or has_default_password or radio_not_configured, reasons


def setup_status(config: dict) -> tuple[bool, dict]:
    """Return whether public first-run setup remains available."""
    needs_setup, reasons = legacy_setup_status(config)
    setup = config.get("setup", {}) if isinstance(config, dict) else {}
    setup = setup if isinstance(setup, dict) else {}
    completed = setup.get("completed")

    if isinstance(completed, bool):
        return not completed, reasons

    return needs_setup, reasons


def migrate_legacy_setup_completion(config: dict) -> bool:
    """Mark a legacy config complete only when its old setup test was complete."""
    if not isinstance(config, dict):
        return False

    setup = config.get("setup")
    if isinstance(setup, dict) and isinstance(setup.get("completed"), bool):
        return False

    needs_setup, _ = legacy_setup_status(config)
    if needs_setup:
        return False

    if not isinstance(setup, dict):
        setup = {}
        config["setup"] = setup
    setup["completed"] = True
    return True
