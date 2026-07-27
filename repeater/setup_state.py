"""First-run setup state and legacy migration helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

_BOOTSTRAP_HASH_PREFIX = "sha256:"


class BootstrapSecretManager:
    """Create and validate a local, one-time first-run bootstrap credential."""

    def __init__(
        self,
        *,
        config: dict,
        config_manager,
        storage_dir: str | Path,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.config = config
        self.config_manager = config_manager
        self.delivery_path = Path(storage_dir) / "bootstrap-token"
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._lock = threading.Lock()
        self._claim = None

    @staticmethod
    def _digest(token: str) -> str:
        return _BOOTSTRAP_HASH_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def clear_hash(config: dict) -> None:
        setup = config.get("setup") if isinstance(config, dict) else None
        if isinstance(setup, dict):
            setup.pop("bootstrap_secret_hash", None)

    def _write_delivery_token(self, token: str) -> None:
        self.delivery_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.delivery_path.parent, 0o700)
        fd, temporary_path = tempfile.mkstemp(
            prefix=".bootstrap-token-", dir=self.delivery_path.parent
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(token + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.delivery_path)
            os.chmod(self.delivery_path, 0o600)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise

    def ensure(self) -> bool:
        """Ensure an incomplete installation has a private local bootstrap token."""
        with self._lock:
            needs_setup, _ = setup_status(self.config)
            setup = self.config.setdefault("setup", {})
            if not needs_setup:
                if isinstance(setup, dict) and "bootstrap_secret_hash" in setup:
                    setup.pop("bootstrap_secret_hash", None)
                    self.config_manager.save_to_file()
                self.delivery_path.unlink(missing_ok=True)
                return False

            configured_digest = setup.get("bootstrap_secret_hash")
            if isinstance(configured_digest, str) and self.delivery_path.is_file():
                try:
                    delivered = self.delivery_path.read_text(encoding="utf-8").strip()
                except OSError:
                    delivered = ""
                if delivered and hmac.compare_digest(configured_digest, self._digest(delivered)):
                    os.chmod(self.delivery_path, 0o600)
                    return True

            token = self._token_factory()
            if not isinstance(token, str) or len(token) < 20:
                raise ValueError("Bootstrap token generator returned an invalid token")
            previous_digest = setup.get("bootstrap_secret_hash")
            self._write_delivery_token(token)
            setup["bootstrap_secret_hash"] = self._digest(token)
            if not self.config_manager.save_to_file():
                if previous_digest is None:
                    setup.pop("bootstrap_secret_hash", None)
                else:
                    setup["bootstrap_secret_hash"] = previous_digest
                self.delivery_path.unlink(missing_ok=True)
                raise RuntimeError("Failed to persist bootstrap credential digest")
            return True

    def claim(self, token: str | None):
        """Reserve a valid token for one in-process bootstrap mutation."""
        with self._lock:
            if self._claim is not None or not isinstance(token, str):
                return None
            setup = self.config.get("setup", {})
            expected = setup.get("bootstrap_secret_hash") if isinstance(setup, dict) else None
            if not isinstance(expected, str) or not hmac.compare_digest(expected, self._digest(token)):
                return None
            self._claim = object()
            return self._claim

    def release(self, claim) -> None:
        with self._lock:
            if claim is self._claim:
                self._claim = None

    def retire(self, claim) -> None:
        """Retire a claimed token after setup completion has persisted."""
        with self._lock:
            if claim is not self._claim:
                raise ValueError("Bootstrap claim is not active")
            self.delivery_path.unlink(missing_ok=True)
            self._claim = None


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
