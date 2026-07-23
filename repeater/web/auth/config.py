from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse


class AuthConfigError(ValueError):
    """Raised when web.auth configuration is invalid."""


JSONScalar = str | int | float | bool | None
VALID_MODES = {"local", "local_and_oidc", "oidc"}


@dataclass(frozen=True)
class ClaimRule:
    claim: str
    any_of: tuple[JSONScalar, ...]


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    client_id: str
    client_secret: str
    external_url: str
    scopes: tuple[str, ...]
    provider_name: str
    authorization_rules: tuple[ClaimRule, ...]
    timeout_seconds: float = 5.0
    discovery_ttl_seconds: int = 300
    jwks_ttl_seconds: int = 300

    @property
    def callback_url(self) -> str:
        return f"{self.external_url}/auth/oidc/callback"


@dataclass(frozen=True)
class AuthSettings:
    mode: str
    oidc: OIDCSettings | None = None

    @property
    def local_enabled(self) -> bool:
        return self.mode in {"local", "local_and_oidc"}

    @property
    def oidc_enabled(self) -> bool:
        return self.mode in {"local_and_oidc", "oidc"}


def normalize_auth_settings(config: dict[str, Any] | None) -> AuthSettings:
    web = config.get("web", {}) if isinstance(config, dict) else {}
    auth = web.get("auth") if isinstance(web, dict) else None
    if auth is None:
        return AuthSettings(mode="local")
    if not isinstance(auth, dict):
        raise AuthConfigError("web.auth must be a mapping")

    mode = str(auth.get("mode", "local")).strip()
    if mode not in VALID_MODES:
        raise AuthConfigError("web.auth.mode must be one of: local, local_and_oidc, oidc")

    oidc = None
    if mode in {"local_and_oidc", "oidc"}:
        oidc = _normalize_oidc_settings(auth.get("oidc"))
    return AuthSettings(mode=mode, oidc=oidc)


def _normalize_oidc_settings(raw: Any) -> OIDCSettings:
    if not isinstance(raw, dict):
        raise AuthConfigError("web.auth.oidc is required for OIDC auth modes")

    issuer = _required_string(raw, "issuer")
    client_id = _required_string(raw, "client_id")
    client_secret = _required_string(raw, "client_secret")
    external_url = _normalize_external_url(_required_string(raw, "external_url"))
    scopes = _normalize_scopes(raw.get("scopes"))
    provider_name = str(raw.get("provider_name") or "OIDC").strip() or "OIDC"
    rules = _normalize_rules(raw.get("authorization"))

    _validate_url("issuer", issuer, allow_path=True)
    _validate_url("external_url", external_url, allow_path=False)
    if "openid" not in scopes:
        raise AuthConfigError("web.auth.oidc.scopes must include openid")

    return OIDCSettings(
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        external_url=external_url,
        scopes=scopes,
        provider_name=provider_name,
        authorization_rules=rules,
        timeout_seconds=float(raw.get("timeout_seconds", 5.0)),
        discovery_ttl_seconds=int(raw.get("discovery_ttl_seconds", 300)),
        jwks_ttl_seconds=int(raw.get("jwks_ttl_seconds", 300)),
    )


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuthConfigError(f"web.auth.oidc.{key} is required")
    return value.strip()


def _normalize_scopes(value: Any) -> tuple[str, ...]:
    if value is None:
        raise AuthConfigError("web.auth.oidc.scopes is required")
    if not isinstance(value, (list, tuple)):
        raise AuthConfigError("web.auth.oidc.scopes must be a list")
    scopes = tuple(str(item).strip() for item in value if isinstance(item, str) and item.strip())
    if not scopes:
        raise AuthConfigError("web.auth.oidc.scopes must not be empty")
    if "offline_access" in scopes:
        raise AuthConfigError("web.auth.oidc.scopes must not include offline_access")
    return scopes


def _normalize_rules(authz: Any) -> tuple[ClaimRule, ...]:
    if not isinstance(authz, dict):
        raise AuthConfigError("web.auth.oidc.authorization is required")
    raw_rules = authz.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise AuthConfigError("web.auth.oidc.authorization.rules must include at least one rule")

    rules: list[ClaimRule] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise AuthConfigError(f"authorization rule {index} must be a mapping")
        claim = raw_rule.get("claim")
        if not isinstance(claim, str) or not _valid_claim_path(claim):
            raise AuthConfigError(f"authorization rule {index} has invalid claim path")
        any_of = raw_rule.get("any_of")
        if not isinstance(any_of, list) or not any_of:
            raise AuthConfigError(f"authorization rule {index} any_of must not be empty")
        if any(not _is_json_scalar(item) for item in any_of):
            raise AuthConfigError(f"authorization rule {index} any_of values must be JSON scalar")
        rules.append(ClaimRule(claim=claim, any_of=tuple(any_of)))
    return tuple(rules)


def _is_json_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _valid_claim_path(path: str) -> bool:
    parts = path.split(".")
    return bool(parts) and all(part.replace("_", "a").replace("-", "a").isalnum() for part in parts)


def _normalize_external_url(url: str) -> str:
    parsed = urlparse(url)
    normalized = parsed._replace(path="", params="", query="", fragment="")
    return urlunparse(normalized).rstrip("/")


def _validate_url(name: str, url: str, *, allow_path: bool) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise AuthConfigError(f"web.auth.oidc.{name} must be an absolute URL")
    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
        raise AuthConfigError(
            f"web.auth.oidc.{name} must use HTTPS except loopback development URLs"
        )
    if not allow_path and parsed.path not in {"", "/"}:
        raise AuthConfigError(f"web.auth.oidc.{name} must not include a path")


def _is_loopback_host(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}
