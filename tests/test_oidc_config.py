from dataclasses import FrozenInstanceError

import pytest

from repeater.web.auth.config import AuthConfigError, normalize_auth_settings


def _oidc(**overrides):
    value = {
        "issuer": "https://auth.example.com/application/o/openhop/",
        "client_id": "openhop",
        "client_secret": "secret",
        "external_url": "https://repeater.example.com/ui",
        "scopes": ["openid", "profile", "email"],
        "provider_name": "Authentik",
        "authorization": {"rules": [{"claim": "realm_access.roles", "any_of": ["admin"]}]},
    }
    value.update(overrides)
    return value


def test_absent_web_auth_defaults_to_local_and_does_not_mutate_input():
    raw = {"web": {"web_path": "/tmp/ui"}}
    settings = normalize_auth_settings(raw)

    assert settings.mode == "local"
    assert settings.local_enabled is True
    assert settings.oidc_enabled is False
    assert "auth" not in raw["web"]


@pytest.mark.parametrize(
    ("mode", "local", "oidc"),
    [("local", True, False), ("local_and_oidc", True, True), ("oidc", False, True)],
)
def test_valid_modes(mode, local, oidc):
    cfg = {"web": {"auth": {"mode": mode, "oidc": _oidc()}}}
    settings = normalize_auth_settings(cfg)

    assert settings.mode == mode
    assert settings.local_enabled is local
    assert settings.oidc_enabled is oidc
    assert settings.oidc is None if not oidc else settings.oidc.client_id == "openhop"
    if settings.oidc:
        assert settings.oidc.external_url == "https://repeater.example.com"
        assert settings.oidc.callback_url == "https://repeater.example.com/auth/oidc/callback"


def test_immutable_and_defensively_copied():
    cfg = {"web": {"auth": {"mode": "oidc", "oidc": _oidc(scopes=["openid"])}}}
    settings = normalize_auth_settings(cfg)
    cfg["web"]["auth"]["oidc"]["scopes"].append("offline_access")
    cfg["web"]["auth"]["oidc"]["authorization"]["rules"][0]["any_of"].append("other")

    assert settings.oidc.scopes == ("openid",)
    assert settings.oidc.authorization_rules[0].any_of == ("admin",)
    with pytest.raises(FrozenInstanceError):
        settings.mode = "local"


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"mode": "ldap"}, "web.auth.mode"),
        ({"mode": "oidc", "oidc": _oidc(issuer="")}, "issuer"),
        ({"mode": "oidc", "oidc": _oidc(client_id="")}, "client_id"),
        ({"mode": "oidc", "oidc": _oidc(client_secret="")}, "client_secret"),
        ({"mode": "oidc", "oidc": _oidc(external_url="")}, "external_url"),
        ({"mode": "oidc", "oidc": _oidc(scopes=["profile"])}, "openid"),
        ({"mode": "oidc", "oidc": _oidc(authorization={"rules": []})}, "rule"),
        ({"mode": "oidc", "oidc": _oidc(issuer="http://auth.example.com")}, "HTTPS"),
        ({"mode": "oidc", "oidc": _oidc(external_url="http://repeater.example.com")}, "HTTPS"),
        (
            {
                "mode": "oidc",
                "oidc": _oidc(authorization={"rules": [{"claim": "bad..x", "any_of": ["x"]}]}),
            },
            "claim",
        ),
        (
            {
                "mode": "oidc",
                "oidc": _oidc(authorization={"rules": [{"claim": "groups", "any_of": []}]}),
            },
            "any_of",
        ),
        (
            {
                "mode": "oidc",
                "oidc": _oidc(
                    authorization={"rules": [{"claim": "groups", "any_of": [{"x": "y"}]}]}
                ),
            },
            "scalar",
        ),
    ],
)
def test_invalid_settings_are_actionable(patch, message):
    with pytest.raises(AuthConfigError, match=message):
        normalize_auth_settings({"web": {"auth": patch}})


def test_loopback_http_is_allowed_for_development():
    settings = normalize_auth_settings(
        {
            "web": {
                "auth": {
                    "mode": "oidc",
                    "oidc": _oidc(
                        issuer="http://127.0.0.1:9000/application/o/openhop/",
                        external_url="http://localhost:8000",
                    ),
                }
            }
        }
    )

    assert settings.oidc.issuer == "http://127.0.0.1:9000/application/o/openhop/"
