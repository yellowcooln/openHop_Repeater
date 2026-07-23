import io
import json
from types import SimpleNamespace
from urllib.parse import urlparse

import cherrypy
import pytest

from repeater.web.auth.oidc_client import NormalizedOIDCIdentity, OIDCProviderError
from repeater.web.auth_endpoints import AuthEndpoints


def oidc_config(mode="local_and_oidc"):
    return {
        "web": {
            "auth": {
                "mode": mode,
                "oidc": {
                    "issuer": "https://auth.example.com/application/o/openhop/",
                    "client_id": "openhop",
                    "client_secret": "secret",
                    "external_url": "https://repeater.example.com",
                    "provider_name": "Authentik",
                    "scopes": ["openid", "profile", "email"],
                    "authorization": {"rules": [{"claim": "groups", "any_of": ["openhop-admins"]}]},
                },
            }
        },
        "repeater": {"security": {"admin_password": "local-password"}},
    }


def cp_ctx(monkeypatch, method="GET", params=None, body=b""):
    req = SimpleNamespace(
        method=method,
        params=params or {},
        body=io.BytesIO(body),
        headers={},
        app=SimpleNamespace(script_name=""),
        base="http://127.0.0.1",
        path_info="/auth/oidc/start",
        is_index=False,
        script_name="",
    )
    resp = SimpleNamespace(status=200, headers={})
    monkeypatch.setattr(cherrypy, "request", req, raising=False)
    monkeypatch.setattr(cherrypy, "response", resp, raising=False)
    return req, resp


def jwt_handler():
    return SimpleNamespace(create_jwt=lambda *args, **kwargs: "internal-jwt", expiry_minutes=15)


class FakeOIDCClient:
    def __init__(self):
        self.exchanged = None
        self.validated = None

    def create_pkce(self):
        return "verifier", "challenge"

    def authorization_url(self, *, state, nonce, code_challenge):
        return f"https://auth.example.com/authorize?state={state}&nonce={nonce}&code_challenge={code_challenge}"

    def exchange_code(self, code, code_verifier):
        self.exchanged = (code, code_verifier)
        return {"id_token": "id-token"}

    def validate_id_token(self, id_token, *, nonce):
        self.validated = (id_token, nonce)
        return NormalizedOIDCIdentity(
            subject="alice",
            issuer="https://auth.example.com/application/o/openhop/",
            oidc_subject="stable-sub",
            session_exp=2000000000,
            claims={"groups": ["openhop-admins"]},
        )


def test_auth_methods_metadata_all_modes(monkeypatch):
    for mode, local, oidc in [
        ("local", True, False),
        ("local_and_oidc", True, True),
        ("oidc", False, True),
    ]:
        cfg = {} if mode == "local" else oidc_config(mode)
        cp_ctx(monkeypatch)
        auth = AuthEndpoints(cfg, jwt_handler(), token_manager=object())
        out = auth.methods()

        assert out["success"] is True
        assert out["local"] is local
        assert out["oidc"] is oidc
        assert ("oidc_provider_name" in out) is oidc


def test_local_mode_oidc_flow_not_usable(monkeypatch):
    cp_ctx(monkeypatch, params={"client_id": "c", "return_to": "/"})
    auth = AuthEndpoints({}, jwt_handler(), token_manager=object())

    with pytest.raises(cherrypy.HTTPError) as exc:
        auth.oidc.start()

    assert exc.value.status == 404


def test_oidc_mode_rejects_local_login_and_mixed_allows(monkeypatch):
    cp_ctx(
        monkeypatch,
        method="POST",
        body=json.dumps(
            {"username": "admin", "password": "local-password", "client_id": "c"}
        ).encode(),
    )
    oidc_only = AuthEndpoints(oidc_config("oidc"), jwt_handler(), token_manager=object())
    out = json.loads(oidc_only.login().decode())
    assert out["success"] is False
    assert out["error_code"] == "local_login_disabled"
    assert cherrypy.response.status == 403

    cp_ctx(
        monkeypatch,
        method="POST",
        body=json.dumps(
            {"username": "admin", "password": "local-password", "client_id": "c"}
        ).encode(),
    )
    mixed = AuthEndpoints(oidc_config("local_and_oidc"), jwt_handler(), token_manager=object())
    out = json.loads(mixed.login().decode())
    assert out["success"] is True


def test_start_callback_exchange_happy_path_and_replay(monkeypatch):
    fake_client = FakeOIDCClient()
    auth = AuthEndpoints(
        oidc_config(),
        jwt_handler(),
        token_manager=object(),
        oidc_client_factory=lambda _settings: fake_client,
    )

    cp_ctx(monkeypatch, params={"client_id": "browser-client", "return_to": "/dashboard"})
    with pytest.raises(cherrypy.HTTPRedirect) as start:
        auth.oidc.start()
    assert start.value.urls[0].startswith("https://auth.example.com/authorize?")
    state = start.value.urls[0].split("state=", 1)[1].split("&", 1)[0]

    cp_ctx(monkeypatch, params={"state": state, "code": "auth-code"})
    with pytest.raises(cherrypy.HTTPRedirect) as callback:
        auth.oidc.callback()
    callback_url = urlparse(callback.value.urls[0])
    assert callback_url.path == "/dashboard"
    assert callback_url.query.startswith("oidc_exchange=")
    exchange_code = callback_url.query.split("oidc_exchange=", 1)[1]
    assert fake_client.exchanged == ("auth-code", "verifier")
    assert fake_client.validated[0] == "id-token"
    assert fake_client.validated[1]

    cp_ctx(
        monkeypatch,
        method="POST",
        body=json.dumps({"code": exchange_code, "client_id": "browser-client"}).encode(),
    )
    out = json.loads(auth.oidc.exchange().decode())
    assert out["success"] is True
    assert out["token"] == "internal-jwt"

    cp_ctx(
        monkeypatch,
        method="POST",
        body=json.dumps({"code": exchange_code, "client_id": "browser-client"}).encode(),
    )
    out = json.loads(auth.oidc.exchange().decode())
    assert out["success"] is False
    assert cherrypy.response.status == 401


@pytest.mark.parametrize("return_to", ["https://evil.example/", "//evil.example/", "dashboard"])
def test_start_rejects_unsafe_return_paths(monkeypatch, return_to):
    auth = AuthEndpoints(
        oidc_config(),
        jwt_handler(),
        token_manager=object(),
        oidc_client_factory=lambda _settings: FakeOIDCClient(),
    )
    cp_ctx(monkeypatch, params={"client_id": "c", "return_to": return_to})

    with pytest.raises(cherrypy.HTTPError) as exc:
        auth.oidc.start()
    assert exc.value.status == 400


def test_callback_provider_failure_redirects_safely(monkeypatch):
    class DenyClient(FakeOIDCClient):
        def exchange_code(self, code, code_verifier):
            raise OIDCProviderError("secret provider detail")

    auth = AuthEndpoints(
        oidc_config(),
        jwt_handler(),
        token_manager=object(),
        oidc_client_factory=lambda _settings: DenyClient(),
    )
    cp_ctx(monkeypatch, params={"client_id": "browser-client", "return_to": "/"})
    with pytest.raises(cherrypy.HTTPRedirect) as start:
        auth.oidc.start()
    state = start.value.urls[0].split("state=", 1)[1].split("&", 1)[0]

    cp_ctx(monkeypatch, params={"state": state, "code": "auth-code"})
    with pytest.raises(cherrypy.HTTPRedirect) as callback:
        auth.oidc.callback()

    callback_url = urlparse(callback.value.urls[0])
    assert callback_url.path == "/login"
    assert callback_url.query == "oidc_error=provider"
