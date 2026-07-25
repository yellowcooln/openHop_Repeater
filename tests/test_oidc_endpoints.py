import io
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import cherrypy
import pytest

from repeater.web.auth.oidc_client import NormalizedOIDCIdentity, OIDCProviderError
from repeater.web.auth.oidc_store import OIDCExchangeRecord
from repeater.web.auth_endpoints import AuthEndpoints
from repeater.web.oidc_endpoints import _OIDCStartThrottle, _safe_local_return_path


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
        auth.oidc.start(client_id="browser-client", return_to="/dashboard")
    assert start.value.urls[0].startswith("https://auth.example.com/authorize?")
    state = start.value.urls[0].split("state=", 1)[1].split("&", 1)[0]

    cp_ctx(monkeypatch, params={"state": state, "code": "auth-code"})
    with pytest.raises(cherrypy.HTTPRedirect) as callback:
        auth.oidc.callback()
    callback_url = urlparse(callback.value.urls[0])
    assert callback_url.scheme == "https"
    assert callback_url.netloc == "repeater.example.com"
    assert callback_url.path == "/login"
    callback_query = parse_qs(callback_url.query)
    assert callback_query["return_to"] == ["/dashboard"]
    exchange_code = callback_query["oidc_exchange"][0]
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
    assert cherrypy.response.headers["Cache-Control"] == "no-store"
    assert cherrypy.response.headers["Pragma"] == "no-cache"

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


@pytest.mark.parametrize(
    "return_to",
    [r"/\evil.example", "/%5cevil.example", "/login\r\nLocation: https://evil.example"],
)
def test_safe_return_path_rejects_browser_normalization_and_header_injection(return_to):
    assert _safe_local_return_path(return_to) is False


def test_start_and_callback_only_accept_get(monkeypatch):
    auth = AuthEndpoints(
        oidc_config(),
        jwt_handler(),
        token_manager=object(),
        oidc_client_factory=lambda _settings: FakeOIDCClient(),
    )

    cp_ctx(monkeypatch, method="POST", params={"client_id": "browser"})
    with pytest.raises(cherrypy.HTTPError) as start_error:
        auth.oidc.start()
    assert start_error.value.status == 405

    cp_ctx(monkeypatch, method="POST", params={"state": "state", "code": "code"})
    with pytest.raises(cherrypy.HTTPError) as callback_error:
        auth.oidc.callback()
    assert callback_error.value.status == 405


def test_exchange_denies_identity_when_upstream_session_expired(monkeypatch):
    calls = []
    handler = SimpleNamespace(
        create_jwt=lambda *args, **kwargs: calls.append((args, kwargs)) or "internal-jwt",
        expiry_minutes=15,
    )
    auth = AuthEndpoints(
        oidc_config(),
        handler,
        token_manager=object(),
        oidc_client_factory=lambda _settings: FakeOIDCClient(),
    )
    exchange = auth.oidc.store.create_exchange(
        lambda: "expired-code",
        OIDCExchangeRecord(
            code="",
            client_id="browser",
            identity={
                "sub": "alice",
                "oidc_iss": "https://auth.example.com/application/o/openhop/",
                "oidc_sub": "stable-sub",
                "session_exp": 1,
            },
            expires_at=0,
        ),
    )
    assert exchange is not None

    cp_ctx(
        monkeypatch,
        method="POST",
        body=json.dumps({"code": "expired-code", "client_id": "browser"}).encode(),
    )
    result = json.loads(auth.oidc.exchange().decode())

    assert result["success"] is False
    assert result["error_code"] == "oidc_session_expired"
    assert cherrypy.response.status == 401
    assert calls == []


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
    assert callback_url.scheme == "https"
    assert callback_url.netloc == "repeater.example.com"
    assert callback_url.path == "/login"
    assert callback_url.query == "oidc_error=provider"


def test_callback_missing_values_uses_configured_https_origin(monkeypatch):
    auth = AuthEndpoints(
        oidc_config(),
        jwt_handler(),
        token_manager=object(),
        oidc_client_factory=lambda _settings: FakeOIDCClient(),
    )
    cp_ctx(monkeypatch, params={})

    with pytest.raises(cherrypy.HTTPRedirect) as callback:
        auth.oidc.callback()

    assert callback.value.urls[0] == "https://repeater.example.com/login?oidc_error=callback"


def test_oidc_start_throttle_returns_retry_after(monkeypatch):
    throttle = SimpleNamespace(
        get_retry_after=lambda _client_ip: 17, register_attempt=lambda _ip: 0
    )
    auth = AuthEndpoints(
        oidc_config(),
        jwt_handler(),
        token_manager=object(),
        oidc_client_factory=lambda _settings: FakeOIDCClient(),
        oidc_start_throttle=throttle,
    )
    req, response = cp_ctx(
        monkeypatch,
        params={"client_id": "browser-client", "return_to": "/"},
    )
    req.remote = SimpleNamespace(ip="198.51.100.25")

    with pytest.raises(cherrypy.HTTPError) as exc:
        auth.oidc.start()

    assert exc.value.status == 429
    assert response.headers["Retry-After"] == "17"


def test_oidc_start_throttle_bounds_each_client_and_recovers_after_window():
    now = [100.0]
    throttle = _OIDCStartThrottle(
        per_ip_attempts=2,
        global_attempts=10,
        window_seconds=60,
        time_fn=lambda: now[0],
    )

    assert throttle.get_retry_after("198.51.100.1") == 0
    assert throttle.register_attempt("198.51.100.1") == 0
    assert throttle.register_attempt("198.51.100.1") == 60
    assert throttle.get_retry_after("198.51.100.2") == 0

    now[0] += 61
    assert throttle.get_retry_after("198.51.100.1") == 0


def test_oidc_start_throttle_does_not_allocate_for_globally_blocked_clients():
    throttle = _OIDCStartThrottle(per_ip_attempts=10, global_attempts=1, window_seconds=60)

    throttle.register_attempt("198.51.100.1")
    for index in range(100):
        assert throttle.get_retry_after(f"203.0.113.{index}") > 0

    assert list(throttle._per_ip) == ["198.51.100.1"]
