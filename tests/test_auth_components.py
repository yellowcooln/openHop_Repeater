import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import cherrypy
import jwt
import pytest

from repeater.web.auth.api_tokens import APITokenManager
from repeater.web.auth.cherrypy_tool import check_auth, check_optional_auth
from repeater.web.auth.jwt_handler import JWTHandler
from repeater.web.auth.middleware import require_auth


def test_jwt_handler_create_and_verify_and_invalid_cases():
    secret = "test-secret-key-minimum-32-bytes!!"
    h = JWTHandler(secret, expiry_minutes=15)
    token = h.create_jwt("admin", "client-1")

    payload = h.verify_jwt(token)
    assert payload is not None
    assert payload["sub"] == "admin"
    assert payload["client_id"] == "client-1"

    expired = jwt.encode(
        {"sub": "admin", "client_id": "c", "iat": 1, "exp": 1}, secret, algorithm="HS256"
    )
    assert h.verify_jwt(expired) is None
    assert h.verify_jwt("not-a-token") is None


def test_jwt_handler_extra_claims_reserved_protection_and_max_exp():
    h = JWTHandler("test-secret-key-minimum-32-bytes!!", expiry_minutes=15)
    max_exp = int(time.time()) + 100

    token = h.create_jwt(
        "alice",
        "client-1",
        extra_claims={
            "auth_source": "oidc",
            "role": "admin",
            "oidc_iss": "https://issuer/",
            "oidc_sub": "sub-1",
            "session_exp": max_exp,
        },
        max_exp=max_exp,
    )
    payload = h.verify_jwt(token)

    assert payload["sub"] == "alice"
    assert payload["client_id"] == "client-1"
    assert payload["auth_source"] == "oidc"
    assert payload["exp"] == max_exp

    for reserved in ("sub", "iat", "exp", "client_id"):
        with pytest.raises(ValueError, match="reserved"):
            h.create_jwt("alice", "client-1", extra_claims={reserved: "bad"})


def test_jwt_handler_rejects_tokens_from_an_older_security_epoch():
    h = JWTHandler("test-secret-key-minimum-32-bytes!!", expiry_minutes=15, security_epoch=4)
    old_token = h.create_jwt("admin", "client-1")

    assert h.verify_jwt(old_token)["security_epoch"] == 4

    h.set_security_epoch(5)

    assert h.verify_jwt(old_token) is None
    assert h.verify_jwt(h.create_jwt("admin", "client-1"))["security_epoch"] == 5
    with pytest.raises(ValueError, match="reserved"):
        h.create_jwt("admin", "client-1", extra_claims={"security_epoch": 4})


def test_api_token_manager_happy_paths_and_revoke_false():
    db = SimpleNamespace(
        create_api_token=MagicMock(return_value=10),
        verify_api_token=MagicMock(return_value={"id": 10, "name": "n1"}),
        revoke_api_token=MagicMock(side_effect=[True, False]),
        list_api_tokens=MagicMock(return_value=[{"id": 10, "name": "n1"}]),
    )

    mgr = APITokenManager(sqlite_handler=db, secret_key="k")

    token_id, plaintext = mgr.create_token("n1")
    assert token_id == 10
    assert isinstance(plaintext, str)
    assert len(plaintext) == 64

    verified = mgr.verify_token(plaintext)
    assert verified["id"] == 10

    assert mgr.revoke_token(10) is True
    assert mgr.revoke_token(11) is False
    assert mgr.list_tokens()[0]["name"] == "n1"


def _set_cp(monkeypatch, method="GET", path="/api/private", headers=None, params=None, cfg=None):
    req = SimpleNamespace(
        method=method,
        path_info=path,
        headers=headers or {},
        params=params or {},
        user=None,
    )
    resp = SimpleNamespace(status=200, headers={})
    monkeypatch.setattr(cherrypy, "request", req, raising=False)
    monkeypatch.setattr(cherrypy, "response", resp, raising=False)
    monkeypatch.setattr(cherrypy, "config", cfg or {}, raising=False)
    return req, resp


def test_check_auth_options_terminates_request_before_handler_dispatch(monkeypatch):
    handler = MagicMock(return_value={"secret": "must-not-run"})
    req, resp = _set_cp(monkeypatch, method="OPTIONS")
    req.handler = handler

    assert check_auth() is None
    assert req.handler is None
    assert resp.status == 204


def test_require_auth_options_does_not_invoke_wrapped_handler(monkeypatch):
    handler = MagicMock(return_value={"secret": "must-not-run"})
    _req, resp = _set_cp(monkeypatch, method="OPTIONS")

    result = require_auth(handler)()

    assert result == b""
    handler.assert_not_called()
    assert resp.status == 204


def test_check_auth_skips_public_login(monkeypatch):
    _set_cp(monkeypatch, method="GET", path="/auth/login")
    assert check_auth() is None


def test_check_auth_missing_handlers_raises_http_500(monkeypatch):
    _set_cp(monkeypatch, cfg={})
    with pytest.raises(cherrypy.HTTPError) as exc_info:
        check_auth()

    assert exc_info.value.status == 500


def test_check_auth_accepts_bearer_token(monkeypatch):
    jwt_handler = SimpleNamespace(verify_jwt=lambda _t: {"sub": "admin", "client_id": "c1"})
    token_manager = SimpleNamespace(verify_token=lambda _k: None)
    req, _resp = _set_cp(
        monkeypatch,
        headers={"Authorization": "Bearer abc"},
        cfg={"jwt_handler": jwt_handler, "token_manager": token_manager},
    )

    assert check_auth() is None
    assert req.user["auth_type"] == "jwt"


def test_optional_auth_allows_anonymous_first_run_request(monkeypatch):
    req, _resp = _set_cp(monkeypatch, path="/api/config_import", cfg={})

    assert check_optional_auth() is None
    assert req.user is None


def test_optional_auth_populates_user_for_authenticated_config_import(monkeypatch):
    jwt_handler = SimpleNamespace(verify_jwt=lambda _t: {"sub": "admin", "client_id": "c1"})
    token_manager = SimpleNamespace(verify_token=lambda _k: None)
    req, _resp = _set_cp(
        monkeypatch,
        path="/api/config_import",
        headers={"Authorization": "Bearer valid"},
        cfg={"jwt_handler": jwt_handler, "token_manager": token_manager},
    )

    assert check_optional_auth() is None
    assert req.user == {"username": "admin", "client_id": "c1", "auth_type": "jwt"}


def test_optional_auth_rejects_invalid_supplied_credentials(monkeypatch):
    jwt_handler = SimpleNamespace(verify_jwt=lambda _t: None)
    token_manager = SimpleNamespace(verify_token=lambda _k: None)
    _set_cp(
        monkeypatch,
        path="/api/config_import",
        headers={"Authorization": "Bearer invalid"},
        cfg={"jwt_handler": jwt_handler, "token_manager": token_manager},
    )

    with pytest.raises(cherrypy.HTTPError) as exc_info:
        check_optional_auth()

    assert exc_info.value.status == 401


def test_check_auth_accepts_query_token_and_removes_it(monkeypatch):
    jwt_handler = SimpleNamespace(verify_jwt=lambda _t: {"sub": "admin", "client_id": "c2"})
    token_manager = SimpleNamespace(verify_token=lambda _k: None)
    req, _resp = _set_cp(
        monkeypatch,
        params={"token": "xyz", "x": "1"},
        cfg={"jwt_handler": jwt_handler, "token_manager": token_manager},
    )

    assert check_auth() is None
    assert req.user["auth_type"] == "jwt_query"
    assert "token" not in req.params


def test_check_auth_accepts_api_key(monkeypatch):
    jwt_handler = SimpleNamespace(verify_jwt=lambda _t: None)
    token_manager = SimpleNamespace(verify_token=lambda _k: {"id": 3, "name": "svc"})
    req, _resp = _set_cp(
        monkeypatch,
        headers={"X-API-Key": "k"},
        cfg={"jwt_handler": jwt_handler, "token_manager": token_manager},
    )

    assert check_auth() is None
    assert req.user["auth_type"] == "api_token"


def test_check_auth_unauthorized_raises_http_error(monkeypatch):
    jwt_handler = SimpleNamespace(verify_jwt=lambda _t: None)
    token_manager = SimpleNamespace(verify_token=lambda _k: None)
    _set_cp(monkeypatch, cfg={"jwt_handler": jwt_handler, "token_manager": token_manager})

    with pytest.raises(cherrypy.HTTPError):
        check_auth()
