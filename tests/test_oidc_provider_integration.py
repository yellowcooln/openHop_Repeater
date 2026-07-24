"""Disposable standards-compatible provider smoke test for the complete OIDC handoff."""

import base64
import hashlib
import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import cherrypy
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from repeater.web.auth.jwt_handler import JWTHandler
from repeater.web.auth_endpoints import AuthEndpoints


def _cherrypy_context(monkeypatch, *, method="GET", params=None, body=b""):
    request = SimpleNamespace(
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
    response = SimpleNamespace(status=200, headers={})
    monkeypatch.setattr(cherrypy, "request", request, raising=False)
    monkeypatch.setattr(cherrypy, "response", response, raising=False)


class _Provider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.nonce = ""
        self.code_challenge = ""
        self.received_token_request = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.issuer = f"http://127.0.0.1:{self.server.server_port}/application/o/openhop/"

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def _handler(self):
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def _json(self, payload):
                encoded = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self):
                if self.path.endswith("/.well-known/openid-configuration"):
                    self._json(
                        {
                            "issuer": provider.issuer,
                            "authorization_endpoint": provider.issuer + "authorize",
                            "token_endpoint": provider.issuer + "token",
                            "jwks_uri": provider.issuer + "jwks",
                        }
                    )
                    return
                if self.path == "/application/o/openhop/jwks":
                    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
                        provider.key.public_key(), as_dict=True
                    )
                    jwk.update({"kid": "integration-key", "alg": "RS256", "use": "sig"})
                    self._json({"keys": [jwk]})
                    return
                self.send_error(404)

            def do_POST(self):
                if self.path != "/application/o/openhop/token":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode())
                provider.received_token_request = {key: values[0] for key, values in form.items()}
                now = int(time.time())
                id_token = jwt.encode(
                    {
                        "iss": provider.issuer,
                        "aud": "openhop",
                        "sub": "authentik-user-id",
                        "preferred_username": "alice",
                        "groups": ["openhop-admins"],
                        "nonce": provider.nonce,
                        "iat": now,
                        "exp": now + 600,
                    },
                    provider.key,
                    algorithm="RS256",
                    headers={"kid": "integration-key"},
                )
                self._json({"token_type": "Bearer", "id_token": id_token})

        return Handler


def test_disposable_provider_full_code_flow(monkeypatch):
    provider = _Provider()
    try:
        config = {
            "web": {
                "auth": {
                    "mode": "oidc",
                    "oidc": {
                        "issuer": provider.issuer,
                        "client_id": "openhop",
                        "client_secret": "integration-secret",
                        "external_url": "http://127.0.0.1:8080",
                        "provider_name": "Authentik",
                        "scopes": ["openid", "profile", "email"],
                        "authorization": {
                            "rules": [{"claim": "groups", "any_of": ["openhop-admins"]}]
                        },
                    },
                }
            },
            "repeater": {"security": {"admin_password": "unused-local-password"}},
        }
        jwt_handler = JWTHandler("integration-jwt-secret-at-least-32-bytes", expiry_minutes=15)
        auth = AuthEndpoints(config, jwt_handler, token_manager=object())

        _cherrypy_context(
            monkeypatch,
            params={"client_id": "browser-client", "return_to": "/?tab=configuration"},
        )
        with pytest.raises(cherrypy.HTTPRedirect) as start:
            auth.oidc.start()
        authorization = parse_qs(urlparse(start.value.urls[0]).query)
        provider.nonce = authorization["nonce"][0]
        provider.code_challenge = authorization["code_challenge"][0]

        _cherrypy_context(
            monkeypatch,
            params={"state": authorization["state"][0], "code": "provider-code"},
        )
        with pytest.raises(cherrypy.HTTPRedirect) as callback:
            auth.oidc.callback()
        callback_query = parse_qs(urlparse(callback.value.urls[0]).query)
        assert urlparse(callback.value.urls[0]).path == "/login"
        assert callback_query["return_to"] == ["/?tab=configuration"]

        verifier = provider.received_token_request["code_verifier"]
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        assert challenge == provider.code_challenge
        assert provider.received_token_request["client_secret"] == "integration-secret"

        _cherrypy_context(
            monkeypatch,
            method="POST",
            body=json.dumps(
                {
                    "code": callback_query["oidc_exchange"][0],
                    "client_id": "browser-client",
                }
            ).encode(),
        )
        exchanged = json.loads(auth.oidc.exchange().decode())
        payload = jwt_handler.verify_jwt(exchanged["token"])

        assert exchanged["success"] is True
        assert payload["sub"] == "alice"
        assert payload["auth_source"] == "oidc"
        assert payload["oidc_iss"] == provider.issuer
        assert payload["oidc_sub"] == "authentik-user-id"
        assert "id_token" not in exchanged
    finally:
        provider.close()
