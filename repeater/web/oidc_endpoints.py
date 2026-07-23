from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Callable
from urllib.parse import urlencode

import cherrypy

from .auth.config import AuthSettings
from .auth.oidc_client import OIDCClient, OIDCProviderError
from .auth.oidc_store import OIDCExchangeRecord, OIDCFlowRecord, OneTimeOIDCStore

logger = logging.getLogger(__name__)


class OIDCEndpoints:
    def __init__(
        self,
        auth_settings: AuthSettings,
        jwt_handler,
        store: OneTimeOIDCStore | None = None,
        oidc_client_factory: Callable | None = None,
    ):
        self.auth_settings = auth_settings
        self.jwt_handler = jwt_handler
        self.store = store or OneTimeOIDCStore(ttl_seconds=300, exchange_ttl_seconds=60)
        self._oidc_client_factory = oidc_client_factory or OIDCClient
        self._client = None

    def _require_enabled(self):
        if not self.auth_settings.oidc_enabled or not self.auth_settings.oidc:
            raise cherrypy.HTTPError(404, "OIDC authentication is not enabled")

    def _client_for_request(self):
        self._require_enabled()
        if self._client is None:
            self._client = self._oidc_client_factory(self.auth_settings.oidc)
        return self._client

    @cherrypy.expose
    def start(self):
        self._require_enabled()
        client_id = str(cherrypy.request.params.get("client_id") or "").strip()
        return_to = str(cherrypy.request.params.get("return_to") or "/").strip() or "/"
        if not client_id:
            raise cherrypy.HTTPError(400, "client_id is required")
        if not _safe_local_return_path(return_to):
            raise cherrypy.HTTPError(400, "return_to must be an application-local path")

        client = self._client_for_request()
        verifier, challenge = client.create_pkce()
        nonce = _secret()
        record = self.store.create_flow(
            _secret,
            OIDCFlowRecord(
                state="",
                nonce=nonce,
                code_verifier=verifier,
                return_to=return_to,
                client_id=client_id,
                expires_at=0,
            ),
        )
        if record is None:
            raise cherrypy.HTTPError(503, "OIDC flow store is full")

        try:
            url = client.authorization_url(
                state=record.state, nonce=record.nonce, code_challenge=challenge
            )
        except OIDCProviderError:
            raise cherrypy.HTTPError(503, "OIDC provider unavailable")
        raise cherrypy.HTTPRedirect(url)

    @cherrypy.expose
    def callback(self, **_kwargs):
        self._require_enabled()
        state = str(cherrypy.request.params.get("state") or "")
        code = str(cherrypy.request.params.get("code") or "")
        if not state or not code:
            raise cherrypy.HTTPRedirect("/login?oidc_error=callback")

        record = self.store.consume_flow(state)
        if not record:
            raise cherrypy.HTTPRedirect("/login?oidc_error=state")

        try:
            client = self._client_for_request()
            token_response = client.exchange_code(code, record.code_verifier)
            identity = client.validate_id_token(token_response["id_token"], nonce=record.nonce)
            exchange = self.store.create_exchange(
                _secret,
                OIDCExchangeRecord(
                    code="",
                    client_id=record.client_id,
                    identity={
                        "sub": identity.subject,
                        "oidc_iss": identity.issuer,
                        "oidc_sub": identity.oidc_subject,
                        "session_exp": identity.session_exp,
                    },
                    expires_at=0,
                ),
            )
        except OIDCProviderError:
            logger.warning(
                "OIDC callback failed for provider %s", self.auth_settings.oidc.provider_name
            )
            raise cherrypy.HTTPRedirect("/login?oidc_error=provider")

        if exchange is None:
            raise cherrypy.HTTPRedirect("/login?oidc_error=exchange")
        separator = "&" if "?" in record.return_to else "?"
        raise cherrypy.HTTPRedirect(
            f"{record.return_to}{separator}{urlencode({'oidc_exchange': exchange.code})}"
        )

    @cherrypy.expose
    def exchange(self):
        cherrypy.response.headers["Content-Type"] = "application/json"
        self._require_enabled()
        if cherrypy.request.method != "POST":
            raise cherrypy.HTTPError(405, "Method not allowed")

        try:
            body = cherrypy.request.body.read().decode("utf-8")
            data = json.loads(body) if body else {}
            code = str(data.get("code") or "").strip()
            client_id = str(data.get("client_id") or "").strip()
            if not code or not client_id:
                cherrypy.response.status = 400
                return json.dumps(
                    {"success": False, "error": "code and client_id are required"}
                ).encode()

            record = self.store.consume_exchange(code, client_id)
            if not record:
                cherrypy.response.status = 401
                return json.dumps(
                    {"success": False, "error": "Invalid or expired OIDC exchange"}
                ).encode()

            identity = record.identity
            token = self.jwt_handler.create_jwt(
                identity["sub"],
                client_id,
                extra_claims={
                    "auth_source": "oidc",
                    "role": "admin",
                    "oidc_iss": identity["oidc_iss"],
                    "oidc_sub": identity["oidc_sub"],
                    "session_exp": identity["session_exp"],
                },
                max_exp=identity["session_exp"],
            )
            return json.dumps(
                {
                    "success": True,
                    "token": token,
                    "expires_in": self.jwt_handler.expiry_minutes * 60,
                    "username": identity["sub"],
                }
            ).encode("utf-8")
        except Exception:
            logger.exception("OIDC exchange failed")
            cherrypy.response.status = 500
            return json.dumps({"success": False, "error": "OIDC exchange failed"}).encode("utf-8")


def _safe_local_return_path(return_to: str) -> bool:
    return return_to.startswith("/") and not return_to.startswith("//")


def _secret() -> str:
    return secrets.token_urlsafe(32)
