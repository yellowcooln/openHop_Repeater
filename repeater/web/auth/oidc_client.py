from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt

from .claims import evaluate_claim_rules
from .config import OIDCSettings


class OIDCProviderError(RuntimeError):
    """Provider or token validation failure safe to map to authentication denial."""


HttpGet = Callable[[str, float], dict[str, Any]]
HttpPost = Callable[[str, dict[str, str], float], dict[str, Any]]

ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}


@dataclass(frozen=True)
class NormalizedOIDCIdentity:
    subject: str
    issuer: str
    oidc_subject: str
    session_exp: int
    claims: dict[str, Any]


class OIDCClient:
    def __init__(
        self,
        settings: OIDCSettings,
        http_get: HttpGet | None = None,
        http_post: HttpPost | None = None,
        time_fn: Callable[[], float] | None = None,
    ):
        self.settings = settings
        self._http_get = http_get or self._default_get
        self._http_post = http_post or self._default_post
        self._time_fn = time_fn or time.time
        self._discovery: dict[str, Any] | None = None
        self._discovery_expires_at = 0.0
        self._jwks: dict[str, Any] | None = None
        self._jwks_expires_at = 0.0

    @staticmethod
    def create_pkce() -> tuple[str, str]:
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def discovery(self) -> dict[str, Any]:
        now = self._time_fn()
        if self._discovery and self._discovery_expires_at > now:
            return dict(self._discovery)

        url = self._discovery_url()
        try:
            document = self._http_get(url, self.settings.timeout_seconds)
        except Exception as exc:
            raise OIDCProviderError("OIDC discovery unavailable") from exc
        if not isinstance(document, dict):
            raise OIDCProviderError("OIDC discovery response malformed")
        if document.get("issuer") != self.settings.issuer:
            raise OIDCProviderError("OIDC discovery issuer mismatch")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(document.get(key), str) or not document[key]:
                raise OIDCProviderError(f"OIDC discovery missing {key}")

        self._discovery = dict(document)
        self._discovery_expires_at = now + self.settings.discovery_ttl_seconds
        return dict(document)

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        document = self.discovery()
        scopes = [scope for scope in self.settings.scopes if scope != "offline_access"]
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.settings.client_id,
                "redirect_uri": self.settings.callback_url,
                "scope": " ".join(scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{document['authorization_endpoint']}?{query}"

    def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        document = self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.settings.callback_url,
            "client_id": self.settings.client_id,
            "client_secret": self.settings.client_secret,
            "code_verifier": code_verifier,
        }
        try:
            response = self._http_post(
                document["token_endpoint"], data, self.settings.timeout_seconds
            )
        except Exception as exc:
            raise OIDCProviderError("OIDC token exchange failed") from exc
        if not isinstance(response, dict) or response.get("error") or not response.get("id_token"):
            raise OIDCProviderError("OIDC token endpoint returned an error")
        return dict(response)

    def validate_id_token(self, id_token: str, *, nonce: str) -> NormalizedOIDCIdentity:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as exc:
            raise OIDCProviderError("Invalid ID token header") from exc

        alg = header.get("alg")
        if alg not in ASYMMETRIC_ALGS:
            raise OIDCProviderError("Unsupported ID token signing algorithm")
        key = self._key_for_header(header)

        try:
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=[alg],
                audience=self.settings.client_id,
                issuer=self.settings.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise OIDCProviderError("ID token expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise OIDCProviderError("Invalid issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise OIDCProviderError("Audience mismatch") from exc
        except jwt.InvalidTokenError as exc:
            raise OIDCProviderError("Invalid ID token") from exc

        if claims.get("nonce") != nonce:
            raise OIDCProviderError("ID token nonce mismatch")

        claim_result = evaluate_claim_rules(claims, self.settings.authorization_rules)
        if not claim_result.allowed:
            raise OIDCProviderError("OIDC authorization denied")

        oidc_sub = str(claims["sub"])
        subject = _display_subject(claims, oidc_sub)
        return NormalizedOIDCIdentity(
            subject=subject,
            issuer=str(claims["iss"]),
            oidc_subject=oidc_sub,
            session_exp=int(claims["exp"]),
            claims=dict(claims),
        )

    def _key_for_header(self, header: dict[str, Any]) -> Any:
        kid = header.get("kid")
        if not kid:
            raise OIDCProviderError("ID token missing key id")
        jwks = self._jwks_document()
        key = _find_jwk(jwks, kid)
        if key is None:
            jwks = self._jwks_document(force_refresh=True)
            key = _find_jwk(jwks, kid)
        if key is None:
            raise OIDCProviderError("Unknown ID token key id")
        return jwt.algorithms.get_default_algorithms()[header["alg"]].from_jwk(json.dumps(key))

    def _jwks_document(self, *, force_refresh: bool = False) -> dict[str, Any]:
        now = self._time_fn()
        if not force_refresh and self._jwks and self._jwks_expires_at > now:
            return dict(self._jwks)
        document = self.discovery()
        try:
            jwks = self._http_get(document["jwks_uri"], self.settings.timeout_seconds)
        except Exception as exc:
            raise OIDCProviderError("OIDC JWKS unavailable") from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise OIDCProviderError("OIDC JWKS response malformed")
        self._jwks = dict(jwks)
        self._jwks_expires_at = now + self.settings.jwks_ttl_seconds
        return dict(jwks)

    def _discovery_url(self) -> str:
        return f"{self.settings.issuer.rstrip('/')}/.well-known/openid-configuration"

    @staticmethod
    def _default_get(url: str, timeout: float) -> dict[str, Any]:
        request = Request(url, headers={"Accept": "application/json"})  # nosec B310
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _default_post(url: str, data: dict[str, str], timeout: float) -> dict[str, Any]:
        body = urlencode(data).encode("utf-8")
        request = Request(
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))


def _find_jwk(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    for key in jwks.get("keys", []):
        if isinstance(key, dict) and key.get("kid") == kid:
            return key
    return None


def _display_subject(claims: dict[str, Any], oidc_sub: str) -> str:
    for key in ("preferred_username", "name"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    digest = hashlib.sha256(oidc_sub.encode("utf-8")).hexdigest()[:12]
    return f"oidc-{digest}"
