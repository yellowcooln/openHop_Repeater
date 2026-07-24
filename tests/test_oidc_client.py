import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from repeater.web.auth.config import ClaimRule, OIDCSettings
from repeater.web.auth.oidc_client import OIDCClient, OIDCProviderError


def settings(**overrides):
    base = {
        "issuer": "https://auth.example.com/application/o/openhop/",
        "client_id": "openhop",
        "client_secret": "secret",
        "external_url": "https://repeater.example.com",
        "scopes": ("openid", "profile", "email"),
        "provider_name": "Authentik",
        "authorization_rules": (ClaimRule("groups", ("openhop-admins",)),),
        "timeout_seconds": 1.5,
    }
    base.update(overrides)
    return OIDCSettings(**base)


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_for(key, kid="kid-1"):
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return jwk


def id_token(key, kid="kid-1", **claims):
    now = int(time.time())
    payload = {
        "iss": "https://auth.example.com/application/o/openhop/",
        "aud": "openhop",
        "sub": "stable-sub",
        "preferred_username": "alice",
        "nonce": "nonce-1",
        "iat": now,
        "exp": now + 600,
        "groups": ["openhop-admins"],
    }
    payload.update(claims)
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})


def oidc_get_for_jwks(jwks):
    def get(url, _timeout):
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": "https://auth.example.com/application/o/openhop/",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "jwks_uri": "https://auth.example.com/jwks",
            }
        return jwks

    return get


def test_discovery_validates_issuer_and_required_endpoints():
    calls = []

    def get(url, timeout):
        calls.append((url, timeout))
        return {
            "issuer": "https://auth.example.com/application/o/openhop/",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    client = OIDCClient(settings(), http_get=get)
    discovery = client.discovery()

    assert discovery["token_endpoint"].endswith("/token")
    assert calls == [
        ("https://auth.example.com/application/o/openhop/.well-known/openid-configuration", 1.5)
    ]


@pytest.mark.parametrize(
    "document",
    [
        {"issuer": "https://wrong.example.com/"},
        {"issuer": "https://auth.example.com/application/o/openhop/", "token_endpoint": "x"},
    ],
)
def test_invalid_discovery_fails_closed(document):
    client = OIDCClient(settings(), http_get=lambda *_args: document)

    with pytest.raises(OIDCProviderError):
        client.discovery()


@pytest.mark.parametrize(
    "field,url",
    [
        ("authorization_endpoint", "http://provider.example/authorize"),
        ("token_endpoint", "file:///tmp/token"),
        ("jwks_uri", "http://127.0.0.1/jwks"),
    ],
)
def test_discovery_rejects_insecure_provider_endpoints(field, url):
    document = {
        "issuer": "https://auth.example.com/application/o/openhop/",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "jwks_uri": "https://auth.example.com/jwks",
    }
    document[field] = url
    client = OIDCClient(settings(), http_get=lambda *_args: document)

    with pytest.raises(OIDCProviderError, match="secure absolute URL"):
        client.discovery()


def test_discovery_allows_http_only_for_explicit_loopback_test_issuer():
    loopback_settings = settings(issuer="http://127.0.0.1:9000/application/o/openhop/")
    client = OIDCClient(
        loopback_settings,
        http_get=lambda *_args: {
            "issuer": loopback_settings.issuer,
            "authorization_endpoint": "http://127.0.0.1:9000/authorize",
            "token_endpoint": "http://127.0.0.1:9000/token",
            "jwks_uri": "http://127.0.0.1:9000/jwks",
        },
    )

    assert client.discovery()["token_endpoint"] == "http://127.0.0.1:9000/token"


def test_pkce_and_authorization_url_do_not_request_offline_access():
    client = OIDCClient(settings(scopes=("openid", "profile", "offline_access")))
    verifier, challenge = client.create_pkce()

    assert len(verifier) >= 43
    assert challenge != verifier

    client = OIDCClient(
        settings(),
        http_get=lambda *_args: {
            "issuer": "https://auth.example.com/application/o/openhop/",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks",
        },
    )
    url = client.authorization_url(state="state", nonce="nonce", code_challenge="challenge")
    assert "code_challenge_method=S256" in url
    assert "offline_access" not in url
    assert "redirect_uri=https%3A%2F%2Frepeater.example.com%2Fauth%2Foidc%2Fcallback" in url


def test_token_exchange_posts_server_side_and_rejects_errors(signing_key):
    token = id_token(signing_key)
    posted = {}

    def post(url, data, timeout):
        posted.update({"url": url, "data": data, "timeout": timeout})
        return {"id_token": token}

    client = OIDCClient(
        settings(),
        http_get=lambda *_args: {
            "issuer": "https://auth.example.com/application/o/openhop/",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks",
        },
        http_post=post,
    )

    assert client.exchange_code("auth-code", "verifier")["id_token"] == token
    assert posted["data"]["code_verifier"] == "verifier"
    assert posted["data"]["client_secret"] == "secret"

    bad = OIDCClient(
        settings(), http_get=client._http_get, http_post=lambda *_args: {"error": "bad"}
    )
    with pytest.raises(OIDCProviderError):
        bad.exchange_code("auth-code", "verifier")


def test_validates_id_token_and_claims(signing_key):
    client = OIDCClient(
        settings(),
        http_get=oidc_get_for_jwks({"keys": [jwk_for(signing_key)]}),
    )

    identity = client.validate_id_token(id_token(signing_key), nonce="nonce-1")

    assert identity.subject == "alice"
    assert identity.oidc_subject == "stable-sub"
    assert identity.issuer == "https://auth.example.com/application/o/openhop/"
    assert identity.session_exp > int(time.time())


def test_multiple_audiences_require_matching_authorized_party(signing_key):
    client = OIDCClient(
        settings(),
        http_get=oidc_get_for_jwks({"keys": [jwk_for(signing_key)]}),
    )

    with pytest.raises(OIDCProviderError, match="authorized party"):
        client.validate_id_token(
            id_token(signing_key, aud=["openhop", "another-client"]),
            nonce="nonce-1",
        )

    identity = client.validate_id_token(
        id_token(
            signing_key,
            aud=["openhop", "another-client"],
            azp="openhop",
        ),
        nonce="nonce-1",
    )
    assert identity.oidc_subject == "stable-sub"


@pytest.mark.parametrize("jwk_patch", [{"use": "enc"}, {"alg": "RS512"}])
def test_rejects_jwk_that_is_not_valid_for_id_token_signature(signing_key, jwk_patch):
    jwk = jwk_for(signing_key)
    jwk.update(jwk_patch)
    client = OIDCClient(settings(), http_get=oidc_get_for_jwks({"keys": [jwk]}))

    with pytest.raises(OIDCProviderError, match="signing key"):
        client.validate_id_token(id_token(signing_key), nonce="nonce-1")


def test_missing_asymmetric_algorithm_backend_fails_cleanly(monkeypatch, signing_key):
    jwk = jwk_for(signing_key)
    client = OIDCClient(settings(), http_get=oidc_get_for_jwks({"keys": [jwk]}))
    monkeypatch.setattr(jwt.algorithms, "get_default_algorithms", dict)

    with pytest.raises(OIDCProviderError, match="algorithm backend unavailable"):
        client._key_for_header({"alg": "RS256", "kid": "kid-1"})


@pytest.mark.parametrize(
    ("claim_patch", "error"),
    [
        ({"iss": "https://wrong.example.com/"}, "Invalid issuer"),
        ({"aud": "other"}, "Audience"),
        ({"exp": int(time.time()) - 10}, "expired"),
        ({"nonce": "wrong"}, "nonce"),
        ({"groups": ["other"]}, "authorization"),
    ],
)
def test_rejects_invalid_tokens(signing_key, claim_patch, error):
    client = OIDCClient(settings(), http_get=oidc_get_for_jwks({"keys": [jwk_for(signing_key)]}))

    with pytest.raises(OIDCProviderError, match=error):
        client.validate_id_token(id_token(signing_key, **claim_patch), nonce="nonce-1")


def test_rejects_unsupported_alg_and_refreshes_unknown_kid_once(signing_key):
    client = OIDCClient(settings(), http_get=lambda *_args: {"keys": [jwk_for(signing_key)]})
    with pytest.raises(OIDCProviderError, match="algorithm"):
        client.validate_id_token(
            jwt.encode({"sub": "x"}, "secret", algorithm="HS256"), nonce="nonce-1"
        )

    calls = []

    def get(_url, _timeout):
        if _url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": "https://auth.example.com/application/o/openhop/",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "jwks_uri": "https://auth.example.com/jwks",
            }
        calls.append(1)
        if len(calls) == 1:
            return {"keys": []}
        return {"keys": [jwk_for(signing_key, "rotated")]}

    rotated = OIDCClient(settings(), http_get=get)
    assert (
        rotated.validate_id_token(
            id_token(signing_key, kid="rotated"), nonce="nonce-1"
        ).oidc_subject
        == "stable-sub"
    )
    assert len(calls) == 2


def test_default_http_requests_use_application_user_agent(monkeypatch):
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setattr("repeater.web.auth.oidc_client.urlopen", fake_urlopen)

    OIDCClient._default_get("https://auth.example.com/discovery", 1.5)
    OIDCClient._default_post("https://auth.example.com/token", {"code": "x"}, 1.5)

    assert len(requests) == 2
    for request, timeout in requests:
        assert request.get_header("User-agent") == "openHop-Repeater/1.0 OIDC-Client"
        assert request.get_header("Accept") == "application/json"
        assert timeout == 1.5
