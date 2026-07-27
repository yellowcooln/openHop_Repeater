from __future__ import annotations

import pytest

from repeater.web.auth.config import AuthConfigError, normalize_auth_settings
from repeater.web.proxy import ProxyConfigError, TrustedProxyPolicy


def _resolve(
    policy: TrustedProxyPolicy,
    *,
    remote: str = "192.0.2.20",
    headers: dict[str, str] | None = None,
    scheme: str = "http",
    host: str = "192.0.2.20:8000",
):
    return policy.resolve_request(
        remote_ip=remote,
        headers=headers or {},
        direct_scheme=scheme,
        direct_host=host,
    )


def _oidc_config(*, oidc_external_url: str | None, http: dict | None = None) -> dict:
    oidc = {
        "issuer": "https://auth.example.com/application/o/openhop/",
        "client_id": "openhop",
        "client_secret": "secret",
        "provider_name": "Authentik",
        "scopes": ["openid", "profile"],
        "authorization": {"rules": [{"claim": "groups", "any_of": ["admins"]}]},
    }
    if oidc_external_url is not None:
        oidc["external_url"] = oidc_external_url
    return {
        "http": http or {},
        "web": {"auth": {"mode": "oidc", "oidc": oidc}},
    }


def test_empty_trust_list_ignores_all_forwarding_headers():
    policy = TrustedProxyPolicy.from_config({})

    context = _resolve(
        policy,
        headers={
            "X-Forwarded-For": "198.51.100.40",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "evil.example",
            "Forwarded": 'for=198.51.100.40;proto=https;host="evil.example"',
        },
    )

    assert context.client_ip == "192.0.2.20"
    assert context.scheme == "http"
    assert context.host == "192.0.2.20:8000"
    assert context.origin == "http://192.0.2.20:8000"
    assert context.forwarded is False


def test_trusted_cidr_walks_xff_right_to_left_past_trusted_proxies():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["10.0.0.0/24"]}}
    )

    context = _resolve(
        policy,
        remote="10.0.0.2",
        headers={
            # A client supplied the leftmost spoof. Trusted proxies appended the
            # actual client and nearest upstream proxy to the right.
            "X-Forwarded-For": "198.51.100.99, 203.0.113.7, 10.0.0.3",
        },
    )

    assert context.client_ip == "203.0.113.7"
    assert context.forwarded is True


def test_trusted_ipv6_cidr_and_all_trusted_chain_return_leftmost_address():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["2001:db8:1::/48"]}}
    )

    context = _resolve(
        policy,
        remote="2001:db8:1::2",
        headers={"X-Forwarded-For": "2001:db8:1::4, 2001:db8:1::3"},
        host="[2001:db8:1::2]:8000",
    )

    assert context.client_ip == "2001:db8:1::4"


def test_malformed_xff_chain_fails_closed_to_socket_peer():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["10.0.0.0/24"]}}
    )

    context = _resolve(
        policy,
        remote="10.0.0.2",
        headers={"X-Forwarded-For": "203.0.113.7, not-an-ip, 10.0.0.3"},
    )

    assert context.client_ip == "10.0.0.2"


def test_trusted_chain_aligns_proto_and_host_with_client_boundary():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["10.0.0.0/24"]}}
    )

    context = _resolve(
        policy,
        remote="10.0.0.2",
        headers={
            "X-Forwarded-For": "198.51.100.99, 203.0.113.7, 10.0.0.3",
            "X-Forwarded-Proto": "http, https, http",
            "X-Forwarded-Host": (
                "evil.example, repeater.example.com, internal.example"
            ),
        },
    )

    assert context.scheme == "https"
    assert context.host == "repeater.example.com"
    assert context.origin == "https://repeater.example.com"


def test_trusted_peer_single_proto_and_host_override_multi_hop_metadata_lists():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["10.0.0.0/24"]}}
    )

    context = _resolve(
        policy,
        remote="10.0.0.2",
        headers={
            "X-Forwarded-For": "203.0.113.7, 10.0.0.3",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "repeater.example.com",
        },
    )

    assert context.client_ip == "203.0.113.7"
    assert context.scheme == "https"
    assert context.host == "repeater.example.com"


def test_mismatched_forwarded_metadata_chain_falls_back_to_direct_origin():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["10.0.0.0/24"]}}
    )

    context = _resolve(
        policy,
        remote="10.0.0.2",
        headers={
            "X-Forwarded-For": "203.0.113.7, 10.0.0.3",
            "X-Forwarded-Proto": "https, http, https",
            "X-Forwarded-Host": "repeater.example.com, internal.example, evil.example",
        },
    )

    assert context.client_ip == "203.0.113.7"
    assert context.scheme == "http"
    assert context.host == "192.0.2.20:8000"


def test_malformed_forwarded_proto_or_host_falls_back_to_direct_values():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["10.0.0.2"]}}
    )

    context = _resolve(
        policy,
        remote="10.0.0.2",
        headers={
            "X-Forwarded-Proto": "javascript",
            "X-Forwarded-Host": "evil.example/path\r\nLocation: https://evil.example",
        },
    )

    assert context.scheme == "http"
    assert context.host == "192.0.2.20:8000"


@pytest.mark.parametrize(
    "http_config",
    [
        {"trusted_proxies": "10.0.0.1"},
        {"trusted_proxies": ["not-a-network"]},
        {"trusted_proxies": ["192.168.1.10/24"]},
        {"external_url": "https://user@example.com"},
        {"external_url": "https://example.com/path"},
        {"redirect_to_https": True},
        {"redirect_to_https": True, "external_url": "http://127.0.0.1:8000"},
    ],
)
def test_invalid_proxy_configuration_fails_startup(http_config):
    with pytest.raises(ProxyConfigError):
        TrustedProxyPolicy.from_config({"http": http_config})


def test_https_redirect_uses_canonical_origin_and_preserves_local_target():
    policy = TrustedProxyPolicy.from_config(
        {
            "http": {
                "external_url": "https://repeater.example.com",
                "redirect_to_https": True,
            }
        }
    )
    context = _resolve(policy, host="attacker.example")

    assert policy.redirect_url(context, "/doc/openapi.json", "format=yaml") == (
        "https://repeater.example.com/doc/openapi.json?format=yaml"
    )
    secure = _resolve(policy, scheme="https")
    assert policy.redirect_url(secure, "/", "") is None


def test_ipv4_mapped_ipv6_peer_matches_trusted_ipv4_network():
    policy = TrustedProxyPolicy.from_config(
        {"http": {"trusted_proxies": ["127.0.0.0/8"]}}
    )

    context = _resolve(
        policy,
        remote="::ffff:127.0.0.1",
        headers={"X-Forwarded-For": "203.0.113.7"},
    )

    assert context.client_ip == "203.0.113.7"
    assert context.forwarded is True
    assert policy.is_trusted("::ffff:127.0.0.1") is True


def test_https_redirect_rejects_network_path_and_backslash_targets():
    policy = TrustedProxyPolicy.from_config(
        {
            "http": {
                "external_url": "https://repeater.example.com",
                "redirect_to_https": True,
            }
        }
    )
    context = _resolve(policy)

    assert policy.redirect_url(context, "//evil.example/path", "") == (
        "https://repeater.example.com/"
    )
    assert policy.redirect_url(context, "/\\evil.example/path", "") == (
        "https://repeater.example.com/"
    )


def test_oidc_inherits_canonical_http_external_url():
    config = _oidc_config(
        oidc_external_url=None,
        http={"external_url": "https://repeater.example.com"},
    )

    settings = normalize_auth_settings(config)

    assert settings.oidc is not None
    assert settings.oidc.external_url == "https://repeater.example.com"
    assert settings.oidc.callback_url == "https://repeater.example.com/auth/oidc/callback"


def test_oidc_rejects_conflicting_canonical_origins():
    config = _oidc_config(
        oidc_external_url="https://other.example.com",
        http={"external_url": "https://repeater.example.com"},
    )

    with pytest.raises(AuthConfigError, match="must match http.external_url"):
        normalize_auth_settings(config)


def test_oidc_accepts_semantically_equivalent_canonical_origins():
    config = _oidc_config(
        oidc_external_url="https://Repeater.Example.com:443/ui",
        http={"external_url": "https://repeater.example.com"},
    )

    settings = normalize_auth_settings(config)

    assert settings.oidc is not None
    assert settings.oidc.external_url == "https://repeater.example.com"
