from __future__ import annotations

import json

import cherrypy
from cherrypy.test import helper

from repeater.web.http_server import HTTPStatsServer
from repeater.web.proxy import TrustedProxyPolicy


class _ContextApp:
    @cherrypy.expose
    def index(self):
        context = cherrypy.request.proxy_context
        cherrypy.response.headers["Content-Type"] = "application/json"
        return json.dumps(
            {
                "client_ip": context.client_ip,
                "scheme": context.scheme,
                "host": context.host,
                "forwarded": context.forwarded,
            }
        ).encode()


class TestTrustedProxyDispatch(helper.CPWebCase):
    @staticmethod
    def setup_server():
        server = object.__new__(HTTPStatsServer)
        server.proxy_policy = TrustedProxyPolicy.from_config(
            {"http": {"trusted_proxies": ["192.0.2.0/24"]}}
        )
        cherrypy.tools.trusted_proxy = cherrypy.Tool(
            "on_start_resource", server._apply_proxy_policy, priority=5
        )
        cherrypy.tree.mount(
            _ContextApp(),
            "/",
            {"/": {"tools.trusted_proxy.on": True}},
        )

    def test_direct_peer_cannot_spoof_forwarded_client_or_origin(self):
        self.getPage(
            "/",
            headers=[
                ("X-Forwarded-For", "198.51.100.40"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "evil.example"),
                (
                    "Forwarded",
                    'for=198.51.100.40;proto=https;host="evil.example"',
                ),
            ],
        )

        self.assertStatus("200 OK")
        payload = json.loads(self.body)
        assert payload["client_ip"] in {"127.0.0.1", "::1"}
        assert payload["scheme"] == "http"
        assert payload["host"] != "evil.example"
        assert payload["forwarded"] is False


class TestTrustedLoopbackProxyDispatch(helper.CPWebCase):
    @staticmethod
    def setup_server():
        server = object.__new__(HTTPStatsServer)
        server.proxy_policy = TrustedProxyPolicy.from_config(
            {"http": {"trusted_proxies": ["127.0.0.0/8", "::1/128"]}}
        )
        cherrypy.tools.trusted_proxy = cherrypy.Tool(
            "on_start_resource", server._apply_proxy_policy, priority=5
        )
        cherrypy.tree.mount(
            _ContextApp(),
            "/",
            {"/": {"tools.trusted_proxy.on": True}},
        )

    def test_trusted_peer_supplies_client_and_https_origin(self):
        self.getPage(
            "/",
            headers=[
                ("X-Forwarded-For", "203.0.113.7"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "repeater.example.com"),
            ],
        )

        self.assertStatus("200 OK")
        payload = json.loads(self.body or b"{}")
        assert payload == {
            "client_ip": "203.0.113.7",
            "scheme": "https",
            "host": "repeater.example.com",
            "forwarded": True,
        }


class TestCanonicalHTTPSRedirectDispatch(helper.CPWebCase):
    @staticmethod
    def setup_server():
        server = object.__new__(HTTPStatsServer)
        server.proxy_policy = TrustedProxyPolicy.from_config(
            {
                "http": {
                    "trusted_proxies": ["192.0.2.0/24"],
                    "external_url": "https://repeater.example.com",
                    "redirect_to_https": True,
                }
            }
        )
        cherrypy.tools.trusted_proxy = cherrypy.Tool(
            "on_start_resource", server._apply_proxy_policy, priority=5
        )
        cherrypy.tree.mount(
            _ContextApp(),
            "/auth",
            {"/": {"tools.trusted_proxy.on": True}},
        )
        cherrypy.tree.mount(
            _ContextApp(),
            "/doc",
            {"/": {"tools.trusted_proxy.on": True}},
        )

    def test_untrusted_https_claim_redirects_to_canonical_origin(self):
        self.getPage(
            "/doc/openapi.json?format=yaml",
            headers=[
                ("Host", "attacker.example"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "attacker.example"),
            ],
        )

        self.assertStatus(308)
        headers = dict(self.headers)
        assert headers["Location"] == (
            "https://repeater.example.com/doc/openapi.json?format=yaml"
        )

    def test_mounted_auth_prefix_is_preserved_before_body_parsing(self):
        self.getPage(
            "/auth/oidc/start?client_id=browser",
            method="POST",
            body=b"{malformed-json",
            headers=[
                ("Host", "attacker.example"),
                ("Content-Type", "application/json"),
                ("X-Forwarded-Proto", "https"),
            ],
        )

        self.assertStatus(308)
        headers = dict(self.headers)
        assert headers["Location"] == (
            "https://repeater.example.com/auth/oidc/start?client_id=browser"
        )
