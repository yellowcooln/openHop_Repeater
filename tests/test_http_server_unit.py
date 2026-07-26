import io
import json
import logging
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import cherrypy
import pytest

from repeater.web import http_server as hs


def test_log_buffer_emit_collects_messages():
    buf = hs.LogBuffer(max_lines=2)
    rec1 = logging.LogRecord("x", logging.INFO, __file__, 1, "hello", (), None)
    rec2 = logging.LogRecord("x", logging.ERROR, __file__, 2, "boom", (), None)
    rec3 = logging.LogRecord("x", logging.WARNING, __file__, 3, "warn", (), None)

    buf.emit(rec1)
    buf.emit(rec2)
    buf.emit(rec3)

    assert len(buf.logs) == 2
    assert buf.logs[-1]["level"] == "WARNING"
    assert "warn" in buf.logs[-1]["message"]


def test_log_buffer_emit_redacts_sensitive_values():
    buf = hs.LogBuffer(max_lines=5)
    rec = logging.LogRecord(
        "auth",
        logging.DEBUG,
        __file__,
        10,
        "auth password=secret123 token=abc123 Authorization: Bearer deadbeef",
        (),
        None,
    )

    buf.emit(rec)

    assert len(buf.logs) == 1
    entry = buf.logs[0]
    assert "secret123" not in entry["message"]
    assert "abc123" not in entry["message"]
    assert "deadbeef" not in entry["message"]
    assert "[REDACTED]" in entry["message"]
    assert "raw_message" not in entry


def test_log_buffer_emit_redacts_oidc_client_secret_code_and_bearer_token():
    buf = hs.LogBuffer(max_lines=5)
    rec = logging.LogRecord(
        "oidc",
        logging.INFO,
        __file__,
        12,
        (
            "callback client_secret=super-secret authorization_code=auth-code-123 "
            "code=short-code Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        ),
        (),
        None,
    )

    buf.emit(rec)

    message = buf.logs[0]["message"]
    assert "super-secret" not in message
    assert "auth-code-123" not in message
    assert "short-code" not in message
    assert "eyJhbGciOiJIUzI1NiJ9.payload.sig" not in message
    assert message.count("[REDACTED]") >= 4


def test_log_buffer_emit_includes_exception_text_without_crashing():
    buf = hs.LogBuffer(max_lines=5)
    try:
        raise RuntimeError("boom password=secret123")
    except RuntimeError:
        rec = logging.LogRecord(
            "x",
            logging.ERROR,
            __file__,
            20,
            "failure while sending advert",
            (),
            sys.exc_info(),
        )

    buf.emit(rec)

    assert len(buf.logs) == 1
    assert "exception" in buf.logs[0]
    assert "RuntimeError" in buf.logs[0]["exception"]
    assert "secret123" not in buf.logs[0]["exception"]


def test_doc_endpoint_routes_and_openapi_json_paths(monkeypatch):
    api = SimpleNamespace(docs=lambda: "docs-html")
    doc = hs.DocEndpoint(api)

    assert doc.index() == "docs-html"
    assert doc.docs() == "docs-html"

    monkeypatch.setattr(
        cherrypy, "response", SimpleNamespace(headers={}, status=200), raising=False
    )

    # success path
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: io.StringIO("openapi: 3.0.0\n"))
    out = doc.openapi_json()
    assert cherrypy.response.headers["Content-Type"] == "application/json"
    assert b"openapi" in out

    # not found
    def _missing(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("builtins.open", _missing)
    out = doc.openapi_json()
    assert cherrypy.response.status == 404
    assert b"not found" in out

    # generic error
    def _err(*_args, **_kwargs):
        raise RuntimeError("bad")

    monkeypatch.setattr("builtins.open", _err)
    out = doc.openapi_json()
    assert cherrypy.response.status == 500
    assert b"Error loading OpenAPI spec" in out


def test_stats_app_index_and_default_routing(monkeypatch, tmp_path):
    index_html = tmp_path / "index.html"
    index_html.write_text("<html>ok</html>", encoding="utf-8")

    fake_api = SimpleNamespace(config_manager=object(), docs=lambda: "d")
    monkeypatch.setattr(hs, "APIEndpoints", lambda *args, **kwargs: fake_api)

    app = hs.StatsApp(config={"web": {"web_path": str(tmp_path)}})

    monkeypatch.setattr(cherrypy, "request", SimpleNamespace(method="GET"), raising=False)
    assert app.index() == "<html>ok</html>"

    monkeypatch.setattr(cherrypy, "request", SimpleNamespace(method="OPTIONS"), raising=False)
    assert app.default("anything") == ""

    monkeypatch.setattr(cherrypy, "request", SimpleNamespace(method="GET"), raising=False)
    with pytest.raises(cherrypy.NotFound):
        app.default("api")

    assert app.default("ws", "packets") == ""
    assert app.default("route") == "<html>ok</html>"


def test_stats_app_exposes_compiled_ui_favicon(monkeypatch, tmp_path):
    favicon = b"compiled-ui-favicon"
    (tmp_path / "favicon.ico").write_bytes(favicon)

    fake_api = SimpleNamespace(config_manager=object(), docs=lambda: "d")
    monkeypatch.setattr(hs, "APIEndpoints", lambda *args, **kwargs: fake_api)
    monkeypatch.setattr(cherrypy, "response", SimpleNamespace(headers={}), raising=False)

    app = hs.StatsApp(config={"web": {"web_path": str(tmp_path)}})

    assert app.favicon_ico() == favicon
    assert cherrypy.response.headers["Content-Type"] == "image/x-icon"


def test_stats_app_injects_discord_embed_from_site_name(monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text(
        "<html><head><title>Repeater</title></head><body></body></html>", encoding="utf-8"
    )
    fake_api = SimpleNamespace(config_manager=object(), docs=lambda: "d")
    monkeypatch.setattr(hs, "APIEndpoints", lambda *args, **kwargs: fake_api)
    app = hs.StatsApp(
        config={
            "web": {"web_path": str(tmp_path), "site_name": 'North & <Main> "Repeater"'},
            "repeater": {"node_name": "fallback-node"},
        }
    )

    rendered = app.index()

    assert 'property="og:title" content="North &amp; &lt;Main&gt; &quot;Repeater&quot; | openHop Repeater"' in rendered
    assert 'property="og:type" content="website"' in rendered
    assert 'name="twitter:card" content="summary"' in rendered
    assert "North & <Main>" not in rendered


def test_stats_app_embed_falls_back_to_repeater_node_name(monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<html><head></head><body></body></html>", encoding="utf-8")
    fake_api = SimpleNamespace(config_manager=object(), docs=lambda: "d")
    monkeypatch.setattr(hs, "APIEndpoints", lambda *args, **kwargs: fake_api)
    app = hs.StatsApp(
        config={
            "web": {"web_path": str(tmp_path), "site_name": "  "},
            "repeater": {"node_name": "Mesh Hilltop"},
        }
    )

    assert 'property="og:title" content="Mesh Hilltop | openHop Repeater"' in app.index()


def test_stats_app_index_error_paths(monkeypatch, tmp_path):
    fake_api = SimpleNamespace(config_manager=object(), docs=lambda: "d")
    monkeypatch.setattr(hs, "APIEndpoints", lambda *args, **kwargs: fake_api)

    app = hs.StatsApp(config={"web": {"web_path": str(tmp_path)}})

    with pytest.raises(cherrypy.HTTPError):
        app.index()

    # Force generic open() exception branch
    def _explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("builtins.open", _explode)
    (tmp_path / "index.html").write_text("ignored", encoding="utf-8")
    with pytest.raises(cherrypy.HTTPError):
        app.index()


def test_http_server_utility_methods(monkeypatch, tmp_path):
    def _fake_init_auth(self):
        self.jwt_handler = object()
        self.token_manager = object()

    monkeypatch.setattr(hs.HTTPStatsServer, "_init_auth_handlers", _fake_init_auth)
    monkeypatch.setattr(
        hs,
        "StatsApp",
        lambda *args, **kwargs: SimpleNamespace(api=SimpleNamespace(config_manager=object())),
    )
    monkeypatch.setattr(hs, "AuthEndpoints", lambda *args, **kwargs: object())
    monkeypatch.setattr(hs, "DocEndpoint", lambda *_args, **_kwargs: object())

    server = hs.HTTPStatsServer(
        config={"web": {"cors_enabled": False}}, config_path=str(Path(tmp_path) / "cfg.yml")
    )

    monkeypatch.setattr(cherrypy, "response", SimpleNamespace(headers={}), raising=False)
    out = server._json_error_handler(401, "no", "", "")
    assert '"success": false' in out

    install_called = {"v": False}
    monkeypatch.setattr(hs.cherrypy_cors, "install", lambda: install_called.__setitem__("v", True))
    server._setup_server_cors()
    assert install_called["v"] is True

    exited = {"v": False}
    monkeypatch.setattr(
        cherrypy,
        "engine",
        SimpleNamespace(exit=lambda: exited.__setitem__("v", True)),
        raising=False,
    )
    server.stop()
    assert exited["v"] is True


def test_cors_response_headers_allow_bearer_preflight_without_credentials():
    headers = dict(hs._cors_response_headers())

    assert headers["Access-Control-Allow-Origin"] == "*"
    assert "OPTIONS" in headers["Access-Control-Allow-Methods"]
    assert "Authorization" in headers["Access-Control-Allow-Headers"]
    assert "Access-Control-Allow-Credentials" not in headers


def test_security_response_headers_are_restrictive():
    headers = dict(hs._security_response_headers())

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Content-Security-Policy"] == "frame-ancestors 'none'"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"


def test_no_store_response_headers_disable_browser_and_proxy_caching():
    headers = dict(hs._no_store_response_headers())

    assert headers == {"Cache-Control": "no-store", "Pragma": "no-cache"}


def test_json_server_error_does_not_echo_internal_message(monkeypatch, tmp_path):
    def _fake_init_auth(self):
        self.jwt_handler = object()
        self.token_manager = object()

    monkeypatch.setattr(hs.HTTPStatsServer, "_init_auth_handlers", _fake_init_auth)
    monkeypatch.setattr(
        hs,
        "StatsApp",
        lambda *args, **kwargs: SimpleNamespace(api=SimpleNamespace(config_manager=object())),
    )
    monkeypatch.setattr(hs, "AuthEndpoints", lambda *args, **kwargs: object())
    monkeypatch.setattr(hs, "DocEndpoint", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cherrypy, "response", SimpleNamespace(headers={}), raising=False)
    server = hs.HTTPStatsServer(config={}, config_path=str(Path(tmp_path) / "cfg.yml"))

    result = server._json_error_handler("500 Internal Server Error", "secret traceback", "x", "y")

    assert "secret traceback" not in result
    assert json.loads(result)["error"] == "Internal server error"


def test_generated_jwt_secret_uses_atomic_private_config_writer(monkeypatch, tmp_path):
    config_path = tmp_path / "etc" / "openhop_repeater" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("repeater: {}\n", encoding="utf-8")
    os.chmod(config_path, 0o644)

    monkeypatch.setattr(hs, "JWTHandler", lambda secret, expiry_minutes: (secret, expiry_minutes))
    monkeypatch.setattr(hs, "SQLiteHandler", lambda path: path)
    monkeypatch.setattr(hs, "APITokenManager", lambda storage, secret: (storage, secret))
    monkeypatch.setattr(hs, "resolve_storage_dir", lambda *_args, **_kwargs: tmp_path / "data")

    server = object.__new__(hs.HTTPStatsServer)
    server.config = {"repeater": {}}
    server.config_path = str(config_path)
    server._init_auth_handlers()

    saved = config_path.read_text(encoding="utf-8")
    assert "jwt_secret:" in saved
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_http_server_passes_oidc_factory_to_auth_endpoints(monkeypatch, tmp_path):
    def _fake_init_auth(self):
        self.jwt_handler = object()
        self.token_manager = object()

    captured = {}
    monkeypatch.setattr(hs.HTTPStatsServer, "_init_auth_handlers", _fake_init_auth)
    monkeypatch.setattr(
        hs,
        "StatsApp",
        lambda *args, **kwargs: SimpleNamespace(api=SimpleNamespace(config_manager=object())),
    )
    monkeypatch.setattr(hs, "DocEndpoint", lambda *_args, **_kwargs: object())

    def fake_auth(*args, **kwargs):
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(hs, "AuthEndpoints", fake_auth)
    hs.HTTPStatsServer(config={}, config_path=str(Path(tmp_path) / "cfg.yml"))

    assert "oidc_client_factory" in captured["kwargs"]


def test_config_import_route_runs_optional_authentication(monkeypatch):
    mounts = []
    server = object.__new__(hs.HTTPStatsServer)
    server.host = "127.0.0.1"
    server.port = 0
    server.config = {}
    server.daemon_instance = None
    server._cors_enabled = False
    server.jwt_handler = object()
    server.token_manager = object()
    server.app = SimpleNamespace(apply_web_config=lambda: None)
    server.auth_app = object()
    server.doc_app = object()

    monkeypatch.setattr(hs, "_install_cheroot_bad_fd_unraisable_filter", lambda: None)
    monkeypatch.setattr(hs, "register_require_auth_tool", lambda: None)
    monkeypatch.setattr(hs, "WEBSOCKET_AVAILABLE", False)
    monkeypatch.setattr(cherrypy, "config", SimpleNamespace(update=lambda _values: None))
    monkeypatch.setattr(
        cherrypy,
        "tree",
        SimpleNamespace(mount=lambda app, path, config: mounts.append((app, path, config))),
    )
    monkeypatch.setattr(cherrypy, "engine", SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(
        cherrypy,
        "log",
        SimpleNamespace(
            access_log=SimpleNamespace(propagate=True),
            error_log=SimpleNamespace(setLevel=lambda _level: None),
        ),
    )

    server.start()

    main_config = mounts[0][2]
    route_config = main_config["/api/config_import"]
    assert route_config["tools.require_auth.on"] is False
    assert route_config["tools.optional_auth.on"] is True
