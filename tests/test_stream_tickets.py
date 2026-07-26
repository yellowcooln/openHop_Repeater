import hashlib
import io
from types import SimpleNamespace

import cherrypy
import pytest

from repeater.data_acquisition import websocket_handler
from repeater.web import companion_ws_proxy
from repeater.web.auth.cherrypy_tool import check_auth
from repeater.web.auth.stream_tickets import StreamTicketManager
from repeater.web.auth_endpoints import AuthEndpoints


@pytest.fixture
def cp_ctx(monkeypatch):
    def _set(method="GET", headers=None, body=b"", path="/api/auth"):
        request = SimpleNamespace(
            method=method,
            headers=headers or {},
            body=io.BytesIO(body),
            path_info=path,
            params={},
            user=None,
        )
        response = SimpleNamespace(status=200, headers={})
        config = {}
        monkeypatch.setattr(cherrypy, "request", request, raising=False)
        monkeypatch.setattr(cherrypy, "response", response, raising=False)
        monkeypatch.setattr(cherrypy, "config", config, raising=False)
        return request, response, config

    return _set


def test_stream_ticket_is_one_time_endpoint_bound_and_stored_as_digest():
    now = [100.0]
    manager = StreamTicketManager(ttl_seconds=30, time_fn=lambda: now[0])
    issued = manager.issue(
        {"username": "alice", "client_id": "browser", "auth_type": "jwt"},
        "/api/gps-stream",
    )

    ticket = issued["ticket"]
    assert ticket not in manager._tickets
    assert hashlib.sha256(ticket.encode()).hexdigest() in manager._tickets
    assert manager.consume(ticket, "/api/logs_stream") is None
    assert manager.consume(ticket, "/api/gps_stream") is None


def test_stream_ticket_expires_and_rejects_unknown_paths():
    now = [100.0]
    manager = StreamTicketManager(ttl_seconds=30, time_fn=lambda: now[0])
    with pytest.raises(ValueError, match="Unsupported stream path"):
        manager.issue({"username": "alice"}, "/api/config_export")

    ticket = manager.issue({"username": "alice"}, "/ws/packets")["ticket"]
    now[0] = 131.0
    assert manager.consume(ticket, "/ws/packets") is None


def test_check_auth_accepts_stream_ticket_and_api_key_header(monkeypatch):
    manager = StreamTicketManager()
    ticket = manager.issue(
        {"username": "alice", "client_id": "browser", "auth_type": "jwt"},
        "/api/gps_stream",
    )["ticket"]
    request = SimpleNamespace(
        method="GET",
        path_info="/api/gps_stream",
        headers={},
        params={"ticket": ticket},
        handler=object(),
    )
    monkeypatch.setattr(cherrypy, "request", request, raising=False)
    monkeypatch.setattr(cherrypy, "response", SimpleNamespace(status=200), raising=False)
    monkeypatch.setattr(
        cherrypy,
        "config",
        {
            "jwt_handler": SimpleNamespace(verify_jwt=lambda _token: None),
            "token_manager": SimpleNamespace(verify_token=lambda _token: None),
            "stream_ticket_manager": manager,
        },
        raising=False,
    )

    check_auth()

    assert request.user["username"] == "alice"
    assert request.user["auth_type"] == "stream_ticket"
    assert "ticket" not in request.params

    request.headers = {"X-API-Key": "ha-token"}
    request.params = {}
    cherrypy.config["token_manager"] = SimpleNamespace(
        verify_token=lambda _token: {"id": 4, "name": "Home Assistant"}
    )
    check_auth()
    assert request.user["auth_type"] == "api_token"


def test_stream_ticket_endpoint_requires_supported_path(cp_ctx):
    manager = StreamTicketManager()
    auth = AuthEndpoints(config={}, jwt_handler=object(), token_manager=object())
    _request, _response, cfg = cp_ctx(
        method="POST",
        headers={"Authorization": "Bearer valid"},
        body=b'{"path":"/api/gps-stream"}',
        path="/auth/stream_ticket",
    )
    cfg["jwt_handler"] = SimpleNamespace(
        verify_jwt=lambda _token: {"sub": "alice", "client_id": "browser"}
    )
    cfg["token_manager"] = SimpleNamespace(verify_token=lambda _token: None)
    cfg["stream_ticket_manager"] = manager

    result = auth.stream_ticket()

    assert result["success"] is True
    assert result["path"] == "/api/gps_stream"
    assert manager.consume(result["ticket"], "/api/gps_stream")["username"] == "alice"


def test_packet_websocket_consumes_ticket_once(monkeypatch):
    manager = StreamTicketManager()
    ticket = manager.issue({"username": "alice", "client_id": "browser"}, "/ws/packets")["ticket"]
    monkeypatch.setattr(
        cherrypy,
        "config",
        {
            "jwt_handler": SimpleNamespace(verify_jwt=lambda _token: None),
            "token_manager": SimpleNamespace(verify_token=lambda _token: None),
            "stream_ticket_manager": manager,
        },
        raising=False,
    )

    ws = object.__new__(websocket_handler.PacketWebSocket)
    ws.environ = {"QUERY_STRING": f"ticket={ticket}&client_id=browser"}
    ws.close = lambda **_kwargs: None
    ws.opened()
    try:
        assert ws.user == "alice"
        assert manager.consume(ticket, "/ws/packets") is None
    finally:
        websocket_handler._connected_clients.discard(ws)


def test_companion_websocket_accepts_ticket_before_route_validation(monkeypatch):
    manager = StreamTicketManager()
    ticket = manager.issue({"username": "alice"}, "/ws/companion-frame")["ticket"]
    monkeypatch.setattr(
        cherrypy,
        "config",
        {
            "jwt_handler": SimpleNamespace(verify_jwt=lambda _token: None),
            "stream_ticket_manager": manager,
        },
        raising=False,
    )
    closed = []
    ws = object.__new__(companion_ws_proxy.CompanionFrameWebSocket)
    ws.environ = {"QUERY_STRING": f"ticket={ticket}"}
    ws.close = lambda **kwargs: closed.append(kwargs)

    ws.opened()

    assert closed == [{"code": 1008, "reason": "missing companion_name"}]
