from types import SimpleNamespace
from unittest.mock import MagicMock

import cherrypy
import pytest

from repeater.web.api_endpoints import APIEndpoints


def _endpoint(monkeypatch, *, auth_type: str, author_pubkey: str):
    request = SimpleNamespace(
        method="POST",
        json={
            "room_name": "General",
            "message": "Maintenance notice",
            "author_pubkey": author_pubkey,
        },
        user={"auth_type": auth_type},
    )
    response = SimpleNamespace(status=200, headers={})
    monkeypatch.setattr(cherrypy, "request", request, raising=False)
    monkeypatch.setattr(cherrypy, "response", response, raising=False)

    room_server = SimpleNamespace(
        local_identity=SimpleNamespace(get_public_key=lambda: bytes.fromhex("11" * 32))
    )
    endpoint = object.__new__(APIEndpoints)
    endpoint.config = {}
    endpoint.event_loop = None
    endpoint._get_room_server_by_name_or_hash = MagicMock(
        return_value={"name": "General", "hash": 0x42, "room_server": room_server}
    )
    return endpoint


@pytest.mark.parametrize("special_author", ["server", "system", "SERVER"])
def test_api_token_cannot_impersonate_room_server(monkeypatch, special_author):
    endpoint = _endpoint(
        monkeypatch,
        auth_type="api_token",
        author_pubkey=special_author,
    )

    with pytest.raises(cherrypy.HTTPError) as exc_info:
        endpoint.room_post_message()

    assert exc_info.value.status == 403
    endpoint._get_room_server_by_name_or_hash.assert_not_called()


def test_jwt_admin_can_post_room_server_announcement(monkeypatch):
    endpoint = _endpoint(monkeypatch, auth_type="jwt", author_pubkey="server")

    result = endpoint.room_post_message()

    assert result == {"success": False, "error": "Event loop not available"}
    endpoint._get_room_server_by_name_or_hash.assert_called_once_with("General", None)


def test_api_token_can_still_post_as_explicit_client_key(monkeypatch):
    endpoint = _endpoint(monkeypatch, auth_type="api_token", author_pubkey="22" * 32)

    result = endpoint.room_post_message()

    assert result == {"success": False, "error": "Event loop not available"}
    endpoint._get_room_server_by_name_or_hash.assert_called_once_with("General", None)
