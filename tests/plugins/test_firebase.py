from __future__ import annotations

import io
import json
import urllib.error
from typing import Any
from unittest.mock import patch


class _FakeResp:
    def __init__(self, payload: Any, status: int = 200):
        self._body = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload
        self._status = status

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self._status

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def _patch_urlopen(payload, status: int = 200):
    """Return an ``urlopen`` patch context manager."""
    return patch("urllib.request.urlopen", return_value=_FakeResp(payload, status))


def test_index_renders(authed_client):
    _app, client = authed_client
    res = client.get("/plugins/firebase/")
    assert res.status_code == 200
    assert b"Firebase tester" in res.data


def test_test_connection_calls_url(authed_client):
    _app, client = authed_client
    with _patch_urlopen({"users": {"u1": {"name": "alice"}}}) as mocked:
        res = client.post(
            "/plugins/firebase/test",
            json={"db_url": "https://example.firebaseio.com", "api_key": "AIzaSyABCDEFG"},
        )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["status"] == 200
    assert "auth=AIzaSyABCDEFG" in mocked.call_args[0][0].full_url


def test_request_invalid_method(authed_client):
    _app, client = authed_client
    res = client.post(
        "/plugins/firebase/request",
        json={"db_url": "https://example.firebaseio.com", "method": "TRACE"},
    )
    assert res.status_code == 400


def test_request_invalid_json_body(authed_client):
    _app, client = authed_client
    res = client.post(
        "/plugins/firebase/request",
        json={
            "db_url": "https://example.firebaseio.com",
            "method": "POST",
            "path": "/users",
            "body": "{not valid",
        },
    )
    assert res.status_code == 400
    assert "invalid JSON" in res.get_json()["error"]


def test_request_forwards_body(authed_client):
    _app, client = authed_client
    with _patch_urlopen({"name": "abc"}) as mocked:
        res = client.post(
            "/plugins/firebase/request",
            json={
                "db_url": "https://example.firebaseio.com",
                "method": "POST",
                "path": "/notes",
                "body": {"text": "hi"},
            },
        )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    # The mocked request received the JSON body we passed.
    request_obj = mocked.call_args[0][0]
    assert json.loads(request_obj.data.decode("utf-8")) == {"text": "hi"}
    assert request_obj.get_method() == "POST"


def test_dump_returns_file(authed_client):
    _app, client = authed_client
    with _patch_urlopen({"k": "v"}):
        res = client.post(
            "/plugins/firebase/dump",
            data={"db_url": "https://example.firebaseio.com"},
        )
    assert res.status_code == 200
    assert res.headers["Content-Type"].startswith("application/json")
    assert b'"k": "v"' in res.data


def test_restore_round_trip(authed_client):
    _app, client = authed_client
    payload = {"a": {"b": 1}}
    with _patch_urlopen(payload):
        res = client.post(
            "/plugins/firebase/restore",
            data={
                "db_url": "https://example.firebaseio.com",
                "path": "/",
                "file": (io.BytesIO(json.dumps(payload).encode()), "snap.json"),
            },
            content_type="multipart/form-data",
        )
    assert res.status_code == 200
    assert res.get_json()["ok"] is True


def test_payload_builder(authed_client):
    _app, client = authed_client
    res = client.post(
        "/plugins/firebase/payload",
        json={
            "kind": "localstorage_dump",
            "webhooks": ["https://example.com/wh"],
        },
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    # The webhook is embedded inside the base64-encoded inner JS snippet.
    import base64
    import re
    encoded = re.search(r"atob\('([^']+)'\)", body["payload"]).group(1)
    decoded = base64.b64decode(encoded).decode("utf-8")
    assert "https://example.com/wh" in decoded
    assert body["length"] == len(body["payload"])


def test_payload_beef_requires_hook(authed_client):
    _app, client = authed_client
    res = client.post("/plugins/firebase/payload", json={"kind": "beef_hook"})
    assert res.status_code == 400


def test_request_handles_http_errors(authed_client):
    _app, client = authed_client

    def _raise(*a, **kw):
        raise urllib.error.HTTPError(
            url="x",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"Permission denied"}'),
        )

    with patch("urllib.request.urlopen", side_effect=_raise):
        res = client.post(
            "/plugins/firebase/test",
            json={"db_url": "https://example.firebaseio.com"},
        )
    body = res.get_json()
    assert body["status"] == 403
    assert body["rules_locked"] is True
