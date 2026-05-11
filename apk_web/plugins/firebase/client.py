"""Thin Firebase Realtime Database HTTP client.

Adapted from the standalone CLI tester (``ddddddddd/main.py``). Uses only the
standard library so the plugin has no extra runtime dependencies.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

_TIMEOUT_DEFAULT = 15.0


class FirebaseError(Exception):
    """Raised on transport-level failures so route handlers can show a message."""


def _normalise_path(path: str) -> str:
    path = (path or "/").strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def _build_url(db_url: str, path: str, api_key: Optional[str]) -> str:
    db_url = (db_url or "").rstrip("/")
    if not db_url:
        raise FirebaseError("database URL is required")
    path = _normalise_path(path)
    # Realtime DB REST: append `.json` to the path.
    if path.endswith(".json"):
        rest = path
    else:
        rest = f"{path}.json"
    if api_key:
        q = urllib.parse.urlencode({"auth": api_key})
        return f"{db_url}{rest}?{q}"
    return f"{db_url}{rest}"


class FirebaseClient:
    """Minimal REST client for Firebase Realtime Database."""

    def __init__(
        self,
        db_url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = _TIMEOUT_DEFAULT,
    ) -> None:
        self.db_url = (db_url or "").rstrip("/")
        self.api_key = api_key or None
        self.timeout = float(timeout)

    def request(
        self,
        method: str,
        path: str,
        data: Any = None,
    ) -> Tuple[int, Any]:
        """Run a request. Returns ``(status_code, parsed_body_or_text)``."""
        url = _build_url(self.db_url, path, self.api_key)
        body: Optional[bytes] = None
        headers = {"Accept": "application/json"}
        if data is not None:
            if isinstance(data, (dict, list)):
                body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            elif isinstance(data, bytes):
                body = data
            else:
                body = str(data).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.getcode()
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            status = exc.code
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as exc:
            raise FirebaseError(f"{type(exc).__name__}: {exc}") from exc

        text = raw.decode("utf-8", errors="replace") if raw else ""
        try:
            parsed: Any = json.loads(text) if text else None
        except json.JSONDecodeError:
            parsed = text
        return status, parsed

    def get(self, path: str = "/") -> Tuple[int, Any]:
        return self.request("GET", path)

    def put(self, path: str, data: Any) -> Tuple[int, Any]:
        return self.request("PUT", path, data)

    def post(self, path: str, data: Any) -> Tuple[int, Any]:
        return self.request("POST", path, data)

    def patch(self, path: str, data: Any) -> Tuple[int, Any]:
        return self.request("PATCH", path, data)

    def delete(self, path: str) -> Tuple[int, Any]:
        return self.request("DELETE", path)

    def dump(self) -> Tuple[int, Any]:
        return self.get("/")

    def restore(self, payload: Dict[str, Any], *, path: str = "/") -> Tuple[int, Any]:
        return self.put(path, payload)
