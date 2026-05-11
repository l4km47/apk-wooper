"""Thin stdlib client for the Mobile Security Framework (MobSF) REST API.

Only what we need for the dashboard:

- :meth:`MobsfClient.ping` -- quick reachability probe.
- :meth:`MobsfClient.upload` -- ``POST /api/v1/upload`` with multipart body.
- :meth:`MobsfClient.scan` -- ``POST /api/v1/scan`` (form-encoded).
- :meth:`MobsfClient.report_url` -- browser deep-link to the static analyzer.

Everything goes through ``urllib`` so the plugin has zero third-party deps.
"""

from __future__ import annotations

import json
import mimetypes
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib import error, parse, request


class MobsfError(RuntimeError):
    """Raised when MobSF reports an error or is unreachable."""


@dataclass
class MobsfResponse:
    status: int
    data: Dict[str, Any]


def _normalise_base(url: str) -> str:
    return (url or "").rstrip("/")


class MobsfClient:
    """Minimal REST wrapper around a running MobSF instance.

    MobSF authenticates by sending the API key in the ``Authorization``
    header (no ``Bearer`` prefix), so :class:`MobsfClient` mirrors that.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        *,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = _normalise_base(base_url)
        self.api_key = (api_key or "").strip()
        self.timeout = float(timeout)

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {"User-Agent": "apk-wooper-mobsf-plugin/1.0"}
        if self.api_key:
            headers["Authorization"] = self.api_key
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> MobsfResponse:
        if not self.base_url:
            raise MobsfError("MobSF base URL is not configured")
        url = self.base_url + path
        req = request.Request(url=url, data=data, method=method, headers=self._headers(headers))
        try:
            with request.urlopen(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read()
                status = resp.getcode()
        except error.HTTPError as exc:
            body = (exc.read() or b"").decode("utf-8", "replace")
            raise MobsfError(f"HTTP {exc.code} from MobSF: {body[:200]}") from exc
        except error.URLError as exc:
            raise MobsfError(f"MobSF unreachable: {exc.reason}") from exc
        except OSError as exc:
            raise MobsfError(f"MobSF transport error: {exc}") from exc
        return MobsfResponse(status=status, data=_decode_json(raw))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ping(self) -> Tuple[bool, str]:
        """Return ``(ok, message)``.

        We hit MobSF's home page (``/``) because the public API surface
        does not include a dedicated health endpoint. Any 2xx or 3xx
        response is considered healthy.
        """
        if not self.base_url:
            return (False, "MOBSF_URL is not configured")
        try:
            with request.urlopen(self.base_url + "/", timeout=self.timeout) as resp:
                status = resp.getcode()
                if 200 <= status < 400:
                    return (True, f"MobSF reachable (HTTP {status})")
                return (False, f"MobSF returned HTTP {status}")
        except error.HTTPError as exc:
            # Some MobSF deployments return 302 to /login/, which urllib
            # follows automatically; an HTTPError means a real failure.
            return (False, f"HTTP {exc.code}: {exc.reason}")
        except error.URLError as exc:
            return (False, f"MobSF unreachable: {exc.reason}")
        except OSError as exc:  # pragma: no cover - defensive
            return (False, f"transport error: {exc}")

    def upload(self, apk_path: Path) -> Dict[str, Any]:
        """Upload an APK and return MobSF's parsed JSON response.

        On success MobSF returns something like::

            {"file_name": "app.apk", "hash": "...", "scan_type": "apk"}
        """
        apk_path = Path(apk_path)
        if not apk_path.is_file():
            raise MobsfError(f"APK not found: {apk_path}")
        boundary = "----wooperboundary" + uuid.uuid4().hex
        body, content_type = _build_multipart(apk_path, boundary)
        resp = self._request(
            "POST",
            "/api/v1/upload",
            data=body,
            headers={"Content-Type": content_type},
            timeout=max(self.timeout, 120),
        )
        if resp.status >= 400:
            raise MobsfError(f"MobSF upload failed: HTTP {resp.status}")
        return resp.data

    def scan(self, scan_type: str, file_name: str, hash_value: str) -> Dict[str, Any]:
        """Trigger a static scan for an already-uploaded artefact."""
        if not hash_value:
            raise MobsfError("hash is required to start a scan")
        payload = parse.urlencode(
            {
                "scan_type": scan_type or "apk",
                "file_name": file_name or "app.apk",
                "hash": hash_value,
                "re_scan": "0",
            }
        ).encode("utf-8")
        resp = self._request(
            "POST",
            "/api/v1/scan",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=max(self.timeout, 300),
        )
        if resp.status >= 400:
            raise MobsfError(f"MobSF scan failed: HTTP {resp.status}")
        return resp.data

    def report_url(self, hash_value: str) -> str:
        """Browser URL to the MobSF static-analysis report for *hash_value*."""
        if not self.base_url:
            return ""
        if not hash_value:
            return self.base_url + "/recent_scans/"
        return (
            f"{self.base_url}/static_analyzer/?checksum="
            f"{parse.quote(hash_value, safe='')}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_json(raw: bytes) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        decoded = raw.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return {}
    try:
        loaded = json.loads(decoded)
    except json.JSONDecodeError:
        return {"raw": decoded[:400]}
    if isinstance(loaded, dict):
        return loaded
    return {"data": loaded}


def _build_multipart(apk_path: Path, boundary: str) -> Tuple[bytes, str]:
    mime, _ = mimetypes.guess_type(apk_path.name)
    mime = mime or "application/vnd.android.package-archive"
    file_name = apk_path.name
    file_bytes = apk_path.read_bytes()
    out = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\n"
        f"Content-Type: {mime}\r\n\r\n"
    ).encode("utf-8")
    out += file_bytes
    out += f"\r\n--{boundary}--\r\n".encode("utf-8")
    return out, f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------


def config_path(instance_path: str) -> Path:
    return Path(instance_path) / "mobsf.json"


def load_config(
    instance_path: str,
    *,
    env_url: Optional[str] = None,
    env_api_key: Optional[str] = None,
) -> Dict[str, str]:
    """Resolve ``{url, api_key}`` from the instance file, then env, then defaults."""
    path = config_path(instance_path)
    data: Dict[str, str] = {}
    if path.is_file():
        try:
            raw = path.read_text(encoding="utf-8")
            parsed = json.loads(raw) if raw.strip() else {}
            if isinstance(parsed, dict):
                if isinstance(parsed.get("url"), str):
                    data["url"] = parsed["url"].strip()
                if isinstance(parsed.get("api_key"), str):
                    data["api_key"] = parsed["api_key"].strip()
        except (OSError, json.JSONDecodeError):
            pass
    if not data.get("url"):
        data["url"] = (env_url or os.environ.get("MOBSF_URL", "http://localhost:8000")).strip()
    if not data.get("api_key"):
        data["api_key"] = (env_api_key or os.environ.get("MOBSF_API_KEY", "")).strip()
    return data


def save_config(instance_path: str, url: str, api_key: str) -> Dict[str, str]:
    path = config_path(instance_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = {"url": (url or "").strip(), "api_key": (api_key or "").strip()}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    tmp.replace(path)
    return cfg
