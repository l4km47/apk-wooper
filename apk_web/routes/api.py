from __future__ import annotations

import csv
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, List

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    request,
    send_file,
    stream_with_context,
)
from werkzeug.utils import secure_filename

from apk_web.analysis.runner import is_running as analysis_is_running
from apk_web.analysis.runner import run_analysis_job
from apk_web.analysis.store import AnalysisStore
from apk_web.auth import is_valid_job_id, login_required
from apk_web.decompile_runner import run_decompile_job
from apk_web.java_discovery import java_runtimes_public_snapshot
from apk_web.java_resolve import MIN_JAVA_MAJOR
from apk_web.path_safety import safe_relative_path

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _store():
    return current_app.extensions["job_store"]


@api_bp.route("/java-runtimes", methods=["GET"])
@login_required
def java_runtimes():
    refresh = request.args.get("refresh") == "1"
    repo = Path(current_app.config["REPO_ROOT"])
    cfg = current_app.config
    snap = java_runtimes_public_snapshot(
        repo,
        ttl_sec=int(cfg["JAVA_DISCOVERY_CACHE_SEC"]),
        force_refresh=refresh,
        override_executable=cfg.get("JAVA_EXECUTABLE"),
        minimum_major=int(cfg.get("MIN_JAVA_MAJOR", MIN_JAVA_MAJOR)),
    )
    return jsonify(snap)


def _enqueue(job_id: str) -> None:
    app = current_app._get_current_object()

    def run() -> None:
        with app.app_context():
            run_decompile_job(app, job_id)

    current_app.extensions["executor"].submit(run)


@api_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"error": "missing file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400
    name = secure_filename(f.filename)
    if not name.lower().endswith(".apk"):
        return jsonify({"error": "only .apk files are accepted"}), 400

    store = _store()
    job_id = store.create_job(original_filename=name)
    dest = store.job_dir(job_id) / "input.apk"
    f.save(dest)

    _enqueue(job_id)
    return jsonify({"job_id": job_id})


@api_bp.route("/jobs", methods=["GET"])
@login_required
def list_jobs():
    store = _store()
    return jsonify({"jobs": store.list_jobs()})


@api_bp.route("/jobs/<job_id>", methods=["GET"])
@login_required
def job_status(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    if not store.job_dir(job_id).is_dir():
        return jsonify({"error": "not found"}), 404
    try:
        meta = store.get_meta(job_id)
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404
    return jsonify(meta)


@api_bp.route("/jobs/<job_id>", methods=["DELETE"])
@login_required
def delete_job(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    try:
        store.get_meta(job_id)
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404
    store.delete_job(job_id)
    return jsonify({"ok": True})


def _job_root(job_id: str) -> Path:
    return _store().job_dir(job_id)


_MAX_TREE_NODES = 20000

_PRIORITY_DIR_NAMES = {"out", "jadx"}


def _scandir_sort_key(entry: "os.DirEntry[str]") -> tuple[int, int, str]:
    name = entry.name
    lower = name.lower()
    try:
        is_file = entry.is_file()
    except OSError:
        is_file = False
    priority = 0 if lower in _PRIORITY_DIR_NAMES else 1
    return (priority, 1 if is_file else 0, lower)


def _scan_tree(
    job_root_str: str,
    abs_path: str,
    rel_posix: str,
    display_name: str,
    nodes_used: List[int],
) -> Dict[str, Any]:
    """
    Walk the on-disk tree using os.scandir (which avoids per-entry stat calls
    on Windows). `abs_path` must already be an absolute, normalized path under
    `job_root_str`. `rel_posix` is the POSIX relative path used by the client.
    """
    nodes_used[0] += 1

    children: List[Dict[str, Any]] = []
    try:
        with os.scandir(abs_path) as it:
            entries = sorted(it, key=_scandir_sort_key)
    except OSError:
        return {"name": display_name, "path": rel_posix, "type": "dir", "children": children}

    for entry in entries:
        if nodes_used[0] >= _MAX_TREE_NODES:
            children.append({"name": "...", "path": "", "type": "file"})
            break

        child_rel = entry.name if not rel_posix else f"{rel_posix}/{entry.name}"
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            is_dir = False

        if is_dir:
            children.append(
                _scan_tree(job_root_str, entry.path, child_rel, entry.name, nodes_used)
            )
        else:
            nodes_used[0] += 1
            children.append({"name": entry.name, "path": child_rel, "type": "file"})

    return {"name": display_name, "path": rel_posix, "type": "dir", "children": children}


# Back-compat shim retained because tests import this name.
def _tree_for_dir(job_root: Path, path: Path, nodes_used: List[int]) -> Dict[str, Any]:
    root = job_root.resolve()
    target = path.resolve()
    rel = "" if target == root else target.relative_to(root).as_posix()
    display = root.name if target == root else target.name
    if target.is_file():
        nodes_used[0] += 1
        return {"name": target.name, "path": rel, "type": "file"}
    return _scan_tree(str(root), str(target), rel, display, nodes_used)


@api_bp.route("/jobs/<job_id>/tree", methods=["GET"])
@login_required
def job_tree(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    root = store.job_dir(job_id)
    if not root.is_dir():
        return jsonify({"error": "not found"}), 404
    resolved = root.resolve()
    nodes_used = [0]
    tree = _scan_tree(str(resolved), str(resolved), "", resolved.name, nodes_used)
    return jsonify(
        {
            "tree": tree,
            "truncated": nodes_used[0] >= _MAX_TREE_NODES,
            "node_count": nodes_used[0],
            "max_nodes": _MAX_TREE_NODES,
        }
    )


@api_bp.route("/jobs/<job_id>/file", methods=["GET"])
@login_required
def job_file(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    rel = request.args.get("path") or ""
    store = _store()
    job_root = store.job_dir(job_id)
    try:
        target = safe_relative_path(job_root, rel)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not target.is_file():
        return jsonify({"error": "not a file"}), 404
    max_bytes = int(current_app.config["FILE_READ_MAX_BYTES"])
    try:
        size = target.stat().st_size
    except OSError:
        return jsonify({"error": "cannot read file"}), 400
    if size > max_bytes:
        return jsonify({"error": f"file too large ({size} bytes); max {max_bytes}"}), 413
    data = target.read_bytes()
    text = None
    binary_note = None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-8", errors="replace")
            binary_note = "Decoded as UTF-8 with replacement characters."
        except Exception:
            text = None
            binary_note = "Binary file; cannot display as text."
    rel_posix = target.relative_to(job_root).as_posix()
    return jsonify(
        {
            "path": rel_posix,
            "size": size,
            "text": text,
            "binary_note": binary_note,
        }
    )


@api_bp.route("/jobs/<job_id>/raw", methods=["GET"])
@login_required
def job_file_raw(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    rel = request.args.get("path") or ""
    store = _store()
    job_root = store.job_dir(job_id)
    try:
        target = safe_relative_path(job_root, rel)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not target.is_file():
        return jsonify({"error": "not a file"}), 404
    return send_file(
        target,
        as_attachment=True,
        download_name=target.name,
    )


@api_bp.route("/jobs/<job_id>/icon", methods=["GET"])
@login_required
def job_icon(job_id: str):
    """Serve the cached app icon inline (or 404 if extraction never produced one)."""
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    if not store.job_dir(job_id).is_dir():
        return jsonify({"error": "not found"}), 404
    try:
        meta = store.get_meta(job_id)
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404
    apk_meta = meta.get("apk_meta") or {}
    rel = str(apk_meta.get("icon_rel") or "").strip()
    if not rel:
        return jsonify({"error": "no icon"}), 404
    try:
        target = safe_relative_path(store.job_dir(job_id), rel)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not target.is_file():
        return jsonify({"error": "no icon"}), 404
    resp = send_file(target, mimetype=_icon_mimetype(target.suffix.lower()))
    resp.headers["Cache-Control"] = "private, max-age=86400"
    return resp


@api_bp.route("/jobs/<job_id>/apk-meta", methods=["GET"])
@login_required
def job_apk_meta(job_id: str):
    """Return only the APK metadata block; lazily backfills for legacy jobs."""
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    if not store.job_dir(job_id).is_dir():
        return jsonify({"error": "not found"}), 404
    try:
        meta = store.get_meta(job_id)
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404
    apk_meta = meta.get("apk_meta")
    if not apk_meta:
        apk_meta = _backfill_apk_meta(job_id)
    return jsonify({"apk_meta": apk_meta or {}})


@api_bp.route("/jobs/<job_id>/apk-meta", methods=["POST"])
@login_required
def job_apk_meta_refresh(job_id: str):
    """Force re-extraction of APK metadata (e.g. after copying a new icon)."""
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    if not store.job_dir(job_id).is_dir():
        return jsonify({"error": "not found"}), 404
    apk_meta = _backfill_apk_meta(job_id, force=True)
    return jsonify({"apk_meta": apk_meta or {}})


def _icon_mimetype(suffix: str) -> str:
    return {
        ".png": "image/png",
        ".webp": "image/webp",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
    }.get(suffix, "application/octet-stream")


def _backfill_apk_meta(job_id: str, *, force: bool = False) -> Dict[str, Any]:
    """Extract & persist APK metadata for an existing job.

    Used both for legacy jobs created before this feature shipped and for
    explicit refresh requests. Returns the freshly stored dict (or the
    existing one if extraction is impossible).
    """
    from apk_web.apk_meta import extract as extract_apk_meta

    store = _store()
    try:
        meta = store.get_meta(job_id)
    except FileNotFoundError:
        return {}
    if not force and meta.get("apk_meta"):
        return meta["apk_meta"]
    try:
        apk_meta = extract_apk_meta(store.job_dir(job_id)).to_dict()
    except Exception:  # noqa: BLE001 - never fail a request over metadata
        return meta.get("apk_meta") or {}
    store.update_meta(job_id, apk_meta=apk_meta)
    return apk_meta


class _ChunkSink:
    """
    Non-seekable file-like sink for :mod:`zipfile`. zipfile detects the
    missing seek capability and falls back to data descriptors, which is what
    we want for chunked streaming responses.
    """

    def __init__(self) -> None:
        self._chunks: List[bytes] = []
        self._pos = 0

    def write(self, data: Any) -> int:
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        self._chunks.append(data)
        self._pos += len(data)
        return len(data)

    def tell(self) -> int:
        return self._pos

    def flush(self) -> None:
        return None

    def seek(self, *_args: Any, **_kwargs: Any) -> int:
        # Explicitly unsupported so ZipFile sets the data-descriptor flag.
        raise OSError("non-seekable stream")

    def drain(self) -> bytes:
        if not self._chunks:
            return b""
        data = b"".join(self._chunks)
        self._chunks.clear()
        return data


@api_bp.route("/jobs/<job_id>/download", methods=["GET"])
@login_required
def job_download(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    root = store.job_dir(job_id)
    if not root.is_dir():
        return jsonify({"error": "not found"}), 404

    # Snapshot the file list up front so we can advertise the total count
    # in a response header before streaming begins.
    files: List[Path] = [p for p in root.rglob("*") if p.is_file()]

    try:
        meta = store.get_meta(job_id)
        base = meta.get("original_filename") or "job"
        safe_base = secure_filename(str(base)).replace(".apk", "") or "apk_job"
    except FileNotFoundError:
        safe_base = "apk_job"
    download_name = f"{safe_base}_{job_id[:8]}.zip"

    def generate() -> Iterator[bytes]:
        sink = _ChunkSink()
        with zipfile.ZipFile(
            sink, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
        ) as zf:
            for path in files:
                arc = path.relative_to(root).as_posix()
                try:
                    zf.write(path, arcname=arc)
                except OSError:
                    continue
                chunk = sink.drain()
                if chunk:
                    yield chunk
        tail = sink.drain()
        if tail:
            yield tail

    headers = {
        "Content-Type": "application/zip",
        "Content-Disposition": f'attachment; filename="{download_name}"',
        "X-Job-File-Count": str(len(files)),
        # Same-origin so this is informative; lets future cross-origin clients
        # still read these custom response headers.
        "Access-Control-Expose-Headers": "X-Job-File-Count, Content-Disposition",
        "Cache-Control": "no-store",
    }
    return Response(generate(), headers=headers)


@api_bp.route("/jobs/<job_id>/log", methods=["GET"])
@login_required
def job_log(job_id: str):
    if not is_valid_job_id(job_id):
        return jsonify({"error": "invalid job id"}), 400
    store = _store()
    lp = store.log_path(job_id)
    if not lp.is_file():
        return jsonify({"error": "not found"}), 404
    text = lp.read_text(encoding="utf-8", errors="replace")
    return jsonify({"log": text})


def _job_analysis_store(job_id: str) -> "AnalysisStore | None":
    if not is_valid_job_id(job_id):
        return None
    store = _store()
    job_root = store.job_dir(job_id)
    if not job_root.is_dir():
        return None
    return AnalysisStore(job_root)


def _matches_filters(item: Dict[str, Any], severity: str, category: str, rule: str, q: str) -> bool:
    if severity and (item.get("severity") or "").lower() != severity.lower():
        return False
    if category and (item.get("category") or "").lower() != category.lower():
        return False
    if rule and rule not in (item.get("rule_id") or ""):
        return False
    if q:
        needle = q.lower()
        hay = " ".join(
            str(item.get(k) or "") for k in ("file", "match", "snippet", "title", "rule_id")
        ).lower()
        if needle not in hay:
            return False
    return True


@api_bp.route("/jobs/<job_id>/analysis", methods=["GET"])
@login_required
def analysis_findings(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    findings = a.read_findings()
    severity = (request.args.get("severity") or "").strip()
    category = (request.args.get("category") or "").strip()
    rule = (request.args.get("rule") or "").strip()
    q = (request.args.get("q") or "").strip()
    try:
        limit = max(1, min(2000, int(request.args.get("limit") or 200)))
    except ValueError:
        limit = 200
    try:
        offset = max(0, int(request.args.get("offset") or 0))
    except ValueError:
        offset = 0

    filtered: List[Dict[str, Any]] = [
        item for item in findings if _matches_filters(item, severity, category, rule, q)
    ]
    page = filtered[offset : offset + limit]
    return jsonify(
        {
            "total": len(filtered),
            "limit": limit,
            "offset": offset,
            "findings": page,
        }
    )


@api_bp.route("/jobs/<job_id>/analysis/summary", methods=["GET"])
@login_required
def analysis_summary(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(a.read_summary() or {})


@api_bp.route("/jobs/<job_id>/analysis/status", methods=["GET"])
@login_required
def analysis_status(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    store = _store()
    try:
        meta = store.get_meta(job_id)
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404
    progress = a.read_progress()
    return jsonify(
        {
            "status": meta.get("analysis_status") or "none",
            "high_count": meta.get("analysis_high_count") or 0,
            "findings_count": meta.get("analysis_findings_count") or 0,
            "running": analysis_is_running(job_id),
            "progress": progress or None,
            "updated_at": meta.get("analysis_updated_at"),
        }
    )


@api_bp.route("/jobs/<job_id>/analysis/log", methods=["GET"])
@login_required
def analysis_log(job_id: str):
    """Return the dedicated analysis log (newest-first tail by default)."""
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    try:
        tail_bytes = int(request.args.get("tail_bytes") or 65536)
    except ValueError:
        tail_bytes = 65536
    tail_bytes = max(1024, min(1024 * 1024, tail_bytes))
    text = a.read_log(tail_bytes=tail_bytes)
    return jsonify(
        {
            "log": text,
            "running": analysis_is_running(job_id),
            "bytes": len(text.encode("utf-8")),
        }
    )


@api_bp.route("/analysis/tools", methods=["GET"])
@login_required
def analysis_tools_status():
    """Report optional-scanner toggles and whether each binary is installed."""
    import importlib.util

    from apk_web.tools_bootstrap import find_optional_tool

    cfg = current_app.config
    tools_root = Path(cfg.get("TOOLS_ROOT") or "tools")
    snapshot = {}
    for key, names in (
        ("gitleaks", ["gitleaks"]),
        ("trufflehog", ["trufflehog"]),
        ("radare2", ["r2", "radare2"]),
    ):
        binary = None
        for n in names:
            binary = find_optional_tool(n, tools_root)
            if binary is not None:
                break
        flag = "ENABLE_" + key.upper()
        snapshot[key] = {
            "enabled": bool(cfg.get(flag, False)),
            "installed": binary is not None,
            "binary_path": str(binary) if binary else None,
            "auto_install": key in ("gitleaks", "trufflehog", "radare2"),
            "kind": "binary",
        }

    # APKiD is a pure-Python package; surface it the same way but with a
    # pip-style install hint.
    apkid_spec = importlib.util.find_spec("apkid")
    snapshot["apkid"] = {
        "enabled": bool(cfg.get("ENABLE_APKID", False)),
        "installed": apkid_spec is not None,
        "binary_path": getattr(apkid_spec, "origin", None) if apkid_spec else None,
        "auto_install": False,
        "kind": "python_package",
        "install_command": "pip install apkid",
    }
    return jsonify({"tools": snapshot})


@api_bp.route("/analysis/tools/<tool>", methods=["POST"])
@login_required
def analysis_tools_action(tool: str):
    """Install or toggle an optional analyzer at runtime.

    Body: ``{"action": "install" | "enable" | "disable"}``.
    Toggle persists for the current process only.
    """
    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "").lower()
    cfg = current_app.config

    if tool not in ("gitleaks", "trufflehog", "radare2", "apkid"):
        return jsonify({"error": "unknown tool"}), 400

    flag = "ENABLE_" + tool.upper()

    if action in ("enable", "disable"):
        cfg[flag] = action == "enable"
        return jsonify({"ok": True, "enabled": cfg[flag]})

    if action == "install":
        if tool == "apkid":
            from apk_web.analysis.apkid_installer import install_blocking

            force_source = bool(payload.get("force_source"))
            strategy = str(payload.get("strategy") or "auto").lower()
            if strategy not in ("auto", "wheel", "source", "git_source"):
                return jsonify({"error": f"unknown strategy: {strategy}"}), 400
            result = install_blocking(
                force_source=force_source, strategy=strategy
            )
            status_code = 200 if result.ok else 500
            return jsonify(result.to_dict()), status_code

        tools_root = Path(cfg.get("TOOLS_ROOT") or "tools")
        try:
            from apk_web.tools_bootstrap import ensure_gitleaks, ensure_radare2, ensure_trufflehog

            if tool == "gitleaks":
                path = ensure_gitleaks(tools_root, logger=current_app.logger)
            elif tool == "trufflehog":
                path = ensure_trufflehog(tools_root, logger=current_app.logger)
            else:
                path = ensure_radare2(tools_root, logger=current_app.logger)
        except Exception as exc:
            return jsonify({"error": f"install failed: {exc}"}), 500
        return jsonify({"ok": True, "binary_path": str(path)})

    return jsonify({"error": "missing action"}), 400


@api_bp.route("/analysis/tools/apkid/install/stream", methods=["POST"])
@login_required
def apkid_install_stream():
    """Stream APKiD pip install output line-by-line as ``text/plain``.

    Final line is ``[result ok]`` or ``[result error <kind>]`` so the UI
    can react without re-parsing pip's noise.
    """
    from apk_web.analysis.apkid_installer import install_streaming

    body = request.get_json(silent=True) or {}
    force_source = bool(body.get("force_source"))
    strategy = str(body.get("strategy") or "auto").lower()
    if strategy not in ("auto", "wheel", "source", "git_source"):
        strategy = "auto"

    def _gen():
        for line in install_streaming(
            force_source=force_source, strategy=strategy
        ):
            yield (line + "\n")

    return Response(
        stream_with_context(_gen()),
        mimetype="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@api_bp.route("/jobs/<job_id>/analysis", methods=["POST"])
@login_required
def analysis_rerun(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    if analysis_is_running(job_id):
        return jsonify({"error": "analysis already running"}), 409
    app = current_app._get_current_object()

    def _run() -> None:
        with app.app_context():
            try:
                run_analysis_job(app, job_id)
            except Exception:  # pragma: no cover - already logged in runner
                pass

    current_app.extensions["executor"].submit(_run)
    return jsonify({"ok": True, "status": "running"})


def _to_sarif(job_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert findings to a minimal SARIF v2.1.0 report."""
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    sev_to_level = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    for f in findings:
        rid = f.get("rule_id") or "unknown"
        rules.setdefault(
            rid,
            {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.get("title") or rid},
                "defaultConfiguration": {
                    "level": sev_to_level.get(f.get("severity", "info"), "note"),
                },
            },
        )
        results.append(
            {
                "ruleId": rid,
                "level": sev_to_level.get(f.get("severity", "info"), "note"),
                "message": {"text": f.get("title") or rid},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("file") or ""},
                            "region": {
                                "startLine": max(1, int(f.get("line") or 1)),
                                "startColumn": max(1, int(f.get("column") or 1)),
                            },
                        },
                    }
                ],
                "properties": {
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "tool": f.get("tool"),
                    "confidence": f.get("confidence"),
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "apk-wooper",
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"apk-wooper/{job_id}"},
                "results": results,
            }
        ],
    }


@api_bp.route("/jobs/<job_id>/analysis/export", methods=["GET"])
@login_required
def analysis_export(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    fmt = (request.args.get("format") or "json").lower().strip()
    findings = a.read_findings()
    summary = a.read_summary()
    base = f"apk-wooper-{job_id[:8]}-findings"

    if fmt == "json":
        payload = {"summary": summary, "findings": findings}
        return Response(
            json.dumps(payload, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base}.json"'},
        )

    if fmt == "csv":
        buf = io.StringIO()
        cols = [
            "severity",
            "category",
            "rule_id",
            "title",
            "file",
            "line",
            "column",
            "match",
            "tool",
            "confidence",
        ]
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in cols})
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{base}.csv"'},
        )

    if fmt == "sarif":
        report = _to_sarif(job_id, findings)
        return Response(
            json.dumps(report, indent=2, ensure_ascii=False),
            mimetype="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="{base}.sarif"'},
        )

    return jsonify({"error": "unsupported format; use json|csv|sarif"}), 400


@api_bp.route("/jobs/<job_id>/analysis/ignores", methods=["GET"])
@login_required
def analysis_ignores_get(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(a.read_ignores())


@api_bp.route("/jobs/<job_id>/analysis/ignores", methods=["POST"])
@login_required
def analysis_ignores_set(job_id: str):
    a = _job_analysis_store(job_id)
    if a is None:
        return jsonify({"error": "not found"}), 404
    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules") or []
    fps = payload.get("fingerprints") or []
    if not isinstance(rules, list) or not isinstance(fps, list):
        return jsonify({"error": "rules and fingerprints must be arrays"}), 400
    a.write_ignores({"rules": rules, "fingerprints": fps})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Plugin system
# ---------------------------------------------------------------------------


def _plugin_registry_or_none():
    try:
        from apk_web.plugins.loader import get_registry
    except Exception:  # noqa: BLE001
        return None
    return get_registry(current_app)


def _plugins_config_path() -> Path:
    from apk_web.plugins import config as plugin_config

    return plugin_config.config_path(current_app.config)


@api_bp.route("/plugins", methods=["GET"])
@login_required
def plugins_list():
    registry = _plugin_registry_or_none()
    if registry is None:
        return jsonify({"plugins": [], "errors": [], "enabled": False})
    from apk_web.plugins.routes import _health  # internal helper

    plugins = [p.to_public_dict(healthy=_health(p)) for p in registry.all()]
    return jsonify(
        {
            "plugins": plugins,
            "errors": registry.errors(),
            "enabled": bool(current_app.config.get("ENABLE_PLUGINS", True)),
            "config_path": str(_plugins_config_path()),
        }
    )


@api_bp.route("/plugins/external", methods=["POST"])
@login_required
def plugins_external_add():
    from apk_web.plugins import config as plugin_config

    body = request.get_json(silent=True) or {}
    plugin_id = str(body.get("id") or "").strip()
    if not plugin_id:
        return jsonify({"error": "id is required"}), 400
    if not plugin_id.replace("-", "").replace("_", "").isalnum():
        return jsonify({"error": "id must be alphanumeric (with optional - or _)"}), 400
    entry: Dict[str, Any] = {
        "id": plugin_id,
        "name": str(body.get("name") or plugin_id),
        "description": str(body.get("description") or ""),
        "external_path": str(body.get("external_path") or "") or None,
        "module": str(body.get("module") or "") or None,
        "blueprint_attr": str(body.get("blueprint_attr") or "bp"),
        "mode": str(body.get("mode") or "iframe"),
        "accepts": list(body.get("accepts") or []),
        "version": str(body.get("version") or "0.0.0"),
        "icon": body.get("icon"),
    }
    if not entry["external_path"] and not entry["module"]:
        return jsonify({"error": "either external_path or module is required"}), 400
    path = _plugins_config_path()
    cfg = plugin_config.load(path)
    cfg = plugin_config.upsert_external(cfg, entry)
    # Make sure newly added plugins are enabled by default.
    cfg = plugin_config.set_enabled(cfg, plugin_id, True)
    plugin_config.save(path, cfg)
    return jsonify({"ok": True, "restart_required": True, "config": cfg})


@api_bp.route("/plugins/external/<plugin_id>", methods=["DELETE"])
@login_required
def plugins_external_remove(plugin_id: str):
    from apk_web.plugins import config as plugin_config

    path = _plugins_config_path()
    cfg = plugin_config.load(path)
    cfg = plugin_config.remove_external(cfg, plugin_id)
    plugin_config.save(path, cfg)
    return jsonify({"ok": True, "restart_required": True, "config": cfg})


@api_bp.route("/plugins/<plugin_id>/enabled", methods=["POST"])
@login_required
def plugins_set_enabled(plugin_id: str):
    from apk_web.plugins import config as plugin_config

    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    path = _plugins_config_path()
    cfg = plugin_config.load(path)
    cfg = plugin_config.set_enabled(cfg, plugin_id, enabled)
    plugin_config.save(path, cfg)
    return jsonify({"ok": True, "restart_required": True, "config": cfg})


# ---------------------------------------------------------------------------
# Plugin pip dependencies (per-plugin `pip_requires` manifest entries)
# ---------------------------------------------------------------------------


@api_bp.route("/plugins/dependencies", methods=["GET"])
@login_required
def plugins_dependencies_list():
    """Return per-plugin pip-installable dependencies and install state."""
    from apk_web.plugins import dependencies as plugin_deps

    registry = _plugin_registry_or_none()
    plugins = list(registry.all()) if registry else []
    deps = [d.to_dict() for d in plugin_deps.collect(plugins)]
    return jsonify(
        {
            "ok": True,
            "enabled": bool(current_app.config.get("ENABLE_PLUGINS", True)),
            "dependencies": deps,
            "missing_count": sum(1 for d in deps if not d["installed"]),
        }
    )


@api_bp.route("/plugins/dependencies/install", methods=["POST"])
@login_required
def plugins_dependencies_install():
    """Stream ``pip install <allowed-packages>`` line-by-line.

    Only packages declared in a registered plugin's ``pip_requires`` may
    be installed; everything else is rejected to keep this endpoint from
    becoming a generic ``pip install`` proxy.
    """
    from apk_web.plugins import dependencies as plugin_deps

    body = request.get_json(silent=True) or {}
    requested = body.get("packages")
    if not isinstance(requested, list) or not requested:
        return jsonify({"ok": False, "error": "packages: non-empty list required"}), 400
    requested_specs = [str(p).strip() for p in requested if str(p).strip()]
    if not requested_specs:
        return jsonify({"ok": False, "error": "packages: at least one non-empty entry required"}), 400

    registry = _plugin_registry_or_none()
    plugins = list(registry.all()) if registry else []
    allowed = plugin_deps.allowed_pip_specs(plugins)
    disallowed = [p for p in requested_specs if p not in allowed]
    if disallowed:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "package not declared by any registered plugin",
                    "disallowed": disallowed,
                }
            ),
            400,
        )

    def _gen():
        for line in plugin_deps.install_streaming(requested_specs):
            yield (line + "\n")

    return Response(
        stream_with_context(_gen()),
        mimetype="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# MobSF status (used by the dashboard toolbar to show/hide its button)
# ---------------------------------------------------------------------------


@api_bp.route("/mobsf/status", methods=["GET"])
@login_required
def mobsf_status():
    cfg = current_app.config
    if not cfg.get("ENABLE_MOBSF", True):
        return jsonify(
            {"ok": False, "enabled": False, "url": "", "message": "MobSF plugin disabled"}
        )
    try:
        from apk_web.plugins.mobsf.client import MobsfClient, load_config
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "enabled": True, "url": "", "message": str(exc)})
    mobsf_cfg = load_config(
        current_app.instance_path,
        env_url=str(cfg.get("MOBSF_URL") or ""),
        env_api_key=str(cfg.get("MOBSF_API_KEY") or ""),
    )
    client = MobsfClient(mobsf_cfg.get("url", ""), mobsf_cfg.get("api_key", ""), timeout=4.0)
    ok, message = client.ping()
    return jsonify(
        {
            "ok": bool(ok),
            "enabled": True,
            "url": mobsf_cfg.get("url", ""),
            "message": message,
            "api_key_set": bool(mobsf_cfg.get("api_key")),
        }
    )
