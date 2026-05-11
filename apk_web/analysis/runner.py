from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from flask import Flask

from apk_web.analysis.engine import EngineConfig, run_engine
from apk_web.analysis.scanners import DEFAULT_SCANNERS
from apk_web.analysis.scanners.base import Scanner
from apk_web.analysis.store import AnalysisStore
from apk_web.tools_bootstrap import find_optional_tool


_LOG = logging.getLogger(__name__)

# Per-job lock + cancel signalling, so concurrent reruns are detectable.
_JOB_LOCKS: Dict[str, threading.Lock] = {}
_JOB_LOCKS_GUARD = threading.Lock()
_RUNNING_JOBS: Dict[str, threading.Event] = {}


def _lock_for(job_id: str) -> threading.Lock:
    with _JOB_LOCKS_GUARD:
        if job_id not in _JOB_LOCKS:
            _JOB_LOCKS[job_id] = threading.Lock()
        return _JOB_LOCKS[job_id]


def is_running(job_id: str) -> bool:
    return job_id in _RUNNING_JOBS


def _config_from_app(app: Flask) -> EngineConfig:
    cfg = app.config
    return EngineConfig(
        workers=int(cfg.get("ANALYSIS_WORKERS") or 4),
        text_max_bytes=int(cfg.get("ANALYSIS_TEXT_MAX_BYTES") or 5 * 1024 * 1024),
        native_max_bytes=int(cfg.get("ANALYSIS_BINARY_MAX_BYTES") or 200 * 1024 * 1024),
        timeout_sec=int(cfg.get("ANALYSIS_TIMEOUT_SEC") or 600),
    )


def _resolve_scanners(app: Flask) -> List[Scanner]:
    cfg = app.config
    tools_root = Path(cfg.get("TOOLS_ROOT") or "tools")
    scanners: List[Scanner] = list(DEFAULT_SCANNERS)

    if bool(cfg.get("ENABLE_GITLEAKS", False)):
        binary = find_optional_tool("gitleaks", tools_root)
        if binary is not None:
            from apk_web.analysis.scanners.gitleaks import GitleaksScanner

            scanners.append(GitleaksScanner(binary))
        else:
            _LOG.info("ENABLE_GITLEAKS=1 but gitleaks binary not found; skipping.")

    if bool(cfg.get("ENABLE_TRUFFLEHOG", False)):
        binary = find_optional_tool("trufflehog", tools_root)
        if binary is not None:
            from apk_web.analysis.scanners.trufflehog import TrufflehogScanner

            scanners.append(TrufflehogScanner(binary))
        else:
            _LOG.info("ENABLE_TRUFFLEHOG=1 but trufflehog binary not found; skipping.")

    if bool(cfg.get("ENABLE_RADARE2", False)):
        binary = find_optional_tool("r2", tools_root) or find_optional_tool(
            "radare2", tools_root
        )
        if binary is not None:
            from apk_web.analysis.scanners.radare2 import Radare2Scanner

            scanners.append(Radare2Scanner(binary))
        else:
            _LOG.info("ENABLE_RADARE2=1 but r2 binary not found; skipping.")

    return scanners


def run_analysis_job(
    app: Flask,
    job_id: str,
    *,
    log_to_job: bool = True,
) -> Optional[Dict[str, Any]]:
    """Run the analysis engine for *job_id*.

    Returns the summary dict on success, ``None`` if another run is
    already in progress for this job. Updates job meta with
    ``analysis_status``/``analysis_high_count``.
    """
    store_jobs = app.extensions["job_store"]
    job_dir: Path = store_jobs.job_dir(job_id)
    scan_root = job_dir / "out"
    if not scan_root.is_dir():
        scan_root = job_dir

    lock = _lock_for(job_id)
    if not lock.acquire(blocking=False):
        return None

    cancel_event = threading.Event()
    _RUNNING_JOBS[job_id] = cancel_event
    analysis_store = AnalysisStore(job_dir)

    # Fresh run starts with a fresh analysis-only log so the UI tail shows
    # only the current run, not history from previous re-runs.
    analysis_store.reset_log()

    def _emit_log(msg: str) -> None:
        line = msg if msg.endswith("\n") else msg + "\n"
        analysis_store.append_log(line)
        if log_to_job:
            try:
                store_jobs.append_log(job_id, line)
            except Exception:
                _LOG.debug("could not append analysis log to job %s", job_id)

    log_fn: Callable[[str], None] = _emit_log

    try:
        try:
            store_jobs.update_meta(job_id, analysis_status="running")
        except FileNotFoundError:
            return None

        config = _config_from_app(app)
        scanners = _resolve_scanners(app)
        extra_names = [s.name for s in scanners if s not in DEFAULT_SCANNERS]
        log_fn(
            f"[analysis] starting (workers={config.workers}, "
            f"timeout={config.timeout_sec}s"
            + (f", extras=[{', '.join(extra_names)}]" if extra_names else "")
            + ")"
        )
        result = run_engine(
            job_root=job_dir,
            scan_root=scan_root,
            store=analysis_store,
            config=config,
            scanners=scanners,
            cancel_event=cancel_event,
            log=log_fn,
        )
        try:
            store_jobs.update_meta(
                job_id,
                analysis_status="done_with_errors" if result.warnings else "done",
                analysis_high_count=int(result.by_severity.get("high", 0)),
                analysis_findings_count=int(result.findings_count),
                analysis_updated_at=analysis_store.read_summary().get("finished_at"),
            )
        except FileNotFoundError:
            pass
        return analysis_store.read_summary()
    except Exception as exc:
        log_fn(f"[analysis][error] {exc}")
        try:
            store_jobs.update_meta(
                job_id,
                analysis_status="failed",
                analysis_error=str(exc),
            )
        except FileNotFoundError:
            pass
        raise
    finally:
        _RUNNING_JOBS.pop(job_id, None)
        lock.release()


def request_cancel(job_id: str) -> bool:
    evt = _RUNNING_JOBS.get(job_id)
    if evt is None:
        return False
    evt.set()
    return True
