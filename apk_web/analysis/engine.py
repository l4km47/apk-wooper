from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from apk_web.analysis.filters import filter_paths, iter_scan_candidates, looks_binary
from apk_web.analysis.models import Category, Finding, Severity
from apk_web.analysis.scanners import DEFAULT_SCANNERS
from apk_web.analysis.scanners.base import Scanner
from apk_web.analysis.store import AnalysisStore


_LOG = logging.getLogger(__name__)


@dataclass
class EngineConfig:
    workers: int = 4
    text_max_bytes: int = 5 * 1024 * 1024
    native_max_bytes: int = 200 * 1024 * 1024
    timeout_sec: int = 600
    progress_every: int = 50


@dataclass
class EngineResult:
    findings_count: int
    files_scanned: int
    files_total: int
    duration_sec: float
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_rule: Dict[str, int]
    warnings: List[str]


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_read_text(path: Path, *, max_bytes: int) -> Optional[str]:
    try:
        with path.open("rb") as fp:
            head = fp.read(min(max_bytes, 8192))
            if looks_binary(head):
                return None
            rest = fp.read(max_bytes - len(head)) if max_bytes > len(head) else b""
        data = head + rest
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def _scan_text_file(
    abs_path: Path,
    rel: str,
    scanners: Sequence[Scanner],
    text_max_bytes: int,
) -> List[Finding]:
    text = _safe_read_text(abs_path, max_bytes=text_max_bytes)
    if text is None:
        return []
    findings: List[Finding] = []
    for scanner in scanners:
        if scanner.kind != "text":
            continue
        try:
            findings.extend(scanner.scan_text(rel=rel, text=text))
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.warning("scanner %s failed on %s: %s", scanner.name, rel, exc)
    return findings


def _scan_native_file(
    abs_path: Path,
    rel: str,
    scanners: Sequence[Scanner],
) -> List[Finding]:
    findings: List[Finding] = []
    for scanner in scanners:
        if scanner.kind != "native":
            continue
        try:
            findings.extend(scanner.scan_native(rel=rel, path=abs_path))
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.warning("native scanner %s failed on %s: %s", scanner.name, rel, exc)
    return findings


def _run_global_scanners(
    job_root: Path,
    scanners: Sequence[Scanner],
) -> List[Finding]:
    findings: List[Finding] = []
    for scanner in scanners:
        if scanner.kind != "global":
            continue
        try:
            findings.extend(scanner.scan_global(job_root=job_root))
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.warning("global scanner %s failed: %s", scanner.name, exc)
    return findings


def _deduplicate(findings: Iterable[Finding]) -> List[Finding]:
    seen: set[str] = set()
    out: List[Finding] = []
    for f in findings:
        fp = f.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def run_engine(
    *,
    job_root: Path,
    scan_root: Path,
    store: AnalysisStore,
    config: EngineConfig,
    scanners: Optional[Sequence[Scanner]] = None,
    cancel_event: Optional[threading.Event] = None,
    log: Optional[Callable[[str], None]] = None,
) -> EngineResult:
    """Run all scanners against *scan_root* and persist findings to *store*.

    *job_root* is the workspace root and is used to make finding paths
    relative for the UI. *scan_root* is typically ``job_root / "out"`` so
    we never scan the original .apk or our own analysis output.
    """
    scanners = list(scanners or DEFAULT_SCANNERS)
    log = log or (lambda _msg: None)
    cancel_event = cancel_event or threading.Event()

    # Some scanners (SDK fingerprinter) keep "already seen" state to
    # deduplicate at the job level; clear it before each engine run.
    for s in scanners:
        reset = getattr(s, "reset", None)
        if callable(reset):
            try:
                reset()
            except Exception:  # pragma: no cover - defensive
                _LOG.debug("scanner %s reset failed", getattr(s, "name", "?"))

    started = time.monotonic()
    started_at = _utc_iso()
    store.ensure_dir()

    scanner_names = ", ".join(s.name for s in scanners)
    log(f"[analysis] scanners enabled: {scanner_names}")

    store.write_progress(
        {
            "status": "running",
            "phase": "discover",
            "phase_label": "Discovering files",
            "files_done": 0,
            "files_total": 0,
            "findings_so_far": 0,
            "started_at": started_at,
        }
    )
    log(f"[analysis] phase 1/3: discovering scan candidates under {scan_root.name}/")

    candidates = list(iter_scan_candidates(scan_root))
    sized = list(
        filter_paths(
            candidates,
            text_max_bytes=config.text_max_bytes,
            native_max_bytes=config.native_max_bytes,
        )
    )
    files_total = len(sized)
    text_count = sum(1 for _, kind, _ in sized if kind == "text")
    native_count = sum(1 for _, kind, _ in sized if kind == "native")
    log(
        f"[analysis] discovered {files_total} files "
        f"({text_count} text, {native_count} native) - "
        f"{len(candidates) - files_total} skipped by size caps"
    )

    findings: List[Finding] = []
    warnings: List[str] = []

    global_scanner_names = [s.name for s in scanners if getattr(s, "kind", None) == "global"]
    if global_scanner_names:
        store.write_progress(
            {
                "status": "running",
                "phase": "global",
                "phase_label": "Running manifest / google-services scanners",
                "files_done": 0,
                "files_total": files_total,
                "findings_so_far": 0,
                "started_at": started_at,
            }
        )
        log(
            f"[analysis] phase 2/3: running {len(global_scanner_names)} global scanner(s): "
            f"{', '.join(global_scanner_names)}"
        )
    global_started = time.monotonic()
    global_findings = _run_global_scanners(job_root, scanners)
    findings.extend(global_findings)
    if global_findings:
        log(
            f"[analysis] global scanners produced {len(global_findings)} findings in "
            f"{round(time.monotonic() - global_started, 2)}s"
        )

    files_done = 0
    deadline = started + config.timeout_sec
    scan_phase_started = time.monotonic()
    log(
        f"[analysis] phase 3/3: scanning {files_total} files "
        f"with {config.workers} worker thread(s)"
    )
    store.write_progress(
        {
            "status": "running",
            "phase": "scan",
            "phase_label": "Scanning files",
            "files_done": 0,
            "files_total": files_total,
            "findings_so_far": len(findings),
            "started_at": started_at,
        }
    )

    def _make_rel(abs_path: Path) -> str:
        try:
            return abs_path.resolve().relative_to(job_root.resolve()).as_posix()
        except ValueError:
            return abs_path.name

    with ThreadPoolExecutor(max_workers=max(1, config.workers)) as pool:
        futures = []
        for abs_path, kind, _size in sized:
            if cancel_event.is_set():
                break
            rel = _make_rel(abs_path)
            if kind == "text":
                futures.append(
                    pool.submit(
                        _scan_text_file,
                        abs_path,
                        rel,
                        scanners,
                        config.text_max_bytes,
                    )
                )
            elif kind == "native":
                futures.append(
                    pool.submit(
                        _scan_native_file,
                        abs_path,
                        rel,
                        scanners,
                    )
                )

        for fut in as_completed(futures):
            if cancel_event.is_set():
                break
            if time.monotonic() > deadline:
                cancel_event.set()
                warnings.append(
                    f"Analysis exceeded timeout ({config.timeout_sec}s); "
                    "results may be partial."
                )
                log("[analysis] timeout reached; cancelling outstanding workers")
                break
            try:
                batch = fut.result()
            except Exception as exc:  # pragma: no cover - defensive
                warnings.append(f"scanner error: {exc}")
                _LOG.warning("scanner future failed: %s", exc)
                batch = []
            if batch:
                findings.extend(batch)
            files_done += 1
            if (files_done % config.progress_every) == 0 or files_done == files_total:
                elapsed_scan = max(0.001, time.monotonic() - scan_phase_started)
                rate = files_done / elapsed_scan
                store.write_progress(
                    {
                        "status": "running",
                        "phase": "scan",
                        "phase_label": "Scanning files",
                        "files_done": files_done,
                        "files_total": files_total,
                        "findings_so_far": len(findings),
                        "started_at": started_at,
                        "files_per_sec": round(rate, 1),
                    }
                )
            # Coarser log heartbeat so the user sees progress without spam.
            log_every = max(config.progress_every * 5, 250)
            if files_done == files_total or (files_done % log_every) == 0:
                pct = (files_done * 100 // files_total) if files_total else 100
                log(
                    f"[analysis] scanned {files_done}/{files_total} files "
                    f"({pct}%), {len(findings)} findings so far"
                )

    findings = _deduplicate(findings)
    findings.sort(
        key=lambda f: (-Severity.rank(f.severity), f.category.value, f.file, f.line),
    )

    by_severity = Counter(f.severity.value for f in findings)
    by_category = Counter(f.category.value for f in findings)
    by_rule = Counter(f.rule_id for f in findings)
    duration = round(time.monotonic() - started, 3)

    store.write_findings(findings)
    summary = {
        "job_id": job_root.name,
        "started_at": started_at,
        "finished_at": _utc_iso(),
        "duration_sec": duration,
        "files_total": files_total,
        "files_scanned": files_done,
        "findings_count": len(findings),
        "by_severity": dict(by_severity),
        "by_category": dict(by_category),
        "by_rule": dict(by_rule),
        "warnings": warnings,
        "engine_version": 1,
    }
    store.write_summary(summary)
    store.clear_progress()

    log(
        f"[analysis] done: {len(findings)} findings "
        f"({by_severity.get('high', 0)} high, {by_severity.get('medium', 0)} medium, "
        f"{by_severity.get('low', 0)} low) in {duration}s"
    )

    return EngineResult(
        findings_count=len(findings),
        files_scanned=files_done,
        files_total=files_total,
        duration_sec=duration,
        by_severity=dict(by_severity),
        by_category=dict(by_category),
        by_rule=dict(by_rule),
        warnings=warnings,
    )


__all__ = ["EngineConfig", "EngineResult", "run_engine"]
