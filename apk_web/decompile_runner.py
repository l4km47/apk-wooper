from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask

from apk_web.java_discovery import select_java_for_jadx
from apk_web.java_resolve import MIN_JAVA_MAJOR
from apk_web.tools_bootstrap import ensure_decompiler_tools
from apk_web.tools_paths import find_apktool_jar, find_jadx_cli_jar


class _ToolError(RuntimeError):
    """Raised when a child tool exits non-zero. Carries the exit code."""

    def __init__(self, returncode: int, message: str) -> None:
        super().__init__(message)
        self.returncode = returncode


def _run_cmd(
    app: Flask,
    job_id: str,
    argv: List[str],
    *,
    cwd: Path | None = None,
    timeout: int,
) -> None:
    store = app.extensions["job_store"]
    store.append_log(job_id, f"$ {' '.join(argv)}\n")
    proc = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
    )
    if proc.stdout:
        store.append_log(job_id, proc.stdout)
    if proc.stderr:
        store.append_log(job_id, proc.stderr)
    if proc.returncode != 0:
        raise _ToolError(proc.returncode, f"Command failed with exit code {proc.returncode}")


def _has_any_files(root: Path) -> bool:
    """True if `root` exists and contains at least one regular file (any depth)."""
    if not root.is_dir():
        return False
    for p in root.rglob("*"):
        if p.is_file():
            return True
    return False


def run_decompile_job(app: Flask, job_id: str) -> None:
    cfg: Dict[str, Any] = app.config
    store = app.extensions["job_store"]
    tools_root: Path = Path(cfg["TOOLS_ROOT"])
    repo_root: Path = Path(cfg["REPO_ROOT"])
    timeout = int(cfg["DECOMPILE_TIMEOUT_SEC"])
    enable_apktool = bool(cfg["ENABLE_APKTOOL"])

    job_dir = store.job_dir(job_id)
    apk = job_dir / "input.apk"
    out_root = job_dir / "out"
    jadx_out = out_root / "jadx"
    apktool_out = out_root / "apktool"

    store.update_meta(job_id, status="running", error_message=None)

    try:
        if cfg.get("AUTO_DOWNLOAD_TOOLS", True):
            try:
                ensure_decompiler_tools(tools_root, logger=app.logger)
            except Exception as exc:
                store.append_log(job_id, f"[warn] AUTO_DOWNLOAD_TOOLS failed: {exc}\n")

        min_major = int(cfg.get("MIN_JAVA_MAJOR", MIN_JAVA_MAJOR))
        java, _runtimes = select_java_for_jadx(
            repo_root,
            minimum_major=min_major,
            override_executable=cfg.get("JAVA_EXECUTABLE"),
            ttl_sec=int(cfg["JAVA_DISCOVERY_CACHE_SEC"]),
            force_refresh=False,
        )
        jadx_jar = find_jadx_cli_jar(tools_root)
    except Exception as e:
        store.update_meta(job_id, status="failed", error_message=str(e))
        store.append_log(job_id, f"[error] {e}\n")
        return

    warnings: List[str] = []

    try:
        jadx_out.mkdir(parents=True, exist_ok=True)
        jadx_argv = [
            java,
            "-cp",
            str(jadx_jar),
            "jadx.cli.JadxCLI",
            "-d",
            str(jadx_out),
            "--show-bad-code",
            str(apk),
        ]
        try:
            _run_cmd(app, job_id, jadx_argv, cwd=job_dir, timeout=timeout)
        except _ToolError as e:
            # JADX exits non-zero (commonly 1/3) when some classes fail to
            # decompile, but partial output is still written. Keep it.
            if _has_any_files(jadx_out):
                msg = f"JADX exited with errors (code {e.returncode}); partial output kept."
                warnings.append(msg)
                store.append_log(job_id, f"[warn] {msg}\n")
            else:
                raise

        if enable_apktool:
            try:
                apktool_jar = find_apktool_jar(tools_root)
            except FileNotFoundError as e:
                store.append_log(job_id, f"[warn] Apktool skipped: {e}\n")
            else:
                apktool_out.mkdir(parents=True, exist_ok=True)
                apktool_argv = [
                    java,
                    "-jar",
                    str(apktool_jar),
                    "d",
                    "-f",
                    str(apk),
                    "-o",
                    str(apktool_out),
                ]
                try:
                    _run_cmd(app, job_id, apktool_argv, cwd=job_dir, timeout=timeout)
                except _ToolError as e:
                    if _has_any_files(apktool_out):
                        msg = (
                            f"Apktool exited with errors (code {e.returncode}); "
                            "partial output kept."
                        )
                        warnings.append(msg)
                        store.append_log(job_id, f"[warn] {msg}\n")
                    else:
                        # Apktool is optional; log and continue rather than fail
                        # the whole job when JADX already produced output.
                        msg = (
                            f"Apktool failed (code {e.returncode}) and produced no output; "
                            "JADX output is still available."
                        )
                        warnings.append(msg)
                        store.append_log(job_id, f"[warn] {msg}\n")

        if warnings:
            store.update_meta(
                job_id,
                status="done_with_errors",
                error_message="; ".join(warnings),
            )
        else:
            store.update_meta(job_id, status="done", error_message=None)

        try:
            from apk_web.apk_meta import extract as extract_apk_meta

            apk_meta = extract_apk_meta(job_dir)
            store.update_meta(job_id, apk_meta=apk_meta.to_dict())
        except Exception as meta_exc:  # pragma: no cover - defensive
            store.append_log(job_id, f"[apk_meta][warn] failed: {meta_exc}\n")

        if cfg.get("ENABLE_ANALYSIS", True) and cfg.get("ANALYSIS_AUTO_RUN", True):
            if _has_any_files(out_root):
                store.update_meta(job_id, analysis_status="pending")
                try:
                    from apk_web.analysis.runner import run_analysis_job

                    run_analysis_job(app, job_id)
                except Exception as analysis_exc:  # pragma: no cover - defensive
                    store.append_log(
                        job_id,
                        f"[analysis][warn] failed: {analysis_exc}\n",
                    )
    except subprocess.TimeoutExpired:
        msg = f"Decompile exceeded timeout ({timeout}s)"
        store.update_meta(job_id, status="failed", error_message=msg)
        store.append_log(job_id, f"[error] {msg}\n")
    except Exception as e:
        store.update_meta(job_id, status="failed", error_message=str(e))
        store.append_log(job_id, f"[error] {e}\n")
