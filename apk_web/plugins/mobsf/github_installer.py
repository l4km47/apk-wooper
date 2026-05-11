"""GitHub-based MobSF installer (clone + setup + run as user process).

This module manages MobSF as if a developer were following the upstream
README: ``git clone`` the repository into ``<tools_root>/mobsf``, run the
platform setup script to install Python deps inside a venv that lives
*inside the clone*, and then spawn ``run.sh`` / ``run.bat`` as a
detached child process that keeps serving on the chosen host:port.

Everything is driven from the dashboard offline panel, so:

* No admin / root rights are required (no system services, no daemon
  installs, no sudo).
* All paths are constrained under the configured ``TOOLS_ROOT`` to
  prevent path-traversal mishaps.
* State (PID + host port) is tracked in
  ``<repo>/.apk_wooper_mobsf_state.json`` so we can detect a previously
  spawned process across dashboard restarts.

All subprocess invocations use ``shell=False`` with explicit argv lists.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


_LOG = logging.getLogger(__name__)


MOBSF_REPO_URL = "https://github.com/MobSF/Mobile-Security-Framework-MobSF.git"
MOBSF_REPO_DIRNAME = "Mobile-Security-Framework-MobSF"
DEFAULT_HOST_PORT = 8000
STATE_FILE_NAME = ".apk_wooper_mobsf_state.json"

# Windows CREATE_NO_WINDOW flag (Python only exposes it as ``subprocess``
# attribute on Windows builds; resolve via getattr so the constant works
# for cross-platform tests too).
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


# ---------------------------------------------------------------------------
# In-memory MobSF child process state
#
# We keep the most recently spawned ``Popen`` so we can:
#   1. accurately report ``running`` without waiting for a PID-based poll;
#   2. terminate gracefully via ``Popen.terminate()`` from ``stop()``;
#   3. kill the child when the dashboard process exits (atexit hook), so
#      MobSF is truly "under" the main process and never orphaned.
# ---------------------------------------------------------------------------
_PROC_LOCK = threading.Lock()
_MOBSF_PROC: Optional[subprocess.Popen] = None
_MOBSF_TOOLS_ROOT: Optional[Path] = None
_ATEXIT_REGISTERED = False


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass
class GithubStatus:
    git_available: bool
    git_version: str
    python_available: bool
    python_version: str
    repo_path: str
    repo_cloned: bool
    setup_done: bool
    pid: Optional[int]
    host_port: Optional[int]
    running: bool
    started_at: Optional[float]
    error: str = ""
    platform: str = ""
    repo_url: str = MOBSF_REPO_URL
    setup_command: str = ""
    run_command: str = ""
    exit_code: Optional[int] = None
    managed_in_process: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "git_available": self.git_available,
            "git_version": self.git_version,
            "python_available": self.python_available,
            "python_version": self.python_version,
            "repo_path": self.repo_path,
            "repo_cloned": self.repo_cloned,
            "setup_done": self.setup_done,
            "pid": self.pid,
            "host_port": self.host_port,
            "running": self.running,
            "started_at": self.started_at,
            "error": self.error,
            "platform": self.platform,
            "repo_url": self.repo_url,
            "setup_command": self.setup_command,
            "run_command": self.run_command,
            "exit_code": self.exit_code,
            "managed_in_process": self.managed_in_process,
        }


def _git_bin() -> Optional[str]:
    return shutil.which("git")


def _python_bin() -> str:
    return sys.executable


def _is_windows() -> bool:
    return os.name == "nt"


def _platform_scripts() -> Tuple[str, str]:
    """Return ``(setup_script_name, run_script_name)`` for this platform."""
    if _is_windows():
        return ("setup.bat", "run.bat")
    return ("setup.sh", "run.sh")


def _run(argv: List[str], *, cwd: Optional[Path] = None, timeout: float = 30.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (-1, "", f"{type(exc).__name__}: {exc}")
    return (proc.returncode, proc.stdout or "", proc.stderr or "")


def _poetry_argv(*args: str) -> List[str]:
    """Invoke Poetry through the dashboard interpreter.

    MobSF's upstream ``run.bat`` calls ``poetry`` from PATH. On Windows that can
    resolve to a different Poetry than the one installed by ``setup.bat`` via
    ``python -m pip install poetry==1.8.4``. Running ``python -m poetry`` keeps
    setup, runtime checks, and start on the same interpreter.
    """
    return [sys.executable, "-m", "poetry", *args]


def _runtime_import_name() -> str:
    return "waitress" if _is_windows() else "gunicorn"


def _runtime_check(repo: Path) -> Tuple[bool, str]:
    """Return whether MobSF's Poetry env can import its server package."""
    import_name = _runtime_import_name()
    rc, out, err = _run(
        _poetry_argv(
            "run",
            "python",
            "-c",
            f"import {import_name}",
        ),
        cwd=repo,
        timeout=45,
    )
    if rc == 0:
        return (True, f"{import_name} is installed in MobSF Poetry env")
    tail = (err or out or "").strip()
    return (
        False,
        f"{import_name} is missing from MobSF Poetry env"
        + (f": {tail[-500:]}" if tail else ""),
    )


def _repair_runtime(repo: Path) -> Tuple[bool, str]:
    """Best-effort repair for a partially installed MobSF Poetry env.

    Setup can fail partway or a PATH-level ``poetry`` can differ from
    ``python -m poetry``. Start should not blindly spawn a broken ``run.bat``;
    it first tries the full Poetry install, then falls back to installing the
    runtime server package directly into the Poetry env.
    """
    rc, out, err = _run(
        _poetry_argv(
            "install",
            "--only",
            "main",
            "--no-root",
            "--no-interaction",
            "--no-ansi",
        ),
        cwd=repo,
        timeout=900,
    )
    if rc == 0:
        ok, msg = _runtime_check(repo)
        if ok:
            return (True, "MobSF Poetry dependencies repaired")
        # Continue to the direct runtime-package fallback below.
        err = msg

    package = "waitress>=3.0.1" if _is_windows() else "gunicorn>=20.0.4"
    rc2, out2, err2 = _run(
        _poetry_argv("run", "python", "-m", "pip", "install", package),
        cwd=repo,
        timeout=300,
    )
    if rc2 == 0:
        ok, msg = _runtime_check(repo)
        if ok:
            return (True, f"Installed missing MobSF runtime package: {package}")
        return (False, msg)

    tail = (err2 or out2 or err or out or "").strip()
    return (
        False,
        "MobSF runtime dependencies are missing and automatic repair failed. "
        "Run the MobSF setup step again, then inspect .apk_wooper_run.log. "
        + (f"Last error: {tail[-700:]}" if tail else ""),
    )


def _ensure_runtime_ready(repo: Path) -> Tuple[bool, str]:
    ok, msg = _runtime_check(repo)
    if ok:
        return (True, msg)
    return _repair_runtime(repo)


def repo_path(tools_root: Path) -> Path:
    return Path(tools_root) / "mobsf" / MOBSF_REPO_DIRNAME


def state_file(tools_root: Path) -> Path:
    return repo_path(tools_root).parent / STATE_FILE_NAME


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


def _load_state(tools_root: Path) -> Dict[str, Any]:
    path = state_file(tools_root)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(tools_root: Path, state: Dict[str, Any]) -> None:
    path = state_file(tools_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def _clear_state(tools_root: Path) -> None:
    path = state_file(tools_root)
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if _is_windows():
        rc, out, _ = _run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            timeout=8,
        )
        if rc != 0:
            return False
        return str(pid) in (out or "")
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Status / preflight
# ---------------------------------------------------------------------------


def github_status(tools_root: Path) -> GithubStatus:
    repo = repo_path(tools_root)
    setup_script, run_script = _platform_scripts()

    git = _git_bin()
    git_available = bool(git)
    git_version = ""
    if git_available:
        rc, out, _ = _run([git, "--version"], timeout=6)
        if rc == 0:
            git_version = (out or "").strip()
        else:
            git_available = False

    py = _python_bin()
    rc, out, _ = _run([py, "--version"], timeout=6)
    python_available = rc == 0
    python_version = (out or "").strip() if rc == 0 else ""

    repo_cloned = (repo / ".git").is_dir()
    setup_done = repo_cloned and (
        (repo / "venv").is_dir()
        or (repo / ".venv").is_dir()
        or (repo / "Pipfile").is_file() and (repo / "Pipfile.lock").is_file()
    )

    state = _load_state(tools_root)
    pid = state.get("pid") if isinstance(state.get("pid"), int) else None
    host_port = state.get("host_port") if isinstance(state.get("host_port"), int) else None
    started_at = state.get("started_at") if isinstance(state.get("started_at"), (int, float)) else None
    exit_code_raw = state.get("exit_code")
    exit_code = int(exit_code_raw) if isinstance(exit_code_raw, int) else None
    running = False

    # Prefer the in-memory Popen when this process spawned MobSF: it gives
    # us an authoritative answer without a tasklist/ps round-trip.
    with _PROC_LOCK:
        proc = _MOBSF_PROC
    managed = proc is not None
    if proc is not None:
        rc = proc.poll()
        if rc is None:
            running = True
            pid = proc.pid
        else:
            running = False
            exit_code = rc
            pid = None
    elif pid:
        running = _pid_alive(int(pid))
        # If the PID is gone but the port is still bound (rare but possible
        # when the user started MobSF a different way), don't claim running.
        if not running:
            pid = None
            _clear_state(tools_root)
    if running and host_port:
        # Belt + braces: prefer the actual port responding.
        running = _port_open("127.0.0.1", int(host_port))

    return GithubStatus(
        git_available=git_available,
        git_version=git_version,
        python_available=python_available,
        python_version=python_version,
        repo_path=str(repo),
        repo_cloned=repo_cloned,
        setup_done=setup_done,
        pid=pid,
        host_port=host_port,
        running=running,
        started_at=started_at,
        platform="windows" if _is_windows() else "unix",
        setup_command=setup_script,
        run_command=run_script,
        exit_code=exit_code,
        managed_in_process=managed,
    )


# ---------------------------------------------------------------------------
# Helpers shared by streaming actions
# ---------------------------------------------------------------------------


def _stream_subprocess(
    argv: List[str], *, cwd: Optional[Path] = None
) -> Iterator[str]:
    """Yield lines from a long-running command, ending with ``[exit <rc>]``."""
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(cwd) if cwd else None,
        )
    except OSError as exc:
        yield f"[error] failed to spawn: {exc}"
        yield "[exit -1]"
        return
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            yield raw.rstrip("\r\n")
    finally:
        proc.stdout.close()
        rc = proc.wait()
        yield f"[exit {rc}]"


# ---------------------------------------------------------------------------
# Clone / setup
# ---------------------------------------------------------------------------


def clone_stream(tools_root: Path) -> Iterator[str]:
    """Stream ``git clone`` output for the MobSF repo."""
    repo = repo_path(tools_root)
    repo.parent.mkdir(parents=True, exist_ok=True)
    git = _git_bin()
    if not git:
        yield "[error] git is not on PATH; install Git and retry."
        yield "[exit 127]"
        return
    if repo.exists():
        if (repo / ".git").is_dir():
            yield f"[client] repo already cloned at {repo}; running 'git pull' instead."
            yield from _stream_subprocess([git, "pull", "--ff-only"], cwd=repo)
            return
        yield f"[error] {repo} exists but is not a git repo. Remove it manually and retry."
        yield "[exit 1]"
        return
    yield f"[client] cloning {MOBSF_REPO_URL}"
    yield from _stream_subprocess(
        [git, "clone", "--depth", "1", MOBSF_REPO_URL, str(repo)],
        cwd=repo.parent,
    )


def setup_stream(tools_root: Path) -> Iterator[str]:
    """Stream MobSF's platform setup script (creates a venv inside the clone)."""
    repo = repo_path(tools_root)
    if not (repo / ".git").is_dir():
        yield "[error] repository is not cloned yet; run Clone first."
        yield "[exit 1]"
        return
    setup_script, _ = _platform_scripts()
    script = repo / setup_script
    if not script.is_file():
        yield f"[error] setup script not found at {script}"
        yield "[exit 1]"
        return

    if _is_windows():
        argv: List[str] = ["cmd.exe", "/c", str(script)]
    else:
        try:
            mode = script.stat().st_mode
            os.chmod(script, mode | 0o111)
        except OSError:
            pass
        argv = ["bash", str(script)]

    yield f"[client] running {setup_script} in {repo}"
    yield from _stream_subprocess(argv, cwd=repo)


# ---------------------------------------------------------------------------
# Start / stop
# ---------------------------------------------------------------------------


def _spawn_run_script(
    repo: Path, host_port: int
) -> Tuple[Optional[subprocess.Popen], Optional[Path], str]:
    """Spawn MobSF's WSGI server as a managed child of the dashboard.

    Returns ``(popen, log_path, error_message)``. The caller owns the
    Popen and is expected to register it in ``_MOBSF_PROC`` plus start a
    monitor thread.

    Lifecycle notes:

    * **Windows**: ``CREATE_NO_WINDOW`` hides the console (no cmd window
      flash) while still giving the child a real console handle so
      Python servers behave normally. ``CREATE_NEW_PROCESS_GROUP`` lets
      us send ``CTRL_BREAK_EVENT`` for a clean shutdown later.
    * **Unix**: the child stays in the dashboard's session so it dies on
      ``SIGHUP`` when the dashboard exits.
    """
    addr = f"127.0.0.1:{host_port}"
    log_path = repo / ".apk_wooper_run.log"
    try:
        log_fp = open(log_path, "ab", buffering=0)
    except OSError as exc:
        return (None, None, f"could not open log file: {exc}")

    try:
        if _is_windows():
            creationflags = 0
            new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            creationflags = new_group | _CREATE_NO_WINDOW
            # Avoid upstream run.bat's bare `poetry` lookup. It can resolve to
            # a different Poetry from PATH and then fail with:
            #   'waitress-serve' is not recognized...
            argv = _poetry_argv(
                "run",
                "waitress-serve",
                f"--listen={addr}",
                "--threads=10",
                "--channel-timeout=3600",
                "mobsf.MobSF.wsgi:application",
            )
            proc = subprocess.Popen(
                argv,
                cwd=str(repo),
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=False,
            )
        else:
            argv = _poetry_argv(
                "run",
                "gunicorn",
                "-b",
                addr,
                "mobsf.MobSF.wsgi:application",
                "--workers=1",
                "--threads=10",
                "--timeout=3600",
                "--log-level=critical",
                "--log-file=-",
                "--access-logfile=-",
                "--error-logfile=-",
                "--capture-output",
            )
            # No ``start_new_session``: MobSF stays in the dashboard's
            # session and gets ``SIGHUP`` when the dashboard exits.
            proc = subprocess.Popen(
                argv,
                cwd=str(repo),
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
    except OSError as exc:
        try:
            log_fp.close()
        except Exception:  # noqa: BLE001
            pass
        return (None, None, f"failed to spawn run script: {exc}")

    return (proc, log_path, "")


# ---------------------------------------------------------------------------
# Monitor thread + atexit hook
# ---------------------------------------------------------------------------


def _monitor(proc: subprocess.Popen, tools_root: Path) -> None:
    """Wait for *proc* to exit, then rewrite the state file.

    Runs in a daemon thread per spawn. On exit we:

    * record ``running=False`` and the ``exit_code`` so the UI reflects
      reality on the next status poll;
    * clear ``_MOBSF_PROC`` if it still points at this process, so
      ``stop()`` won't try to terminate an already-dead handle.
    """
    try:
        exit_code = proc.wait()
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("mobsf monitor thread crashed: %s", exc)
        exit_code = -1

    global _MOBSF_PROC
    with _PROC_LOCK:
        if _MOBSF_PROC is proc:
            _MOBSF_PROC = None

    try:
        state = _load_state(tools_root)
        if state:
            state["running"] = False
            state["exit_code"] = int(exit_code)
            state["exited_at"] = time.time()
            _save_state(tools_root, state)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("mobsf monitor: failed to update state: %s", exc)


def _terminate_proc(proc: subprocess.Popen, *, timeout: float = 5.0) -> None:
    """Best-effort graceful kill of a still-running MobSF child."""
    if proc.poll() is not None:
        return
    try:
        if _is_windows():
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError):
                proc.terminate()
        else:
            proc.terminate()
    except (OSError, ProcessLookupError):
        return
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except (OSError, ProcessLookupError):
        return
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass


def _atexit_terminate() -> None:
    """Stop the tracked MobSF child when the dashboard process exits."""
    with _PROC_LOCK:
        proc = _MOBSF_PROC
        tools_root = _MOBSF_TOOLS_ROOT
    if proc is None:
        return
    _LOG.info("dashboard shutdown: terminating MobSF child (pid=%s)", proc.pid)
    _terminate_proc(proc, timeout=5.0)
    if tools_root is not None:
        try:
            state = _load_state(tools_root)
            if state:
                state["running"] = False
                state["exit_code"] = proc.returncode if proc.returncode is not None else -1
                state["exited_at"] = time.time()
                _save_state(tools_root, state)
        except Exception:  # noqa: BLE001
            pass


def _ensure_atexit_registered() -> None:
    global _ATEXIT_REGISTERED
    if _ATEXIT_REGISTERED:
        return
    try:
        atexit.register(_atexit_terminate)
        _ATEXIT_REGISTERED = True
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("could not register atexit MobSF terminator: %s", exc)


def start(tools_root: Path, *, host_port: int = DEFAULT_HOST_PORT) -> Tuple[bool, str, Dict[str, Any]]:
    if not isinstance(host_port, int) or not (1 <= host_port <= 65535):
        return (False, "host_port out of range", {})
    repo = repo_path(tools_root)
    if not (repo / ".git").is_dir():
        return (False, "repository is not cloned yet", {"needs_clone": True})

    status = github_status(tools_root)
    if status.running:
        return (
            True,
            f"already running on port {status.host_port}",
            {"pid": status.pid, "host_port": status.host_port},
        )

    ready, runtime_msg = _ensure_runtime_ready(repo)
    if not ready:
        return (
            False,
            runtime_msg,
            {"needs_setup": True, "runtime": _runtime_import_name()},
        )

    proc, log_path, err = _spawn_run_script(repo, host_port)
    if proc is None:
        return (False, err or "failed to start", {})

    pid = proc.pid

    state = {
        "pid": pid,
        "host_port": host_port,
        "started_at": time.time(),
        "log_path": str(log_path) if log_path else "",
        "running": True,
    }
    _save_state(tools_root, state)

    # Register the Popen + spawn a daemon monitor thread that updates
    # the state file as soon as MobSF exits, plus an atexit hook that
    # terminates the child if the dashboard goes down.
    global _MOBSF_PROC, _MOBSF_TOOLS_ROOT
    with _PROC_LOCK:
        _MOBSF_PROC = proc
        _MOBSF_TOOLS_ROOT = Path(tools_root)
    monitor = threading.Thread(
        target=_monitor,
        args=(proc, Path(tools_root)),
        name=f"mobsf-monitor-{pid}",
        daemon=True,
    )
    monitor.start()
    _ensure_atexit_registered()

    return (
        True,
        f"started MobSF (pid={pid}) on port {host_port}; allow ~10s to warm up",
        {"pid": pid, "host_port": host_port, "log_path": state["log_path"]},
    )


def stop(tools_root: Path) -> Tuple[bool, str]:
    """Stop the tracked MobSF child.

    Prefers the in-memory Popen handle (clean ``terminate``/``kill``
    cycle). Falls back to an OS-PID-based kill when the dashboard was
    restarted after a previous ``start()`` and the Popen is gone.
    """
    global _MOBSF_PROC

    with _PROC_LOCK:
        proc = _MOBSF_PROC

    if proc is not None and proc.poll() is None:
        pid = proc.pid
        _terminate_proc(proc, timeout=5.0)
        with _PROC_LOCK:
            if _MOBSF_PROC is proc:
                _MOBSF_PROC = None
        _clear_state(tools_root)
        return (True, f"stopped MobSF (pid was {pid})")

    state = _load_state(tools_root)
    pid_raw = state.get("pid")
    if not pid_raw:
        return (True, "no tracked MobSF process to stop")
    try:
        pid = int(pid_raw)
    except (TypeError, ValueError):
        _clear_state(tools_root)
        return (False, "stored pid was invalid; cleared state")

    if not _pid_alive(pid):
        _clear_state(tools_root)
        return (True, f"pid {pid} was no longer running; state cleared")

    if _is_windows():
        rc, _, err = _run(["taskkill", "/PID", str(pid), "/T", "/F"], timeout=20)
        if rc != 0:
            return (False, (err or f"taskkill failed (rc={rc})").strip())
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            return (False, f"kill failed: {exc}")
        # Give it a moment, then SIGKILL if still alive.
        for _ in range(10):
            time.sleep(0.5)
            if not _pid_alive(pid):
                break
        if _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    _clear_state(tools_root)
    return (True, f"stopped MobSF (pid was {pid})")


def tail_log(tools_root: Path, *, max_bytes: int = 16 * 1024) -> str:
    """Return the tail of the run log for the UI."""
    state = _load_state(tools_root)
    log_path = state.get("log_path")
    if not log_path or not Path(log_path).is_file():
        return ""
    try:
        with open(log_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read()
    except OSError as exc:
        return f"[error] could not read log: {exc}"
    try:
        return data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return repr(data)
