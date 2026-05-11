"""Install APKiD via pip with sensible fallbacks and clear error reporting.

APKiD itself is pure-Python, but it depends on ``yara-python-dex`` whose
sdist on PyPI is famously broken on newer Python interpreters (the sdist
omits ``yara-python/README.rst``, so any environment that doesn't have a
prebuilt wheel falls over with::

    FileNotFoundError: [Errno 2] No such file or directory: 'yara-python/README.rst'

This module:

* prefers prebuilt wheels (``--only-binary=:all:``) so the broken source
  build is never even attempted by default;
* falls back to a source build only when the caller explicitly asks
  (``force_source=True``);
* classifies common failure tails into actionable hints so the dashboard
  can surface something more useful than "pip install failed".
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple


_LOG = logging.getLogger(__name__)


# Markers we look for in pip output to classify failures.
_NO_WHEEL_MARKERS = (
    "could not find a version that satisfies the requirement",
    "no matching distribution found",
    "no binary distribution available",
    "no compatible wheels",
    # pip >= 23 backtracks all the way down APKiD's versions before giving
    # up when yara-python / yara-python-dex have no wheel for the current
    # interpreter. The resolver phrases the failure differently:
    "no matching distributions available for your environment",
    "resolutionimpossible",
    "cannot install apkid",
)
_YARA_DEX_MARKERS = (
    "yara-python/readme.rst",
    "yara-python-dex",
)

# Marker for the missing-setuptools error seen on stock Python 3.14 venvs
# when running pip with ``--no-build-isolation``.
_MISSING_BUILD_BACKEND_MARKERS = (
    "backendunavailable",
    "cannot import 'setuptools.build_meta'",
    "cannot import 'setuptools.build_meta:__legacy__'",
)

YARA_PYTHON_DEX_GIT_URL = "https://github.com/MobSF/yara-python-dex.git"


# Supported strategies for :func:`install_streaming`.
STRATEGY_WHEEL = "wheel"          # --only-binary=:all: apkid (default first try)
STRATEGY_SOURCE = "source"        # plain `pip install apkid` (will hit the sdist bug on 3.14)
STRATEGY_GIT_SOURCE = "git_source"  # setuptools+wheel, then git+yara-python-dex --no-build-isolation, then apkid


@dataclass
class InstallResult:
    ok: bool
    installed: bool
    binary_path: Optional[str]
    log: str
    error: Optional[str] = None
    error_kind: Optional[str] = None
    hint: Optional[str] = None
    python_version: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "installed": self.installed,
            "binary_path": self.binary_path,
            "log": self.log,
            "error": self.error,
            "error_kind": self.error_kind,
            "hint": self.hint,
            "python_version": self.python_version,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def install_streaming(
    *,
    force_source: bool = False,
    strategy: str = "auto",
    timeout: int = 900,
) -> Iterator[str]:
    """Stream pip output line-by-line ending with a synthetic summary marker.

    The very last line is always one of::

        [result ok]
        [result error <kind>]

    so callers can parse outcome without re-running classification.

    Parameters
    ----------
    force_source:
        Legacy flag. ``True`` is equivalent to ``strategy="source"``.
    strategy:
        One of ``"auto"``, ``"wheel"``, ``"source"``, or ``"git_source"``.
        ``"auto"`` runs wheel-only first and stops on success; nothing falls
        back automatically because the broken-sdist path is so unhelpful.
    """
    py_version = sys.version.split()[0]
    yield f"[client] python: {py_version}"
    yield f"[client] interpreter: {sys.executable}"

    if _already_installed():
        yield "[client] apkid already importable; nothing to do."
        yield "[result ok]"
        return

    if force_source and strategy == "auto":
        strategy = STRATEGY_SOURCE

    if strategy == STRATEGY_GIT_SOURCE:
        yield from _run_git_source_strategy()
        return

    attempts: List[List[str]] = []
    if strategy in ("auto", STRATEGY_WHEEL):
        attempts.append(
            [
                sys.executable, "-m", "pip", "install", "--upgrade",
                "--only-binary=:all:", "apkid",
            ]
        )
    if strategy == STRATEGY_SOURCE:
        attempts.append(
            [sys.executable, "-m", "pip", "install", "--upgrade", "apkid"]
        )

    yield from _run_attempts_and_classify(
        attempts, python_version=py_version, success_check=_already_installed
    )


def _run_attempts_and_classify(
    attempts: List[List[str]],
    *,
    python_version: str,
    success_check,
) -> Iterator[str]:
    combined: List[str] = []
    last_rc: int = 1
    for argv in attempts:
        yield f"[client] $ {' '.join(argv[1:])}"
        rc, lines = _stream_subprocess(argv)
        combined.extend(lines)
        for line in lines:
            yield line
        last_rc = rc
        yield f"[client] exit {last_rc}"
        if last_rc == 0:
            break

    importlib.invalidate_caches()
    if last_rc == 0 and success_check():
        yield "[result ok]"
        return

    kind, hint = _classify("\n".join(combined), python_version=python_version)
    if hint:
        yield f"[client] hint: {hint}"
    else:
        yield "[client] install failed"
    yield f"[result error {kind}]"


def _stream_subprocess(argv: List[str]) -> Tuple[int, List[str]]:
    """Run *argv* and return ``(returncode, captured_lines)``.

    Lines are also appended to the iterator the caller is yielding from,
    so this helper is meant to be used only from the streaming functions.
    Callers should yield each line themselves; we return them here so the
    classifier can see the full log.
    """
    lines: List[str] = []
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        lines.append(f"[client] failed to spawn process: {exc}")
        return (-1, lines)
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            lines.append(raw.rstrip("\r\n"))
    finally:
        proc.stdout.close()
        rc = proc.wait()
    return (rc, lines)


def _run_git_source_strategy() -> Iterator[str]:
    """Install APKiD by building yara-python-dex from git.

    Sequence:

    1. Ensure ``setuptools`` and ``wheel`` are installed (needed because
       Python 3.14 venvs ship without setuptools, which ``--no-build-isolation``
       requires).
    2. ``pip install --no-build-isolation git+<yara-python-dex>``.
    3. ``pip install apkid``.

    Any step failing aborts the run with a classified error.
    """
    py_version = sys.version.split()[0]
    yield "[client] strategy: git_source"
    yield (
        "[client] this builds yara-python-dex from GitHub with "
        "--no-build-isolation; first ensures setuptools+wheel are present."
    )

    steps: List[Tuple[str, List[str]]] = [
        (
            "setuptools+wheel",
            [
                sys.executable, "-m", "pip", "install", "--upgrade",
                "setuptools", "wheel",
            ],
        ),
        (
            "yara-python-dex (git)",
            [
                sys.executable, "-m", "pip", "install", "--upgrade",
                "--no-build-isolation",
                f"git+{YARA_PYTHON_DEX_GIT_URL}",
            ],
        ),
        (
            "apkid",
            [sys.executable, "-m", "pip", "install", "--upgrade", "apkid"],
        ),
    ]

    combined: List[str] = []
    for label, argv in steps:
        yield f"[client] step: {label}"
        yield f"[client] $ {' '.join(argv[1:])}"
        rc, lines = _stream_subprocess(argv)
        combined.extend(lines)
        for line in lines:
            yield line
        yield f"[client] exit {rc}"
        if rc != 0:
            importlib.invalidate_caches()
            kind, hint = _classify(
                "\n".join(combined), python_version=py_version
            )
            if hint:
                yield f"[client] hint: {hint}"
            yield f"[result error {kind}]"
            return

    importlib.invalidate_caches()
    if _already_installed():
        yield "[result ok]"
        return

    kind, hint = _classify("\n".join(combined), python_version=py_version)
    if hint:
        yield f"[client] hint: {hint}"
    yield f"[result error {kind}]"


def install_blocking(
    *,
    force_source: bool = False,
    strategy: str = "auto",
    timeout: int = 900,
) -> InstallResult:
    """Synchronous variant of :func:`install_streaming`.

    Used by the JSON endpoint that wants a single response object.
    """
    py_version = sys.version.split()[0]
    lines: List[str] = []
    final_kind: Optional[str] = None
    for line in install_streaming(
        force_source=force_source, strategy=strategy, timeout=timeout
    ):
        lines.append(line)
        if line.startswith("[result "):
            final_kind = line[len("[result "):].rstrip("]").strip()
    log = "\n".join(lines)

    if final_kind == "ok":
        spec = importlib.util.find_spec("apkid")
        return InstallResult(
            ok=True,
            installed=spec is not None,
            binary_path=getattr(spec, "origin", None) if spec else None,
            log=log,
            python_version=py_version,
        )

    kind = (final_kind or "error error").split()[-1] if final_kind else "unknown"
    _, hint = _classify(log, python_version=py_version)
    return InstallResult(
        ok=False,
        installed=_already_installed(),
        binary_path=None,
        log=log,
        error="pip install failed",
        error_kind=kind,
        hint=hint,
        python_version=py_version,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _already_installed() -> bool:
    return importlib.util.find_spec("apkid") is not None


def _classify(log: str, *, python_version: str) -> Tuple[str, Optional[str]]:
    """Return ``(kind, hint)`` for a failed install log."""
    lc = (log or "").lower()
    if any(marker in lc for marker in _MISSING_BUILD_BACKEND_MARKERS):
        return (
            "missing_build_backend",
            "pip can't find setuptools.build_meta in your venv. Stock Python 3.14 "
            "venvs ship without setuptools. Use the \"Install via GitHub source\" "
            "button (it runs `pip install setuptools wheel` first) or run that "
            "command manually before retrying.",
        )
    if any(marker in lc for marker in _YARA_DEX_MARKERS) and "readme.rst" in lc:
        py = python_version or sys.version.split()[0]
        major_minor = ".".join(py.split(".")[:2]) or py
        hint = (
            "yara-python-dex (an APKiD dependency) ships a broken sdist on PyPI: "
            "its setup.py opens a README file that isn't included in the tarball. "
            f"Your interpreter (Python {major_minor}) does not have a prebuilt wheel for it. "
            "Click \"Install via GitHub source\" to build yara-python-dex from its "
            "git repo with --no-build-isolation, or install APKiD into a Python "
            "3.11/3.12 venv where wheels exist."
        )
        return ("yara_python_dex_sdist_bug", hint)
    if any(marker in lc for marker in _NO_WHEEL_MARKERS):
        py = python_version or sys.version.split()[0]
        major_minor = ".".join(py.split(".")[:2]) or py
        hint = (
            f"No prebuilt APKiD wheel is available for Python {major_minor} on this platform. "
            "Try \"Install via GitHub source\" (builds yara-python-dex from its git "
            "repo) or run APK Wooper under Python 3.11/3.12 to use prebuilt wheels."
        )
        return ("no_wheel", hint)
    if "permission denied" in lc or "errno 13" in lc:
        return (
            "permission_denied",
            "pip refused to write to site-packages. Run the dashboard inside a virtualenv "
            "(recommended) or grant the install user write access.",
        )
    if "could not connect" in lc or "name or service not known" in lc:
        return (
            "network",
            "pip could not reach PyPI. Check your network / proxy settings and try again.",
        )
    if "git: command not found" in lc or "git was not found" in lc or "is not recognized as an internal or external command" in lc:
        return (
            "git_missing",
            "git is required for the GitHub source strategy. Install Git "
            "(https://git-scm.com/download) and retry.",
        )
    return ("error", "pip install failed; see the log above for the underlying error.")
