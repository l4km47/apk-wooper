"""Inspect and install optional pip dependencies declared by plugins.

Each :class:`Plugin` may set ``pip_requires`` to a list of entries shaped
as ``"pkg"`` or ``"pkg:import_name"``. This module:

* parses those entries into ``(pkg, import_name)`` pairs,
* checks which import names are importable in the current interpreter,
* runs ``pip install`` for the requested set, streaming output line-by-line.

Only packages that are actually declared by a registered plugin are
allowed through the install endpoint, so an attacker can't ask the
dashboard to install arbitrary packages.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from apk_web.plugins.registry import Plugin


_LOG = logging.getLogger(__name__)


# `pkg[extras]==1.0` (no spaces). We tolerate environment markers / specifiers
# in the pip portion but strip them when computing the import name.
_PIP_PKG_RE = re.compile(r"^[A-Za-z0-9._-]+")


@dataclass(frozen=True)
class PluginDep:
    plugin_id: str
    plugin_name: str
    pip: str
    import_name: str
    installed: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "pip": self.pip,
            "import_name": self.import_name,
            "installed": self.installed,
        }


def _parse_entry(entry: str) -> Optional[Tuple[str, str]]:
    """Return ``(pip_spec, import_name)`` for a ``pip_requires`` entry."""
    entry = (entry or "").strip()
    if not entry:
        return None
    if ":" in entry:
        pip_part, _, import_part = entry.partition(":")
        pip_part = pip_part.strip()
        import_part = import_part.strip()
        if not pip_part or not import_part:
            return None
        return (pip_part, import_part)
    base_match = _PIP_PKG_RE.match(entry)
    if not base_match:
        return None
    # Normalize the import name: drop extras, lowercase, replace '-' with '_'
    # (common Python distribution-name convention).
    base = base_match.group(0)
    import_name = base.replace("-", "_").lower()
    return (entry, import_name)


def _is_installed(import_name: str) -> bool:
    try:
        return importlib.util.find_spec(import_name) is not None
    except (ImportError, ValueError):
        return False


def collect(plugins: Iterable[Plugin]) -> List[PluginDep]:
    """Return one :class:`PluginDep` per declared dependency."""
    out: List[PluginDep] = []
    for plugin in plugins:
        for entry in plugin.pip_requires or []:
            parsed = _parse_entry(entry)
            if not parsed:
                continue
            pip_spec, import_name = parsed
            out.append(
                PluginDep(
                    plugin_id=plugin.id,
                    plugin_name=plugin.name,
                    pip=pip_spec,
                    import_name=import_name,
                    installed=_is_installed(import_name),
                )
            )
    return out


def allowed_pip_specs(plugins: Iterable[Plugin]) -> Set[str]:
    """Set of pip specs the install endpoint is allowed to invoke."""
    specs: Set[str] = set()
    for plugin in plugins:
        for entry in plugin.pip_requires or []:
            parsed = _parse_entry(entry)
            if parsed:
                specs.add(parsed[0])
    return specs


def install_streaming(packages: List[str]) -> Iterator[str]:
    """Stream ``pip install`` output, ending with ``[result ok|error <code>]``.

    The caller is responsible for validating *packages* against the set
    returned by :func:`allowed_pip_specs`.
    """
    py_version = sys.version.split()[0]
    yield f"[client] python: {py_version}"
    yield f"[client] interpreter: {sys.executable}"
    if not packages:
        yield "[client] nothing to install"
        yield "[result ok]"
        return

    argv = [sys.executable, "-m", "pip", "install", "--upgrade", *packages]
    yield f"[client] $ {' '.join(argv[1:])}"
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        yield f"[client] failed to spawn pip: {exc}"
        yield "[result error spawn]"
        return
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            yield raw.rstrip("\r\n")
    finally:
        proc.stdout.close()
        rc = proc.wait()
    importlib.invalidate_caches()
    yield f"[client] exit {rc}"
    if rc == 0:
        yield "[result ok]"
    else:
        yield f"[result error rc{rc}]"
