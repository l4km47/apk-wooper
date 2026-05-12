"""Install pip dependencies declared by built-in plugins.

Walks ``apk_web/plugins/<id>/plugin.py``, reads each ``PLUGIN.pip_requires``
list, and installs any whose import name is not yet available in the current
interpreter.

External plugins (entries in ``plugins.json``) are skipped because they are
discovered after the dashboard starts; the Settings -> Plugins panel offers
the same one-click installer for them at runtime.
"""

from __future__ import annotations

import importlib
import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ensure_repo_on_path() -> None:
    repo_str = str(REPO_ROOT)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)


def _builtin_plugins() -> List[object]:
    """Import each built-in plugin module and return its ``PLUGIN`` object."""
    plugins_dir = REPO_ROOT / "apk_web" / "plugins"
    out: List[object] = []
    if not plugins_dir.is_dir():
        return out
    for child in sorted(plugins_dir.iterdir()):
        if not child.is_dir() or child.name.startswith("_"):
            continue
        if not (child / "plugin.py").is_file():
            continue
        module_name = f"apk_web.plugins.{child.name}.plugin"
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            print(f"[plugin-deps] WARN: could not import {module_name}: {exc}")
            continue
        plugin = getattr(module, "PLUGIN", None)
        if plugin is not None:
            out.append(plugin)
    return out


def _missing_specs(plugins: List[object]) -> List[str]:
    """Return a deduplicated list of pip specs whose import is missing."""
    seen: set[str] = set()
    out: List[str] = []
    try:
        from apk_web.plugins.dependencies import _parse_entry, _is_installed  # type: ignore
    except Exception as exc:  # noqa: BLE001
        print(f"[plugin-deps] WARN: cannot import dependency helpers: {exc}")
        return []
    for plugin in plugins:
        for entry in getattr(plugin, "pip_requires", None) or []:
            parsed = _parse_entry(entry)
            if not parsed:
                continue
            pip_spec, import_name = parsed
            if pip_spec in seen:
                continue
            if _is_installed(import_name):
                continue
            seen.add(pip_spec)
            out.append(pip_spec)
    return out


def main() -> int:
    _ensure_repo_on_path()
    plugins = _builtin_plugins()
    if not plugins:
        print("[plugin-deps] no built-in plugins discovered")
        return 0

    missing = _missing_specs(plugins)
    if not missing:
        print("[plugin-deps] all declared plugin pip_requires already satisfied")
        return 0

    print(f"[plugin-deps] installing: {', '.join(missing)}")
    rc = subprocess.call(
        [sys.executable, "-m", "pip", "install", "--upgrade", *missing]
    )
    if rc != 0:
        print(f"[plugin-deps] WARN: pip install exited with rc={rc}")
        return rc
    print("[plugin-deps] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
