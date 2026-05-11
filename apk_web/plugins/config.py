"""Read/write the on-disk plugin configuration (``plugins.json``).

Schema::

    {
      "enabled": ["firebase", "gmap"],
      "disabled": ["broken-plugin"],
      "external": [
        {
          "id": "gmap",
          "name": "Google Maps Toolkit",
          "description": "...",
          "external_path": "C:/path/to/parent/of/package",
          "module": "gmap_web",
          "blueprint_attr": "routes.bp",
          "mode": "iframe",
          "accepts": ["secret.google_api_key"]
        }
      ]
    }

``external_path`` is appended to ``sys.path`` so ``module`` becomes importable.
``blueprint_attr`` is a dotted path resolved against the imported module
(e.g. ``"routes.bp"`` -> ``module.routes.bp``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


def config_path(app_config: Dict[str, Any]) -> Path:
    """Resolve the plugins.json path from app config (with env fallback)."""
    raw = app_config.get("PLUGINS_CONFIG_PATH") or os.environ.get("PLUGINS_CONFIG")
    if raw:
        return Path(raw)
    repo_root = Path(app_config.get("REPO_ROOT", Path.cwd()))
    return repo_root / "plugins.json"


def load(path: Path) -> Dict[str, Any]:
    """Load the config file, returning a normalised dict.

    Missing files are treated as an empty config rather than an error so the
    plugin system works out-of-the-box.
    """
    if not path.is_file():
        return _empty_config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_config()
    if not isinstance(data, dict):
        return _empty_config()
    return _normalise(data)


def save(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(_normalise(data), indent=2, sort_keys=False), encoding="utf-8")
    os.replace(tmp, path)


def _empty_config() -> Dict[str, Any]:
    return {"enabled": [], "disabled": [], "external": []}


def _normalise(data: Dict[str, Any]) -> Dict[str, Any]:
    enabled = data.get("enabled") or []
    disabled = data.get("disabled") or []
    external = data.get("external") or []
    if not isinstance(enabled, list):
        enabled = []
    if not isinstance(disabled, list):
        disabled = []
    if not isinstance(external, list):
        external = []
    cleaned_external: List[Dict[str, Any]] = []
    for entry in external:
        if not isinstance(entry, dict):
            continue
        if not entry.get("id"):
            continue
        cleaned_external.append(
            {
                "id": str(entry.get("id")),
                "name": str(entry.get("name") or entry.get("id")),
                "description": str(entry.get("description") or ""),
                "external_path": (str(entry["external_path"]) if entry.get("external_path") else None),
                "module": str(entry.get("module") or "") or None,
                "blueprint_attr": str(entry.get("blueprint_attr") or "bp"),
                "mode": str(entry.get("mode") or "iframe"),
                "accepts": list(entry.get("accepts") or []),
                "version": str(entry.get("version") or "0.0.0"),
                "icon": entry.get("icon"),
            }
        )
    return {
        "enabled": [str(x) for x in enabled],
        "disabled": [str(x) for x in disabled],
        "external": cleaned_external,
    }


def is_enabled(cfg: Dict[str, Any], plugin_id: str) -> bool:
    enabled = cfg.get("enabled") or []
    disabled = cfg.get("disabled") or []
    if plugin_id in disabled:
        return False
    if not enabled:
        return True
    return plugin_id in enabled


def upsert_external(cfg: Dict[str, Any], entry: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _normalise(dict(cfg))
    plugin_id = str(entry.get("id") or "").strip()
    if not plugin_id:
        raise ValueError("missing plugin id")
    cfg["external"] = [e for e in cfg["external"] if e["id"] != plugin_id]
    cfg["external"].append(
        _normalise({"external": [entry]})["external"][0]
    )
    return cfg


def remove_external(cfg: Dict[str, Any], plugin_id: str) -> Dict[str, Any]:
    cfg = _normalise(dict(cfg))
    cfg["external"] = [e for e in cfg["external"] if e["id"] != plugin_id]
    return cfg


def set_enabled(cfg: Dict[str, Any], plugin_id: str, enabled: bool) -> Dict[str, Any]:
    cfg = _normalise(dict(cfg))
    enabled_list = list(cfg["enabled"])
    disabled_list = list(cfg["disabled"])
    if enabled:
        if plugin_id in disabled_list:
            disabled_list.remove(plugin_id)
        if plugin_id not in enabled_list:
            enabled_list.append(plugin_id)
    else:
        if plugin_id in enabled_list:
            enabled_list.remove(plugin_id)
        if plugin_id not in disabled_list:
            disabled_list.append(plugin_id)
    cfg["enabled"] = enabled_list
    cfg["disabled"] = disabled_list
    return cfg
