"""Discover and register plugins with a Flask app.

Two kinds of plugins are loaded:

1. Built-in plugins under ``apk_web/plugins/<id>/plugin.py`` exposing a
   top-level ``PLUGIN`` object.
2. External plugins listed in ``plugins.json`` (see :mod:`apk_web.plugins.config`).

External entries can take two shapes:
* ``external_path`` points at a folder containing a ``plugin.py`` -- treated
  exactly like a built-in plugin.
* ``module`` + ``blueprint_attr`` (with optional ``external_path`` prepended to
  ``sys.path``) -- imports an arbitrary Flask blueprint without requiring the
  third-party project to know about APK Wooper. ``mode`` defaults to
  ``"iframe"`` for this shape so unmodified UIs render cleanly.

Errors are isolated per plugin and logged. A failing plugin never prevents the
dashboard from starting.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, Blueprint

from apk_web.plugins import config as plugin_config
from apk_web.plugins.registry import Plugin, PluginRegistry

_REGISTRY_KEY = "plugin_registry"
_LOADED_FLAG = "_apk_wooper_plugins_loaded"


def get_registry(app: Flask) -> PluginRegistry:
    reg = app.extensions.get(_REGISTRY_KEY)
    if reg is None:
        reg = PluginRegistry()
        app.extensions[_REGISTRY_KEY] = reg
    return reg


def discover_and_register(app: Flask) -> PluginRegistry:
    """Idempotently discover and mount all enabled plugins."""
    if app.extensions.get(_LOADED_FLAG):
        return get_registry(app)
    registry = get_registry(app)

    cfg_path = plugin_config.config_path(app.config)
    cfg = plugin_config.load(cfg_path)

    _load_builtin(app, registry, cfg)
    _load_external(app, registry, cfg)

    app.extensions[_LOADED_FLAG] = True
    return registry


def _load_builtin(app: Flask, registry: PluginRegistry, cfg: Dict[str, Any]) -> None:
    builtin_root = Path(__file__).resolve().parent
    if not builtin_root.is_dir():
        return
    for child in sorted(builtin_root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("_") or child.name in {"templates"}:
            continue
        plugin_file = child / "plugin.py"
        if not plugin_file.is_file():
            continue
        plugin_id = child.name
        if not plugin_config.is_enabled(cfg, plugin_id):
            continue
        module_name = f"apk_web.plugins.{plugin_id}.plugin"
        try:
            module = importlib.import_module(module_name)
            plugin = _coerce_plugin(module, plugin_id, source="builtin")
            if plugin is None:
                raise RuntimeError(
                    f"{module_name} did not expose a PLUGIN with a blueprint"
                )
            _register_plugin(app, registry, plugin)
        except Exception as exc:  # noqa: BLE001 - isolate per plugin
            _record_failure(app, registry, plugin_id, exc)


def _load_external(app: Flask, registry: PluginRegistry, cfg: Dict[str, Any]) -> None:
    for entry in cfg.get("external", []):
        plugin_id = entry.get("id")
        if not plugin_id:
            continue
        if not plugin_config.is_enabled(cfg, plugin_id):
            continue
        if plugin_id in registry.ids():
            registry.record_error(plugin_id, "duplicate plugin id; skipped external entry")
            continue
        try:
            plugin = _load_external_entry(entry)
            _register_plugin(app, registry, plugin)
        except Exception as exc:  # noqa: BLE001
            _record_failure(app, registry, plugin_id, exc)


def _load_external_entry(entry: Dict[str, Any]) -> Plugin:
    plugin_id = str(entry["id"])
    external_path = entry.get("external_path")
    module_name = entry.get("module")
    blueprint_attr = entry.get("blueprint_attr") or "bp"
    mode = entry.get("mode") or "iframe"

    if external_path:
        external_path = str(external_path)
        if external_path not in sys.path:
            sys.path.insert(0, external_path)

    if module_name:
        module = importlib.import_module(module_name)
        bp = _resolve_attr(module, blueprint_attr)
        if isinstance(bp, Blueprint):
            blueprint = bp
        elif callable(bp):
            blueprint = bp()
            if not isinstance(blueprint, Blueprint):
                raise TypeError(
                    f"callable {module_name}.{blueprint_attr} did not return a Blueprint"
                )
        else:
            raise TypeError(
                f"{module_name}.{blueprint_attr} is not a Blueprint (got {type(bp).__name__})"
            )
        return Plugin(
            id=plugin_id,
            name=str(entry.get("name") or plugin_id),
            description=str(entry.get("description") or ""),
            version=str(entry.get("version") or "0.0.0"),
            icon=entry.get("icon"),
            source="external",
            mode=mode,
            accepts=list(entry.get("accepts") or []),
            blueprint=blueprint,
        )

    if external_path:
        plugin_file = Path(external_path) / "plugin.py"
        if not plugin_file.is_file():
            raise FileNotFoundError(
                f"external plugin folder has no plugin.py: {external_path}"
            )
        module = _load_from_file(plugin_file, f"_apk_external_{plugin_id}")
        plugin = _coerce_plugin(module, plugin_id, source="external")
        if plugin is None:
            raise RuntimeError(
                f"external plugin {plugin_id} did not expose PLUGIN with a blueprint"
            )
        return plugin

    raise ValueError(
        f"external plugin {plugin_id} needs either 'module' or 'external_path'"
    )


def _coerce_plugin(module: Any, plugin_id: str, *, source: str) -> Optional[Plugin]:
    plugin = getattr(module, "PLUGIN", None)
    if not isinstance(plugin, Plugin):
        return None
    if not plugin.blueprint or not isinstance(plugin.blueprint, Blueprint):
        return None
    # Force the on-disk folder name to win over a mismatched manifest id.
    if plugin.id != plugin_id:
        plugin.id = plugin_id
    plugin.source = source
    return plugin


def _register_plugin(app: Flask, registry: PluginRegistry, plugin: Plugin) -> None:
    if plugin.blueprint is None:
        raise RuntimeError(f"plugin {plugin.id} has no blueprint")
    url_prefix = f"/plugins/{plugin.id}"
    blueprint = plugin.blueprint
    # Rename the blueprint defensively so multiple plugins can coexist even if
    # two external apps happen to use the same internal name.
    if blueprint.name != f"plugin_{plugin.id}":
        try:
            blueprint.name = f"plugin_{plugin.id}"
        except AttributeError:
            pass
    app.register_blueprint(blueprint, url_prefix=url_prefix)
    registry.add(plugin)


def _record_failure(app: Flask, registry: PluginRegistry, plugin_id: str, exc: Exception) -> None:
    msg = f"{type(exc).__name__}: {exc}"
    registry.record_error(plugin_id, msg)
    try:
        app.logger.warning(
            "plugin %r failed to load: %s\n%s", plugin_id, msg, traceback.format_exc()
        )
    except Exception:  # noqa: BLE001
        pass


def _resolve_attr(module: Any, dotted: str) -> Any:
    current = module
    for part in dotted.split("."):
        if not part:
            continue
        current = getattr(current, part)
    return current


def _load_from_file(path: Path, module_name: str) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
