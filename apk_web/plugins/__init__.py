"""Plugin system for APK Wooper.

Plugins can be either:
- Built-in: a folder under ``apk_web/plugins/<id>/`` containing a ``plugin.py``
  that exposes a top-level ``PLUGIN`` object (an :class:`Plugin`).
- External: a third-party Flask blueprint mounted via ``plugins.json``.

Plugins are registered as Flask blueprints under ``/plugins/<id>``.

The dashboard exposes them via the ``/api/plugins`` endpoint and a sidebar
section, and Analysis findings whose ``rule_id`` matches a plugin's ``accepts``
list gain an "Open in plugin" deep-link.
"""
from __future__ import annotations

from apk_web.plugins.loader import discover_and_register, get_registry
from apk_web.plugins.registry import Plugin, PluginRegistry
from apk_web.plugins.routes import plugins_bp

__all__ = [
    "Plugin",
    "PluginRegistry",
    "discover_and_register",
    "get_registry",
    "plugins_bp",
]
