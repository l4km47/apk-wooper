"""Plugin data model and in-memory registry."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from flask import Blueprint


@dataclass
class Plugin:
    """Manifest for a single plugin.

    A plugin module should expose a top-level ``PLUGIN`` instance of this class
    (with ``blueprint`` populated). The blueprint will be mounted at
    ``/plugins/<id>``.

    Fields:
        id: Stable slug. Becomes the URL prefix segment.
        name: Human readable label shown in the sidebar / plugins index.
        description: One-line description.
        version: Semver-ish string, advisory only.
        icon: Optional URL to an icon (rendered in the index card).
        source: "builtin" if discovered from ``apk_web/plugins/<id>/`` else
            "external" (entry in ``plugins.json``).
        mode: "native" means the plugin renders its own UI under
            ``/plugins/<id>/`` (its templates can extend
            ``plugins/plugin_base.html``). "iframe" means the dashboard wraps
            the plugin's root URL in an iframe so an unmodified third-party
            Flask app can be reused as-is.
        accepts: List of Analysis ``rule_id`` strings (e.g.
            ``"secret.firebase_api_key"``) the plugin can consume. Used to
            decide which findings get an "Open in plugin" button in the
            Analysis tab.
        blueprint: Flask Blueprint to mount. Must be set for the plugin to be
            registered.
        health: Optional callable returning ``{"ok": bool, "message": str}``;
            shown as a status badge in the plugins index.
    """

    id: str
    name: str
    description: str = ""
    version: str = "0.0.0"
    icon: Optional[str] = None
    source: str = "builtin"
    mode: str = "native"
    accepts: List[str] = field(default_factory=list)
    blueprint: Optional[Blueprint] = None
    health: Optional[Callable[[], Dict[str, Any]]] = None

    def to_public_dict(self, *, healthy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "icon": self.icon,
            "source": self.source,
            "mode": self.mode,
            "accepts": list(self.accepts),
            "url": f"/plugins/{self.id}",
            "healthy": healthy if healthy is not None else {"ok": True, "message": ""},
        }


class PluginRegistry:
    """Holds the set of successfully loaded plugins and any load errors."""

    def __init__(self) -> None:
        self._plugins: Dict[str, Plugin] = {}
        self._errors: List[Dict[str, str]] = []

    def add(self, plugin: Plugin) -> None:
        if plugin.id in self._plugins:
            raise ValueError(f"plugin id already registered: {plugin.id}")
        self._plugins[plugin.id] = plugin

    def all(self) -> List[Plugin]:
        return sorted(self._plugins.values(), key=lambda p: p.name.lower())

    def get(self, plugin_id: str) -> Optional[Plugin]:
        return self._plugins.get(plugin_id)

    def ids(self) -> Iterable[str]:
        return self._plugins.keys()

    def record_error(self, source: str, error: str) -> None:
        self._errors.append({"source": source, "error": error})

    def errors(self) -> List[Dict[str, str]]:
        return list(self._errors)

    def accepts_for(self, rule_id: str) -> List[Plugin]:
        if not rule_id:
            return []
        out: List[Plugin] = []
        for plugin in self._plugins.values():
            if rule_id in plugin.accepts:
                out.append(plugin)
        return out
