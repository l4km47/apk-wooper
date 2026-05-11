"""WSGI middleware that gates a sub-app behind the parent Flask login session.

When we mount a foreign Flask app (or any WSGI app) under ``/plugins/<id>`` via
``DispatcherMiddleware``, those requests bypass the parent app's blueprint
dispatch entirely. That means the parent's ``@login_required`` decorators
never run, and the sub-app would be reachable without authentication.

This middleware reads the parent's session cookie, validates it with the
parent's :class:`SessionInterface`, and only forwards to the sub-app if the
session is authenticated. Otherwise it returns a 302 to ``/login``.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable

from flask import Flask
from werkzeug.wrappers import Request


_RedirectStartResponse = Callable[[str, list], Any]


def build_auth_gate(parent_app: Flask, sub_app: Any) -> Callable:
    """Return a WSGI callable that proxies to ``sub_app`` if authed."""

    cookie_name = parent_app.config.get("SESSION_COOKIE_NAME", "session")
    session_interface = parent_app.session_interface

    def _is_authed(environ: dict) -> bool:
        try:
            req = Request(environ)
            session = session_interface.open_session(parent_app, req)
            if session is None:
                return False
            return bool(session.get("authenticated"))
        except Exception:  # noqa: BLE001
            return False

    def application(environ: dict, start_response: _RedirectStartResponse) -> Iterable[bytes]:
        if not _is_authed(environ):
            location = "/login"
            start_response(
                "302 Found",
                [("Location", location), ("Content-Type", "text/plain; charset=utf-8")],
            )
            return [b"Authentication required."]
        return sub_app(environ, start_response)

    # Carry over a useful __name__ for debugging.
    application.__name__ = f"auth_gate({getattr(sub_app, '__name__', 'sub_app')})"
    # Stash a reference to the original cookie name for tests/inspection.
    application.cookie_name = cookie_name  # type: ignore[attr-defined]
    return application
