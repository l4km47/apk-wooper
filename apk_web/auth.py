from __future__ import annotations

import functools
import uuid

from flask import redirect, request, session, url_for
from werkzeug.security import check_password_hash

from apk_web.config import build_password_hash_from_env


def password_hash_configured() -> bool:
    return build_password_hash_from_env() is not None


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("authenticated"):
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            from flask import jsonify

            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("pages.login"))

    return wrapped


def verify_login(password: str) -> bool:
    h = build_password_hash_from_env()
    if not h:
        return False
    return check_password_hash(h, password)


def is_valid_job_id(job_id: str) -> bool:
    try:
        uuid.UUID(job_id)
    except ValueError:
        return False
    return True
