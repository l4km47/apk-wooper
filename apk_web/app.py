from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask

from apk_web.config import Config, build_password_hash_from_env
from apk_web.job_store import JobStore
from apk_web.routes.api import api_bp
from apk_web.routes.pages import pages_bp


def create_app() -> Flask:
    load_dotenv()
    if not build_password_hash_from_env():
        raise RuntimeError(
            "Set DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH in the environment "
            "(see apk_web README / .env.example)."
        )

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
        instance_relative_config=False,
    )
    app.config.from_object(Config)

    # Config class attributes are evaluated at import time, so env vars set
    # after that (notably in tests via monkeypatch) wouldn't be reflected.
    # Re-apply the env-overridable settings explicitly here.
    secret = os.environ.get("SECRET_KEY")
    if secret:
        app.config["SECRET_KEY"] = secret

    for _path_var in ("WORKSPACES_ROOT", "TOOLS_ROOT"):
        if os.environ.get(_path_var):
            app.config[_path_var] = Path(os.environ[_path_var])

    if os.environ.get("JAVA_EXECUTABLE"):
        app.config["JAVA_EXECUTABLE"] = os.environ["JAVA_EXECUTABLE"]

    # Re-read boolean toggles that may have changed after module import
    # (tests rely on monkeypatching these via env).
    def _refresh_bool(env_key: str) -> None:
        raw = os.environ.get(env_key)
        if raw is None:
            return
        app.config[env_key] = raw.lower() in {"1", "true", "yes", "on"}

    for _bool_key in (
        "AUTO_DOWNLOAD_TOOLS",
        "ENABLE_APKTOOL",
        "ENABLE_ANALYSIS",
        "ANALYSIS_AUTO_RUN",
        "ENABLE_GITLEAKS",
        "ENABLE_TRUFFLEHOG",
        "ENABLE_RADARE2",
        "ENABLE_PLUGINS",
    ):
        _refresh_bool(_bool_key)

    if os.environ.get("PLUGINS_CONFIG"):
        app.config["PLUGINS_CONFIG_PATH"] = os.environ["PLUGINS_CONFIG"]

    workspaces = Path(app.config["WORKSPACES_ROOT"])
    workspaces.mkdir(parents=True, exist_ok=True)

    store = JobStore(workspaces)
    app.extensions["job_store"] = store

    executor = ThreadPoolExecutor(max_workers=int(app.config["JOB_POOL_WORKERS"]))
    app.extensions["executor"] = executor

    if app.config.get("AUTO_DOWNLOAD_TOOLS", True):
        try:
            from apk_web.tools_bootstrap import ensure_decompiler_tools

            ensure_decompiler_tools(Path(app.config["TOOLS_ROOT"]), logger=app.logger)
        except Exception as exc:
            app.logger.warning("AUTO_DOWNLOAD_TOOLS failed (continuing): %s", exc)

    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)

    if app.config.get("ENABLE_PLUGINS", True):
        try:
            from apk_web.plugins import discover_and_register, plugins_bp

            app.register_blueprint(plugins_bp)
            discover_and_register(app)
        except Exception as exc:  # noqa: BLE001
            app.logger.warning("plugin discovery failed (continuing): %s", exc)

    import atexit

    def _cleanup() -> None:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)

    atexit.register(_cleanup)

    return app
