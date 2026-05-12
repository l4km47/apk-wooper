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
        "ENABLE_APKID",
        "ENABLE_PLUGINS",
        "ENABLE_MOBSF",
    ):
        _refresh_bool(_bool_key)

    if os.environ.get("PLUGINS_CONFIG"):
        app.config["PLUGINS_CONFIG_PATH"] = os.environ["PLUGINS_CONFIG"]

    for _str_key in ("MOBSF_URL", "MOBSF_API_KEY"):
        if os.environ.get(_str_key) is not None:
            app.config[_str_key] = os.environ[_str_key]

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

    _maybe_autostart_mobsf(app)

    import atexit

    def _cleanup() -> None:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)

    atexit.register(_cleanup)

    return app


def _maybe_autostart_mobsf(app: Flask) -> None:
    """If ENABLE_MOBSF=true and the MobSF clone looks ready, start it.

    The child process is registered with :mod:`github_installer`'s
    ``atexit`` hook so it stops automatically when the dashboard exits.
    Failures are logged but never abort dashboard startup.
    """
    if not app.config.get("ENABLE_MOBSF", False):
        return
    if os.environ.get("APK_WOOPER_NO_MOBSF_AUTOSTART", "").lower() in {"1", "true", "yes"}:
        return
    try:
        from urllib.parse import urlparse

        from apk_web.plugins.mobsf import github_installer
    except Exception as exc:  # noqa: BLE001
        app.logger.info("MobSF auto-start skipped (import failed): %s", exc)
        return

    tools_root = Path(app.config["TOOLS_ROOT"])
    if not (github_installer.repo_path(tools_root) / ".git").is_dir():
        app.logger.info(
            "MobSF auto-start skipped: clone missing under %s. "
            "Open Plugins -> MobSF and click Clone to install it.",
            tools_root,
        )
        return

    host_port = 8000
    parsed = urlparse(str(app.config.get("MOBSF_URL") or ""))
    if parsed.port:
        host_port = int(parsed.port)

    try:
        status = github_installer.github_status(tools_root)
        if status.running:
            app.logger.info(
                "MobSF already running (pid=%s, port=%s); not starting again.",
                status.pid,
                status.host_port,
            )
            return
        ok, message, _detail = github_installer.start(tools_root, host_port=host_port)
        if ok:
            app.logger.info("MobSF auto-start: %s", message)
        else:
            app.logger.warning("MobSF auto-start: %s", message)
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("MobSF auto-start failed: %s", exc)
