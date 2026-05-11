from __future__ import annotations

import os
from pathlib import Path

from werkzeug.security import generate_password_hash


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-insecure-change-me"
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(200 * 1024 * 1024)))

    REPO_ROOT = _repo_root()
    WORKSPACES_ROOT = Path(os.environ.get("WORKSPACES_ROOT", str(REPO_ROOT / "workspaces")))
    TOOLS_ROOT = Path(os.environ.get("TOOLS_ROOT", str(REPO_ROOT / "tools")))

    # Optional: force a specific java binary (otherwise auto-detect newest suitable JDK).
    _java_exe = os.environ.get("JAVA_EXECUTABLE", "").strip()
    JAVA_EXECUTABLE = _java_exe or None

    AUTO_DOWNLOAD_TOOLS = _env_bool("AUTO_DOWNLOAD_TOOLS", True)

    # Skip rescanning the machine for every decompile; refresh via GET /api/java-runtimes?refresh=1
    JAVA_DISCOVERY_CACHE_SEC = int(os.environ.get("JAVA_DISCOVERY_CACHE_SEC", str(10 * 60)))

    # JADX requires Java 11+ bytecode; default matches bundled JADX releases.
    MIN_JAVA_MAJOR = int(os.environ.get("MIN_JAVA_MAJOR", "11"))

    ENABLE_APKTOOL = _env_bool("ENABLE_APKTOOL", True)

    DECOMPILE_TIMEOUT_SEC = int(os.environ.get("DECOMPILE_TIMEOUT_SEC", str(60 * 45)))
    JOB_POOL_WORKERS = int(os.environ.get("JOB_POOL_WORKERS", "2"))

    FILE_READ_MAX_BYTES = int(os.environ.get("FILE_READ_MAX_BYTES", str(5 * 1024 * 1024)))

    # Static analysis engine
    ENABLE_ANALYSIS = _env_bool("ENABLE_ANALYSIS", True)
    ANALYSIS_AUTO_RUN = _env_bool("ANALYSIS_AUTO_RUN", True)
    ANALYSIS_WORKERS = int(
        os.environ.get("ANALYSIS_WORKERS", str(max(2, (os.cpu_count() or 4) // 2)))
    )
    ANALYSIS_TIMEOUT_SEC = int(os.environ.get("ANALYSIS_TIMEOUT_SEC", str(600)))
    ANALYSIS_TEXT_MAX_BYTES = int(
        os.environ.get("ANALYSIS_TEXT_MAX_BYTES", str(5 * 1024 * 1024))
    )
    ANALYSIS_BINARY_MAX_BYTES = int(
        os.environ.get("ANALYSIS_BINARY_MAX_BYTES", str(200 * 1024 * 1024))
    )
    ENABLE_GITLEAKS = _env_bool("ENABLE_GITLEAKS", False)
    ENABLE_TRUFFLEHOG = _env_bool("ENABLE_TRUFFLEHOG", False)
    ENABLE_RADARE2 = _env_bool("ENABLE_RADARE2", False)
    ENABLE_APKID = _env_bool("ENABLE_APKID", False)

    # Plugin system
    ENABLE_PLUGINS = _env_bool("ENABLE_PLUGINS", True)
    _plugins_config = os.environ.get("PLUGINS_CONFIG", "").strip()
    PLUGINS_CONFIG_PATH = _plugins_config or str(_repo_root() / "plugins.json")

    # MobSF plugin
    ENABLE_MOBSF = _env_bool("ENABLE_MOBSF", True)
    MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000").strip()
    MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "").strip()

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


def build_password_hash_from_env() -> str | None:
    """
    Password for dashboard login.
    Prefer DASHBOARD_PASSWORD_HASH (werkzeug scrypt); else set DASHBOARD_PASSWORD for bootstrap hash.
    """
    h = os.environ.get("DASHBOARD_PASSWORD_HASH")
    if h:
        return h.strip()
    plain = os.environ.get("DASHBOARD_PASSWORD")
    if plain:
        return generate_password_hash(plain.strip())
    return None
