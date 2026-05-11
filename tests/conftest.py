from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch):
    """
    Keep tests isolated from any real `.env` at the repo root.

    The build scripts (build.sh / build.ps1) generate a real `.env` with
    SECRET_KEY and DASHBOARD_PASSWORD_HASH. Without this fixture,
    `create_app()` would call `load_dotenv()` and that hash would override
    whatever credentials a test fixture set up, breaking auth-dependent
    tests.
    """
    for var in (
        "SECRET_KEY",
        "DASHBOARD_PASSWORD",
        "DASHBOARD_PASSWORD_HASH",
        "WORKSPACES_ROOT",
        "TOOLS_ROOT",
        "JAVA_EXECUTABLE",
        "AUTO_DOWNLOAD_TOOLS",
        "ENABLE_APKTOOL",
        "DECOMPILE_TIMEOUT_SEC",
        "JOB_POOL_WORKERS",
        "ENABLE_ANALYSIS",
        "ANALYSIS_AUTO_RUN",
        "ANALYSIS_WORKERS",
        "ANALYSIS_TIMEOUT_SEC",
        "ANALYSIS_TEXT_MAX_BYTES",
        "ANALYSIS_BINARY_MAX_BYTES",
        "ENABLE_GITLEAKS",
        "ENABLE_TRUFFLEHOG",
        "ENABLE_RADARE2",
        "ENABLE_APKID",
        "ENABLE_PLUGINS",
        "PLUGINS_CONFIG",
        "ENABLE_MOBSF",
        "MOBSF_URL",
        "MOBSF_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setattr("apk_web.app.load_dotenv", lambda *a, **kw: False)
    yield
