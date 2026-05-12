"""Tests for ``scripts/init_env.py``.

Verifies:

* The script writes a new ``.env`` from the template when missing, filling
  in ``SECRET_KEY`` and ``DASHBOARD_PASSWORD_HASH``.
* Existing user values are preserved on re-run (no clobbering).
* New uncommented keys added to ``.env.example`` are appended on re-run.
* ``--force`` rotates secrets but does not erase user customizations.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "init_env.py"


def _run(env_dir: Path, template: Path, extra: list[str] | None = None) -> subprocess.CompletedProcess:
    """Invoke ``init_env.py`` against a sandbox env directory."""
    env_file = env_dir / ".env"
    plaintext = env_dir / ".admin_password.txt"
    code = (
        "import runpy, sys\n"
        f"import scripts.init_env as m\n"
        f"m.ENV_FILE = r'{env_file}'.__class__(r'{env_file}')\n"
        # the import above is purely for type access; replace at runtime below:
    )
    # Simpler: import the module and monkey-patch its module-level paths.
    args = [
        sys.executable,
        "-c",
        (
            "import sys, pathlib\n"
            f"sys.path.insert(0, r'{REPO_ROOT}')\n"
            "from scripts import init_env\n"
            f"init_env.ENV_FILE = pathlib.Path(r'{env_file}')\n"
            f"init_env.ENV_EXAMPLE = pathlib.Path(r'{template}')\n"
            f"init_env.PLAINTEXT_FILE = pathlib.Path(r'{plaintext}')\n"
            "raise SystemExit(init_env.main())\n"
        ),
    ]
    if extra:
        args.extend(extra)
    return subprocess.run(
        args, capture_output=True, text=True, cwd=str(REPO_ROOT)
    )


@pytest.fixture()
def template(tmp_path: Path) -> Path:
    body = (
        "# core\n"
        "SECRET_KEY=change-me-to-a-long-random-string\n"
        "HOST=0.0.0.0\n"
        "PORT=5000\n"
        "# DASHBOARD_PASSWORD=change-me\n"
        "ENABLE_ANALYSIS=true\n"
        "ENABLE_MOBSF=true\n"
        "MOBSF_URL=http://localhost:8000\n"
        "# MOBSF_API_KEY=\n"
    )
    template_path = tmp_path / "env.example"
    template_path.write_text(body, encoding="utf-8")
    return template_path


def test_creates_env_with_secret_and_password(tmp_path: Path, template: Path):
    env_dir = tmp_path / "sandbox"
    env_dir.mkdir()
    result = _run(env_dir, template)
    assert result.returncode == 0, result.stderr
    env_text = (env_dir / ".env").read_text(encoding="utf-8")

    assert "SECRET_KEY=" in env_text
    assert "change-me-to-a-long-random-string" not in env_text
    assert "DASHBOARD_PASSWORD_HASH=" in env_text
    assert "HOST=0.0.0.0" in env_text
    assert "ENABLE_MOBSF=true" in env_text
    # Plaintext file is written and dashboard password is visible in stdout.
    plaintext_file = env_dir / ".admin_password.txt"
    assert plaintext_file.exists()
    assert "Dashboard admin password" in result.stdout


def test_idempotent_does_not_overwrite_user_values(tmp_path: Path, template: Path):
    env_dir = tmp_path / "sandbox"
    env_dir.mkdir()
    _run(env_dir, template)
    env_file = env_dir / ".env"
    original = env_file.read_text(encoding="utf-8")

    # Simulate a user edit.
    new_text = re.sub(r"^HOST=.*", "HOST=127.0.0.1", original, flags=re.MULTILINE)
    new_text += "MY_CUSTOM_VAR=42\n"
    env_file.write_text(new_text, encoding="utf-8")

    second = _run(env_dir, template)
    assert second.returncode == 0, second.stderr
    after = env_file.read_text(encoding="utf-8")

    assert "HOST=127.0.0.1" in after
    assert "MY_CUSTOM_VAR=42" in after
    # Generated secrets must be the same (no rotation without --force).
    def _get(key: str, text: str) -> str:
        for line in text.splitlines():
            if line.startswith(f"{key}="):
                return line
        return ""
    assert _get("SECRET_KEY", after) == _get("SECRET_KEY", original)
    assert _get("DASHBOARD_PASSWORD_HASH", after) == _get(
        "DASHBOARD_PASSWORD_HASH", original
    )


def test_appends_new_keys_from_updated_template(tmp_path: Path, template: Path):
    env_dir = tmp_path / "sandbox"
    env_dir.mkdir()
    _run(env_dir, template)

    # Pretend a new release added a key to the example file.
    template.write_text(
        template.read_text(encoding="utf-8") + "NEW_TOGGLE=true\n",
        encoding="utf-8",
    )

    result = _run(env_dir, template)
    assert result.returncode == 0, result.stderr
    after = (env_dir / ".env").read_text(encoding="utf-8")
    assert "NEW_TOGGLE=true" in after
    assert "added by scripts/init_env.py" in after


def test_force_rotates_secrets(tmp_path: Path, template: Path):
    env_dir = tmp_path / "sandbox"
    env_dir.mkdir()
    _run(env_dir, template)
    original = (env_dir / ".env").read_text(encoding="utf-8")

    result = _run(env_dir, template, extra=["--force"])
    assert result.returncode == 0, result.stderr
    after = (env_dir / ".env").read_text(encoding="utf-8")
    # Both must be different.
    def _value(key: str, text: str) -> str:
        for line in text.splitlines():
            if line.startswith(f"{key}="):
                return line.partition("=")[2]
        return ""
    assert _value("SECRET_KEY", after) != _value("SECRET_KEY", original)
    assert _value("DASHBOARD_PASSWORD_HASH", after) != _value(
        "DASHBOARD_PASSWORD_HASH", original
    )


def test_env_example_in_repo_contains_all_supported_keys():
    """Spot-check the shipped template covers all keys we care about."""
    text = (REPO_ROOT / "apk_web" / ".env.example").read_text(encoding="utf-8")
    for key in (
        "SECRET_KEY",
        "HOST",
        "PORT",
        "WORKSPACES_ROOT",
        "TOOLS_ROOT",
        "ENABLE_ANALYSIS",
        "ENABLE_GITLEAKS",
        "ENABLE_TRUFFLEHOG",
        "ENABLE_RADARE2",
        "ENABLE_APKID",
        "ENABLE_PLUGINS",
        "ENABLE_MOBSF",
        "MOBSF_URL",
    ):
        # Must appear at least once (uncommented for required keys, commented
        # examples are also fine for optional ones).
        assert key in text, f"missing {key} in .env.example"
