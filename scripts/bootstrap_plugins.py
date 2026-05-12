"""Plugin bootstrap helper.

* Ensures ``plugins.json`` exists with the empty/expected shape so the
  dashboard's plugins UI works from the very first launch.
* When ``ENABLE_MOBSF=true`` in ``.env``, optionally clones the MobSF
  repository into ``<TOOLS_ROOT>/mobsf`` and (with ``--with-mobsf-setup``)
  runs the upstream platform setup script.

MobSF's setup is slow and may need Visual Studio Build Tools / OpenSSL on
Windows. If you skip ``--with-mobsf-setup`` here, the dashboard's
Plugins -> MobSF page exposes a "Setup" button that streams the same
output so the user can run it interactively when they're ready.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLUGINS_JSON = REPO_ROOT / "plugins.json"


def _ensure_repo_on_path() -> None:
    repo_str = str(REPO_ROOT)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)


def _load_env() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError:
        return
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        load_dotenv(env_file)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _tools_root() -> Path:
    raw = os.environ.get("TOOLS_ROOT")
    if raw:
        return Path(raw)
    return REPO_ROOT / "tools"


def _plugins_json_path() -> Path:
    raw = os.environ.get("PLUGINS_CONFIG")
    if raw:
        return Path(raw)
    return DEFAULT_PLUGINS_JSON


def _ensure_plugins_json(path: Path) -> bool:
    """Create ``plugins.json`` with an empty config when missing.

    Returns True if we wrote the file.
    """
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict) and "external" in data:
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"enabled": [], "disabled": [], "external": []}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return True


def _bootstrap_mobsf(tools_root: Path, *, run_setup: bool) -> int:
    """Clone (and optionally setup) the MobSF repo. Returns 0 on success."""
    try:
        from apk_web.plugins.mobsf import github_installer  # type: ignore
    except Exception as exc:  # noqa: BLE001
        print(f"[plugin-bootstrap] WARN: could not import mobsf installer: {exc}")
        return 1

    tools_root.mkdir(parents=True, exist_ok=True)
    repo = github_installer.repo_path(tools_root)

    if (repo / ".git").is_dir():
        print(f"[plugin-bootstrap] MobSF repo already present: {repo}")
    else:
        print(f"[plugin-bootstrap] cloning MobSF into {repo} ...")
        for line in github_installer.clone_stream(tools_root):
            print(f"[mobsf-clone] {line}")
        if not (repo / ".git").is_dir():
            print("[plugin-bootstrap] WARN: MobSF clone did not produce a .git folder")
            return 2

    if not run_setup:
        print(
            "[plugin-bootstrap] skipped MobSF setup; run it from "
            "Plugins -> MobSF -> Setup, or pass --with-mobsf-setup."
        )
        return 0

    print(f"[plugin-bootstrap] running MobSF setup in {repo} ... (this can take a while)")
    last_line = ""
    for line in github_installer.setup_stream(tools_root):
        print(f"[mobsf-setup] {line}")
        last_line = line
    if "[exit 0]" in last_line:
        print("[plugin-bootstrap] MobSF setup completed")
        return 0
    print(
        "[plugin-bootstrap] WARN: MobSF setup did not finish cleanly. "
        "Check the log above; common causes on Windows are missing Visual "
        "Studio Build Tools or OpenSSL. You can retry from Plugins -> MobSF."
    )
    return 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--with-mobsf-setup",
        action="store_true",
        help="Also run MobSF's platform setup script after cloning.",
    )
    parser.add_argument(
        "--skip-mobsf",
        action="store_true",
        help="Do not touch the MobSF repo even when ENABLE_MOBSF=true.",
    )
    args = parser.parse_args(argv)

    _ensure_repo_on_path()
    _load_env()

    if not _env_bool("ENABLE_PLUGINS", True):
        print("[plugin-bootstrap] ENABLE_PLUGINS=false; nothing to do.")
        return 0

    plugins_json = _plugins_json_path()
    if _ensure_plugins_json(plugins_json):
        print(f"[plugin-bootstrap] wrote starter {plugins_json}")
    else:
        print(f"[plugin-bootstrap] reusing existing {plugins_json}")

    mobsf_enabled = _env_bool("ENABLE_MOBSF", True)
    if not mobsf_enabled:
        print("[plugin-bootstrap] ENABLE_MOBSF=false; skipping MobSF clone.")
        return 0
    if args.skip_mobsf:
        print("[plugin-bootstrap] --skip-mobsf; not touching MobSF repo.")
        return 0

    return _bootstrap_mobsf(_tools_root(), run_setup=args.with_mobsf_setup)


if __name__ == "__main__":
    raise SystemExit(main())
