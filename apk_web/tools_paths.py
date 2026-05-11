from __future__ import annotations

from pathlib import Path


def find_jadx_cli_jar(tools_root: Path) -> Path:
    lib = tools_root / "jadx" / "lib"
    if not lib.is_dir():
        raise FileNotFoundError(f"JADX lib folder not found: {lib}")
    jars = sorted(lib.glob("jadx-*-all.jar"))
    if not jars:
        raise FileNotFoundError(
            f"No jadx-*-all.jar under {lib}. Run scripts/bootstrap_tools.ps1 or bootstrap_tools.sh "
            "and see tools/README.md."
        )
    return jars[0]


def find_apktool_jar(tools_root: Path) -> Path:
    p = tools_root / "apktool.jar"
    if not p.is_file():
        raise FileNotFoundError(
            f"Missing {p}. Run scripts/bootstrap_tools.ps1 or bootstrap_tools.sh and see tools/README.md."
        )
    return p
