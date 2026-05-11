from __future__ import annotations

import logging
import platform
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

JADX_VERSION = "1.5.5"
JADX_ZIP_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"

APKTOOL_VERSION = "2.11.1"
APKTOOL_JAR_URL = (
    f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/"
    f"apktool_{APKTOOL_VERSION}.jar"
)

GITLEAKS_VERSION = "8.18.4"
TRUFFLEHOG_VERSION = "3.83.7"
RADARE2_VERSION = "6.1.4"


def _download_bytes(url: str, *, timeout_sec: int = 180) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "apk_web-tools-bootstrap/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        return resp.read()


def _atomic_write_bytes(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)


def ensure_jadx_distribution(tools_root: Path, *, logger: logging.Logger | None = None) -> bool:
    """
    Ensure `tools/jadx/lib/jadx-*-all.jar` exists by downloading the official zip when missing.
    Returns True if a download/extract happened.
    """
    from apk_web.tools_paths import find_jadx_cli_jar

    try:
        find_jadx_cli_jar(tools_root)
        return False
    except FileNotFoundError:
        pass

    if logger:
        logger.info("JADX not found under %s; downloading %s ...", tools_root, JADX_ZIP_URL)

    data = _download_bytes(JADX_ZIP_URL)
    jadx_root = tools_root / "jadx"
    jadx_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="jadx-unzip-") as td_raw:
        td = Path(td_raw)
        zip_path = td / "jadx.zip"
        zip_path.write_bytes(data)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(td)

        extracted_root = td
        lib_dir = td / "lib"
        if not lib_dir.is_dir():
            candidates = [p for p in td.iterdir() if p.is_dir() and (p / "lib").is_dir()]
            if not candidates:
                raise RuntimeError("Could not locate JADX root (expected lib/ after unzip).")
            extracted_root = candidates[0]

        for child in extracted_root.iterdir():
            target = jadx_root / child.name
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            if child.is_dir():
                shutil.copytree(child, target)
            else:
                shutil.copy2(child, target)

    find_jadx_cli_jar(tools_root)
    if logger:
        logger.info("JADX installed under %s", jadx_root)
    return True


def ensure_apktool_jar(tools_root: Path, *, logger: logging.Logger | None = None) -> bool:
    """
    Ensure `tools/apktool.jar` exists by downloading when missing.
    Returns True if a download happened.
    """
    dest = tools_root / "apktool.jar"
    if dest.is_file() and dest.stat().st_size > 0:
        return False

    if logger:
        logger.info("apktool.jar missing; downloading %s ...", APKTOOL_JAR_URL)
    data = _download_bytes(APKTOOL_JAR_URL)
    _atomic_write_bytes(dest, data)
    if logger:
        logger.info("apktool.jar installed at %s", dest)
    return True


def ensure_decompiler_tools(tools_root: Path, *, logger: logging.Logger | None = None) -> dict[str, bool]:
    """
    Download missing JADX / Apktool artifacts into tools_root when needed.
    """
    tools_root = Path(tools_root)
    tools_root.mkdir(parents=True, exist_ok=True)
    return {
        "jadx": ensure_jadx_distribution(tools_root, logger=logger),
        "apktool": ensure_apktool_jar(tools_root, logger=logger),
    }


# ---------------------------------------------------------------------------
# Optional secret-scanner binaries (off by default; opt-in via settings/env)
# ---------------------------------------------------------------------------


def _platform_slug() -> tuple[str, str]:
    """Return (os_slug, arch_slug) using the slugs used by upstream releases."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system.startswith("darwin"):
        os_slug = "darwin"
    elif system.startswith("windows"):
        os_slug = "windows"
    else:
        os_slug = "linux"
    if machine in ("amd64", "x86_64"):
        arch = "x64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86", "i386", "i686"):
        arch = "x32"
    else:
        arch = "x64"
    return os_slug, arch


def _extract_archive(archive_path: Path, dest_dir: Path) -> None:
    suffix = archive_path.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest_dir)
        return
    # tar.gz / tgz
    with tarfile.open(archive_path, "r:*") as tf:
        tf.extractall(dest_dir)


def _move_binary_into(tool_dir: Path, exe_name: str) -> Path:
    """Move whichever extracted binary matches *exe_name* up to tool_dir/."""
    target = tool_dir / exe_name
    if target.is_file():
        return target
    for candidate in tool_dir.rglob(exe_name):
        if candidate.is_file():
            shutil.copy2(candidate, target)
            try:
                target.chmod(target.stat().st_mode | 0o755)
            except OSError:
                pass
            return target
    raise RuntimeError(f"could not locate {exe_name} inside extracted archive at {tool_dir}")


def ensure_gitleaks(tools_root: Path, *, logger: logging.Logger | None = None) -> Path:
    """Ensure ``tools/gitleaks/gitleaks(.exe)`` exists; download if missing.

    Returns the resolved binary path.
    """
    tool_dir = Path(tools_root) / "gitleaks"
    is_windows = platform.system().lower().startswith("windows")
    exe_name = "gitleaks.exe" if is_windows else "gitleaks"
    target = tool_dir / exe_name
    if target.is_file():
        return target

    tool_dir.mkdir(parents=True, exist_ok=True)
    os_slug, arch = _platform_slug()
    ext = "zip" if is_windows else "tar.gz"
    url = (
        f"https://github.com/gitleaks/gitleaks/releases/download/"
        f"v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_{os_slug}_{arch}.{ext}"
    )
    if logger:
        logger.info("downloading gitleaks: %s", url)

    with tempfile.TemporaryDirectory(prefix="gitleaks-dl-") as td_raw:
        td = Path(td_raw)
        archive = td / f"gitleaks.{ext}"
        archive.write_bytes(_download_bytes(url))
        extract_dir = td / "ext"
        extract_dir.mkdir()
        _extract_archive(archive, extract_dir)
        # Move binary out of the temp dir into our tool_dir.
        for child in extract_dir.rglob(exe_name):
            shutil.copy2(child, target)
            break
        else:
            raise RuntimeError(f"gitleaks binary not found in archive {url}")

    try:
        target.chmod(target.stat().st_mode | 0o755)
    except OSError:
        pass
    if logger:
        logger.info("gitleaks installed at %s", target)
    return target


def ensure_trufflehog(tools_root: Path, *, logger: logging.Logger | None = None) -> Path:
    """Ensure ``tools/trufflehog/trufflehog(.exe)`` exists; download if missing."""
    tool_dir = Path(tools_root) / "trufflehog"
    is_windows = platform.system().lower().startswith("windows")
    exe_name = "trufflehog.exe" if is_windows else "trufflehog"
    target = tool_dir / exe_name
    if target.is_file():
        return target

    tool_dir.mkdir(parents=True, exist_ok=True)
    os_slug, arch = _platform_slug()
    # trufflehog uses amd64/arm64 naming, not x64/x32.
    th_arch = {"x64": "amd64", "x32": "386", "arm64": "arm64"}.get(arch, "amd64")
    url = (
        f"https://github.com/trufflesecurity/trufflehog/releases/download/"
        f"v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_{os_slug}_{th_arch}.tar.gz"
    )
    if logger:
        logger.info("downloading trufflehog: %s", url)

    with tempfile.TemporaryDirectory(prefix="trufflehog-dl-") as td_raw:
        td = Path(td_raw)
        archive = td / "trufflehog.tar.gz"
        archive.write_bytes(_download_bytes(url))
        extract_dir = td / "ext"
        extract_dir.mkdir()
        _extract_archive(archive, extract_dir)
        for child in extract_dir.rglob(exe_name):
            shutil.copy2(child, target)
            break
        else:
            raise RuntimeError(f"trufflehog binary not found in archive {url}")

    try:
        target.chmod(target.stat().st_mode | 0o755)
    except OSError:
        pass
    if logger:
        logger.info("trufflehog installed at %s", target)
    return target


def _radare2_asset() -> tuple[str, str]:
    """Return (asset_name, executable_name) for the current platform.

    The bundled installer is intentionally conservative. Official radare2
    releases provide portable Windows ZIPs, which work well for an app-local
    tools directory. Other OS packages usually need system integration.
    """
    is_windows = platform.system().lower().startswith("windows")
    if not is_windows:
        raise RuntimeError(
            "radare2 auto-install currently supports the official Windows ZIP. "
            "Install radare2 manually or put r2 on PATH for this OS."
        )

    _os_slug, arch = _platform_slug()
    if arch == "arm64":
        suffix = "w64-arm64"
    elif arch == "x32":
        suffix = "w32"
    else:
        suffix = "w64"
    return f"radare2-{RADARE2_VERSION}-{suffix}.zip", "r2.exe"


def ensure_radare2(tools_root: Path, *, logger: logging.Logger | None = None) -> Path:
    """Ensure an app-local radare2 exists under ``tools/radare2``.

    Returns the resolved ``r2(.exe)`` path. On Windows this downloads the
    official portable radare2 ZIP and extracts the full distribution because
    ``r2.exe`` depends on sibling DLL/share files.
    """
    tool_dir = Path(tools_root) / "radare2"
    existing = find_optional_tool("r2", Path(tools_root)) or find_optional_tool(
        "radare2", Path(tools_root)
    )
    if existing and tool_dir.resolve() in existing.resolve().parents:
        return existing

    asset_name, exe_name = _radare2_asset()
    url = f"https://github.com/radareorg/radare2/releases/download/{RADARE2_VERSION}/{asset_name}"
    if logger:
        logger.info("downloading radare2: %s", url)

    if tool_dir.exists():
        shutil.rmtree(tool_dir)
    tool_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="radare2-dl-") as td_raw:
        td = Path(td_raw)
        archive = td / asset_name
        archive.write_bytes(_download_bytes(url, timeout_sec=300))
        _extract_archive(archive, tool_dir)

    found = None
    for candidate in tool_dir.rglob(exe_name):
        if candidate.is_file():
            found = candidate
            break
    if found is None:
        raise RuntimeError(f"radare2 binary not found in archive {url}")

    try:
        found.chmod(found.stat().st_mode | 0o755)
    except OSError:
        pass
    if logger:
        logger.info("radare2 installed at %s", found)
    return found


def find_optional_tool(name: str, tools_root: Path) -> "Path | None":
    """Locate an optional binary by name under tools_root or on PATH."""
    is_windows = platform.system().lower().startswith("windows")
    exe = name + (".exe" if is_windows else "")
    candidates = [
        Path(tools_root) / name / exe,
        Path(tools_root) / name / "bin" / exe,
        Path(tools_root) / exe,
    ]
    for c in candidates:
        if c.is_file():
            return c
    tool_root = Path(tools_root) / ("radare2" if name in {"r2", "radare2"} else name)
    if tool_root.is_dir():
        for c in tool_root.rglob(exe):
            if c.is_file():
                return c
    found = shutil.which(name)
    return Path(found) if found else None
