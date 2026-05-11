from __future__ import annotations

import dataclasses
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from apk_web.java_resolve import MIN_JAVA_MAJOR, parse_java_major_from_output

_INVENTORY_LOCK = threading.RLock()


@dataclasses.dataclass
class JavaRuntime:
    path: str
    major: int
    version_text: str

    def as_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "major": self.major, "version_text": self.version_text}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unique_paths(paths: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for p in paths:
        try:
            rp = str(Path(p).resolve())
        except OSError:
            continue
        if rp in seen:
            continue
        seen.add(rp)
        out.append(rp)
    return out


def _collect_candidate_java_paths() -> List[str]:
    candidates: List[str] = []

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        home = Path(java_home)
        for name in ("java.exe", "java"):
            j = home / "bin" / name
            if j.is_file():
                candidates.append(str(j))

    try:
        import shutil

        w = shutil.which("java")
        if w:
            candidates.append(w)
    except Exception:
        pass

    if sys.platform == "win32":
        candidates.extend(_windows_candidate_java_paths())
        candidates.extend(_windows_registry_java_homes())
    elif sys.platform == "darwin":
        candidates.extend(_macos_candidate_java_paths())
    else:
        candidates.extend(_linux_candidate_java_paths())

    return _unique_paths(candidates)


def _windows_candidate_java_paths() -> List[str]:
    out: List[str] = []
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    bases = [Path(pf), Path(pf86)]
    for base in bases:
        if not base.is_dir():
            continue
        for glob_pat in (
            "Java/*/bin/java.exe",
            "Eclipse Adoptium/*/bin/java.exe",
            "Microsoft/*/bin/java.exe",
            "Amazon Corretto/*/bin/java.exe",
            "Zulu/*/bin/java.exe",
        ):
            try:
                for p in base.glob(glob_pat):
                    if p.is_file():
                        out.append(str(p))
            except OSError:
                continue

        studio_jbr = base / "Android" / "Android Studio" / "jbr" / "bin" / "java.exe"
        if studio_jbr.is_file():
            out.append(str(studio_jbr))

        jb_dir = base / "JetBrains"
        if jb_dir.is_dir():
            try:
                for ide in jb_dir.iterdir():
                    jb = ide / "jbr" / "bin" / "java.exe"
                    if jb.is_file():
                        out.append(str(jb))
            except OSError:
                pass
    return out


def _windows_registry_java_homes() -> List[str]:
    out: List[str] = []
    if sys.platform != "win32":
        return out
    try:
        import winreg  # type: ignore
    except ImportError:
        return out

    def read_homes(hive: int, key_path: str) -> None:
        try:
            key = winreg.OpenKey(hive, key_path)
        except OSError:
            return
        try:
            n_sub, _, _ = winreg.QueryInfoKey(key)
            for i in range(n_sub):
                try:
                    sub_name = winreg.EnumKey(key, i)
                    sk = winreg.OpenKey(key, sub_name)
                    try:
                        try:
                            home, _ = winreg.QueryValueEx(sk, "JavaHome")
                        except OSError:
                            home = None
                        if home:
                            hp = Path(home)
                            for name in ("java.exe", "java"):
                                exe = hp / "bin" / name
                                if exe.is_file():
                                    out.append(str(exe))
                                    break
                    finally:
                        sk.Close()
                except OSError:
                    continue
        finally:
            key.Close()

    read_homes(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\JavaSoft\JDK")
    read_homes(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Eclipse Adoptium\JDK")
    read_homes(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\JDK")

    # Android Studio sometimes registers here (best-effort)
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Android Studio")
        path, _ = winreg.QueryValueEx(key, "Path")
        key.Close()
        jbr = Path(path).parent / "jbr" / "bin" / "java.exe"
        if jbr.is_file():
            out.append(str(jbr))
    except OSError:
        pass

    return out


def _linux_candidate_java_paths() -> List[str]:
    out: List[str] = []
    root = Path("/usr/lib/jvm")
    if root.is_dir():
        try:
            for child in root.iterdir():
                exe = child / "bin" / "java"
                if exe.is_file():
                    out.append(str(exe))
        except OSError:
            pass
    # Common SDKMAN layout
    sdkman = Path.home() / ".sdkman" / "candidates" / "java"
    if sdkman.is_dir():
        try:
            for child in sdkman.iterdir():
                if child.is_dir():
                    exe = child / "bin" / "java"
                    if exe.is_file():
                        out.append(str(exe))
        except OSError:
            pass
    return out


def _macos_candidate_java_paths() -> List[str]:
    out: List[str] = []
    base = Path("/Library/Java/JavaVirtualMachines")
    if base.is_dir():
        try:
            for bundle in base.glob("*.jdk"):
                exe = bundle / "Contents" / "Home" / "bin" / "java"
                if exe.is_file():
                    out.append(str(exe))
        except OSError:
            pass
    return out


def _probe_java(java_exe: str) -> Optional[JavaRuntime]:
    import subprocess

    try:
        proc = subprocess.run(
            [java_exe, "-version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            shell=False,
        )
        text = (proc.stderr or "") + (proc.stdout or "")
        major = parse_java_major_from_output(text)
        line = text.strip().splitlines()[0] if text.strip() else ""
        return JavaRuntime(path=java_exe, major=major, version_text=line or text[:200])
    except Exception:
        return None


def discover_java_runtimes(*, max_workers: int = 8) -> List[JavaRuntime]:
    paths = _collect_candidate_java_paths()
    if not paths:
        return []

    results: List[JavaRuntime] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_probe_java, p): p for p in paths}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception:
                continue

    # Dedupe by path again (should already be unique)
    by_path: Dict[str, JavaRuntime] = {}
    for r in results:
        by_path[r.path] = r
    return sorted(by_path.values(), key=lambda x: (x.major, x.path), reverse=True)


def inventory_cache_path(repo_root: Path) -> Path:
    return repo_root / ".apk_web" / "java_inventory.json"


def save_inventory(repo_root: Path, runtimes: List[JavaRuntime], selected: Optional[str] = None) -> None:
    path = inventory_cache_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": _utc_now_iso(),
        "selected_for_jadx": selected,
        "runtimes": [r.as_dict() for r in runtimes],
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_inventory(repo_root: Path) -> Optional[Dict[str, Any]]:
    path = inventory_cache_path(repo_root)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def pick_best_for_jadx(runtimes: Iterable[JavaRuntime], minimum_major: int) -> Optional[JavaRuntime]:
    candidates = [r for r in runtimes if r.major >= minimum_major]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (r.major, r.path))


def runtimes_from_dicts(items: List[Dict[str, Any]]) -> List[JavaRuntime]:
    out: List[JavaRuntime] = []
    for item in items:
        try:
            out.append(
                JavaRuntime(
                    path=str(item["path"]),
                    major=int(item["major"]),
                    version_text=str(item.get("version_text") or ""),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def inventory_is_fresh(repo_root: Path, ttl_sec: int) -> bool:
    if ttl_sec <= 0:
        return False
    data = load_inventory(repo_root)
    if not data:
        return False
    ts = data.get("updated_at")
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds()
    return 0 <= age <= ttl_sec


def fetch_java_runtimes(repo_root: Path, *, ttl_sec: int, force_refresh: bool) -> List[JavaRuntime]:
    if not force_refresh and ttl_sec > 0 and inventory_is_fresh(repo_root, ttl_sec):
        data = load_inventory(repo_root)
        if data:
            rs = runtimes_from_dicts(list(data.get("runtimes") or []))
            if rs:
                return rs
    rs = discover_java_runtimes()
    save_inventory(repo_root, rs, selected=None)
    return rs


def select_java_for_jadx(
    repo_root: Path,
    *,
    minimum_major: int = MIN_JAVA_MAJOR,
    override_executable: Optional[str],
    ttl_sec: int,
    force_refresh: bool,
) -> tuple[str, List[JavaRuntime]]:
    with _INVENTORY_LOCK:
        runtimes = fetch_java_runtimes(repo_root, ttl_sec=ttl_sec, force_refresh=force_refresh)

        if override_executable:
            o = Path(override_executable)
            if not o.is_file():
                raise RuntimeError(f"JAVA_EXECUTABLE does not exist: {override_executable}")
            resolved = str(o.resolve())
            hit = next((r for r in runtimes if Path(r.path).resolve() == Path(resolved)), None)
            if hit is None:
                probed = _probe_java(resolved)
                if probed is None:
                    raise RuntimeError(f"JAVA_EXECUTABLE is not runnable: {override_executable}")
                hit = probed
                merged = {r.path: r for r in runtimes}
                merged[hit.path] = hit
                runtimes = sorted(merged.values(), key=lambda x: (x.major, x.path), reverse=True)
            if hit.major < minimum_major:
                raise RuntimeError(
                    f"JAVA_EXECUTABLE is Java {hit.major}; JADX needs Java {minimum_major}+."
                )
            save_inventory(repo_root, runtimes, selected=hit.path)
            return hit.path, runtimes

        best = pick_best_for_jadx(runtimes, minimum_major)
        if best is None:
            majors = ", ".join(sorted({str(r.major) for r in runtimes})) or "none"
            raise RuntimeError(
                f"No Java {minimum_major}+ runtime found (detected majors: {majors}). "
                "Install a newer JDK or set JAVA_EXECUTABLE."
            )
        save_inventory(repo_root, runtimes, selected=best.path)
        return best.path, runtimes


def java_runtimes_public_snapshot(
    repo_root: Path,
    *,
    ttl_sec: int,
    force_refresh: bool,
    override_executable: Optional[str],
    minimum_major: int,
) -> Dict[str, Any]:
    """
    Non-throwing summary for the dashboard API: lists runtimes and recommended selection.
    """
    runtimes = fetch_java_runtimes(repo_root, ttl_sec=ttl_sec, force_refresh=force_refresh)
    recommended = pick_best_for_jadx(runtimes, minimum_major)

    selected_path: Optional[str] = None
    selection_note: Optional[str] = None

    if override_executable:
        o = Path(override_executable)
        if not o.is_file():
            selection_note = f"JAVA_EXECUTABLE missing on disk: {override_executable}"
        else:
            hit = next((r for r in runtimes if Path(r.path).resolve() == o.resolve()), None)
            if hit is None:
                hit = _probe_java(str(o.resolve()))
            if hit is None:
                selection_note = "JAVA_EXECUTABLE could not be executed."
            elif hit.major < minimum_major:
                selection_note = (
                    f"JAVA_EXECUTABLE is Java {hit.major} (< {minimum_major}). "
                    "Unset it to use automatic selection."
                )
            else:
                selected_path = hit.path
    elif recommended is not None:
        selected_path = recommended.path
    else:
        selection_note = f"No Java {minimum_major}+ runtime detected."

    inv = load_inventory(repo_root)
    last_selected = inv.get("selected_for_jadx") if inv else None

    return {
        "runtimes": [r.as_dict() for r in runtimes],
        "recommended_for_jadx": recommended.path if recommended else None,
        "effective_selected": selected_path or last_selected,
        "override_executable": override_executable,
        "minimum_major": minimum_major,
        "note": selection_note,
        "cache_ttl_sec": ttl_sec,
        "used_disk_cache": bool(ttl_sec > 0 and inventory_is_fresh(repo_root, ttl_sec) and not force_refresh),
    }
