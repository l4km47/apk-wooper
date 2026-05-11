from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

# JADX 1.5.x ships Java 11 bytecode (class file 55). Older runtimes cannot load it.
MIN_JAVA_MAJOR = 11


def resolve_java_executable() -> str:
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        home = Path(java_home)
        candidates = [home / "bin" / "java.exe", home / "bin" / "java"]
        for c in candidates:
            if c.is_file():
                return str(c)
    which = shutil.which("java")
    if which:
        return which
    raise RuntimeError(
        "Java executable not found. Install JDK 17+ and ensure `java` is on PATH, "
        "or set JAVA_HOME to a JDK installation."
    )


def parse_java_major_from_output(text: str) -> int:
    """Parse major Java version from combined `java -version` stdout/stderr."""
    # Modern: openjdk version "17.0.9" / java version "11.0.22"
    m = re.search(r'version "(\d+)\.', text)
    if m:
        major = int(m.group(1))
        if major != 1:
            return major
    # Legacy: java version "1.8.0_391"
    m = re.search(r'version "1\.(\d+)\.', text)
    if m:
        return int(m.group(1))
    raise RuntimeError(f"Could not parse Java version from: {text[:500]!r}")


def java_major_version(java_exe: str) -> int:
    """Parse `java -version` output (stderr or stdout) into a major version number."""
    proc = subprocess.run(
        [java_exe, "-version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        shell=False,
    )
    text = (proc.stderr or "") + (proc.stdout or "")
    return parse_java_major_from_output(text)


def ensure_java_minimum(java_exe: str, minimum_major: int = MIN_JAVA_MAJOR) -> None:
    major = java_major_version(java_exe)
    if major < minimum_major:
        raise RuntimeError(
            f"This JVM is Java {major}, but JADX requires Java {minimum_major}+ "
            f'(UnsupportedClassVersionError / class file version). Install JDK 17 or 21, '
            f"then set JAVA_HOME to that JDK or put its bin folder earlier on PATH than Java 8. "
            f"Currently using: {java_exe}"
        )
