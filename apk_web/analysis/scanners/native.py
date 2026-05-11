from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable, Iterator, List, Tuple

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.patterns import (
    IPV4_NOISE_PREFIXES,
    SECRET_RULES,
    URL_NOISE_HOSTS,
    URL_RULES,
)
from apk_web.analysis.scanners.base import Scanner


_LOG = logging.getLogger(__name__)

_PRINTABLE_ASCII = set(range(0x20, 0x7F)) | {0x09}
_MIN_STRING_LEN = 5  # minimum chars to count as an interesting string
_STREAM_CHUNK = 4 * 1024 * 1024  # 4 MB chunks while streaming
_MAX_STRINGS_PER_FILE = 200_000  # belt-and-braces cap; large libs are rare


_HOST_RE = re.compile(r"^[a-zA-Z][\w.\-]*$")


def _is_ip_noise(value: str) -> bool:
    return any(value.startswith(prefix) for prefix in IPV4_NOISE_PREFIXES)


def _is_url_noise(url: str) -> bool:
    # Cheap host extraction without urllib to avoid overhead in the hot loop.
    after_scheme = url.split("://", 1)[-1]
    host = after_scheme.split("/", 1)[0].split(":", 1)[0]
    return host in URL_NOISE_HOSTS


def _iter_ascii_strings(data: bytes, *, offset_base: int = 0) -> Iterator[Tuple[int, str]]:
    """Yield (offset, ascii_string) tuples from a bytes chunk."""
    start = -1
    out = bytearray()
    for i, b in enumerate(data):
        if b in _PRINTABLE_ASCII:
            if start < 0:
                start = i
            out.append(b)
            continue
        if len(out) >= _MIN_STRING_LEN:
            yield offset_base + start, out.decode("ascii", errors="replace")
        start = -1
        out.clear()
    if len(out) >= _MIN_STRING_LEN:
        yield offset_base + start, out.decode("ascii", errors="replace")


def _iter_utf16_strings(data: bytes, *, offset_base: int = 0) -> Iterator[Tuple[int, str]]:
    """Yield (offset, utf16le_string) tuples; cheap fixed-state scanner."""
    start = -1
    chars: list[str] = []
    i = 0
    while i + 1 < len(data):
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and lo in _PRINTABLE_ASCII:
            if start < 0:
                start = i
            chars.append(chr(lo))
            i += 2
            continue
        if len(chars) >= _MIN_STRING_LEN:
            yield offset_base + start, "".join(chars)
        chars = []
        start = -1
        i += 2
    if len(chars) >= _MIN_STRING_LEN:
        yield offset_base + start, "".join(chars)


def _stream_strings(path: Path) -> Iterator[Tuple[int, str, str]]:
    """Yield (offset, encoding, string) for every printable string in *path*.

    ASCII passes first (more common in compiled binaries) then UTF-16LE.
    We keep separate counters but cap the total to bound worst-case work.
    """
    yielded = 0
    try:
        size = path.stat().st_size
    except OSError:
        return
    with path.open("rb") as fp:
        offset = 0
        while True:
            chunk = fp.read(_STREAM_CHUNK)
            if not chunk:
                break
            # Slide back by a few bytes if a string straddles chunk boundary.
            for off, s in _iter_ascii_strings(chunk, offset_base=offset):
                yield off, "ascii", s
                yielded += 1
                if yielded >= _MAX_STRINGS_PER_FILE:
                    return
            offset += len(chunk)
        if size <= 64 * 1024 * 1024:
            # UTF-16 strings are rarer; only re-scan small/medium files.
            fp.seek(0)
            offset = 0
            while True:
                chunk = fp.read(_STREAM_CHUNK)
                if not chunk:
                    break
                for off, s in _iter_utf16_strings(chunk, offset_base=offset):
                    yield off, "utf16le", s
                    yielded += 1
                    if yielded >= _MAX_STRINGS_PER_FILE:
                        return
                offset += len(chunk)


def _elf_metadata(path: Path) -> dict:
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.sections import SymbolTableSection
    except Exception:
        return {}

    info: dict = {}
    try:
        with path.open("rb") as fp:
            elf = ELFFile(fp)
            info["arch"] = elf.get_machine_arch()
            info["bits"] = elf.elfclass
            info["endian"] = "little" if elf.little_endian else "big"
            needed: list[str] = []
            soname = None
            for sect in elf.iter_sections():
                if isinstance(sect, DynamicSection):
                    for tag in sect.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)
                        elif tag.entry.d_tag == "DT_SONAME":
                            soname = tag.soname
            info["needed"] = needed
            if soname:
                info["soname"] = soname
            exports: list[str] = []
            for sect in elf.iter_sections():
                if not isinstance(sect, SymbolTableSection):
                    continue
                if sect.name != ".dynsym":
                    continue
                for sym in sect.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    # Heuristic: keep only JNI exports and obviously interesting
                    # globals — avoids the 5k+ symbol noise on big libs.
                    if (
                        sym["st_info"]["bind"] == "STB_GLOBAL"
                        and sym["st_shndx"] != "SHN_UNDEF"
                        and (
                            name.startswith("Java_")
                            or name.startswith("JNI_OnLoad")
                            or "decrypt" in name.lower()
                            or "encrypt" in name.lower()
                            or "verify" in name.lower()
                            or "license" in name.lower()
                        )
                    ):
                        exports.append(name)
            info["exports"] = exports[:50]
    except Exception as exc:  # pragma: no cover - defensive
        _LOG.debug("ELF parse failed for %s: %s", path, exc)
    return info


class _NativeScanner:
    name = "native"
    kind = "native"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        out: List[Finding] = []

        info = _elf_metadata(path)
        if info:
            arch = info.get("arch") or "unknown"
            bits = info.get("bits") or 0
            label = f"{arch} ({bits}-bit)" if bits else str(arch)
            out.append(
                make_finding(
                    rule_id="native.elf_info",
                    category=Category.NATIVE,
                    severity=Severity.INFO,
                    title=f"Native library: {label}",
                    file=rel,
                    full_match=label,
                    tool="elf",
                    confidence=1.0,
                    redact=False,
                    extra={"arch": arch, "bits": bits, "endian": info.get("endian")},
                )
            )
            for libname in info.get("needed") or []:
                out.append(
                    make_finding(
                        rule_id="native.needed_lib",
                        category=Category.NATIVE,
                        severity=Severity.INFO,
                        title=f"Linked library: {libname}",
                        file=rel,
                        full_match=libname,
                        tool="elf",
                        confidence=1.0,
                        redact=False,
                    )
                )
            for sym in info.get("exports") or []:
                out.append(
                    make_finding(
                        rule_id="native.exported_symbol",
                        category=Category.NATIVE,
                        severity=Severity.LOW,
                        title=f"Exported native symbol: {sym}",
                        file=rel,
                        full_match=sym,
                        tool="elf",
                        confidence=0.95,
                        redact=False,
                    )
                )

        # Run the existing secret + URL regex catalogs against the strings
        # extracted from this binary. We deliberately disable IPv4 here:
        # native libs are dense with binary patterns that look like IPs but
        # are almost always false positives, so we keep the URL+secret catalog
        # only.
        rule_pool = list(SECRET_RULES) + [r for r in URL_RULES if r.rule_id != "net.ipv4"]
        seen: set[tuple[str, str]] = set()

        for _offset, _enc, value in _stream_strings(path):
            for rule in rule_pool:
                for m in rule.pattern.finditer(value):
                    matched = m.group(0)
                    key = (rule.rule_id, matched)
                    if key in seen:
                        continue
                    if rule.rule_id in ("net.http_url", "net.ws_url") and _is_url_noise(matched):
                        continue
                    seen.add(key)
                    out.append(
                        make_finding(
                            rule_id=rule.rule_id,
                            category=rule.category,
                            severity=rule.severity,
                            title=f"{rule.title} (in native lib strings)",
                            file=rel,
                            full_match=matched,
                            snippet=value if len(value) <= 200 else value[:200],
                            tool="strings",
                            confidence=max(0.4, rule.confidence - 0.15),
                            redact=rule.redact,
                        )
                    )
        return out


SCANNER: Scanner = _NativeScanner()
