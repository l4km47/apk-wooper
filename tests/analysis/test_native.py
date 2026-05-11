"""ELF + strings scanner verification with a minimal hand-built object."""

from __future__ import annotations

import struct
from pathlib import Path

from apk_web.analysis.engine import EngineConfig, run_engine
from apk_web.analysis.store import AnalysisStore


def _build_minimal_elf64(payload_strings: list[str]) -> bytes:
    """Build a parseable ELF64-LE relocatable object with strings in .rodata."""
    elf_magic = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8

    rodata = b"\x00".join(s.encode("ascii") for s in payload_strings) + b"\x00"
    shstrtab = b"\x00.shstrtab\x00.rodata\x00"

    e_ehsize = 64
    e_shentsize = 64
    num_sections = 3

    rodata_off = e_ehsize
    shstrtab_off = rodata_off + len(rodata)
    sh_off = shstrtab_off + len(shstrtab)

    sh_null = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh_rodata = struct.pack(
        "<IIQQQQIIQQ",
        len("\x00.shstrtab\x00"),  # name offset = .rodata
        1,
        2,
        0,
        rodata_off,
        len(rodata),
        0,
        0,
        1,
        0,
    )
    sh_shstrtab = struct.pack(
        "<IIQQQQIIQQ", 1, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0
    )

    header = elf_magic + struct.pack(
        "<HHIQQQIHHHHHH",
        1,
        0x3E,
        1,
        0,
        0,
        sh_off,
        0,
        e_ehsize,
        0,
        0,
        e_shentsize,
        num_sections,
        2,
    )
    return header + rodata + shstrtab + sh_null + sh_rodata + sh_shstrtab


def test_native_scanner_extracts_strings_and_metadata(tmp_path: Path) -> None:
    root = tmp_path / "job1"
    libdir = root / "out" / "apktool" / "lib" / "arm64-v8a"
    libdir.mkdir(parents=True)
    elf_bytes = _build_minimal_elf64(
        [
            "https://prod.native.example.com/api/v1",
            "sk-abcdefghijklmnopqrstuvwxyz0123456789",
            "AIzaSyNativeAbcDefGhIjKlMnOpQrStUv012345",
            "127.0.0.1",
            "ordinary log message",
        ]
    )
    (libdir / "libdemo.so").write_bytes(elf_bytes)

    store = AnalysisStore(root)
    result = run_engine(
        job_root=root,
        scan_root=root / "out",
        store=store,
        config=EngineConfig(workers=2),
    )

    assert result.findings_count >= 3
    findings = store.read_findings()
    rule_ids = [f["rule_id"] for f in findings]
    assert "native.elf_info" in rule_ids
    assert "secret.openai" in rule_ids
    assert any(f["rule_id"] == "net.http_url" for f in findings)

    so_finding = next(f for f in findings if f["rule_id"] == "native.elf_info")
    assert so_finding["file"].endswith("libdemo.so")
    assert so_finding["extra"].get("arch") in {"x64", "x86_64", "x64 ", None}
