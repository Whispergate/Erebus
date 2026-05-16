"""
Erebus Plugin: PE Metadata Sanitizer
Author: Whispergate
Description: Strip compiler fingerprints from MinGW-built loader binaries.

MinGW leaves highly-recognisable tells in every PE it emits:
  - A `.comment` section containing `GCC: (GNU) 1x.x.x`
  - A deterministic PE timestamp derived from build time
  - A missing Rich header (Microsoft toolchain signature)
  - A `.buildid` / `.debug_*` section pair pointing at the build host PDB
  - Deterministic section ordering and padding

On its own every one of these is a weak signal; together they bucket the
loader into "MinGW-compiled red team payload" family-level detections the
moment one sample is sandboxed. This plugin runs as a post-compile step and
scrubs the cheap-to-remove signals. It is intentionally conservative - it
will not touch bytes that could break section relocations or the import
table.

Operations performed (all optional, controlled by arguments):
  1. Zero the PE COFF timestamp (IMAGE_FILE_HEADER.TimeDateStamp)
  2. Zero the export directory timestamp if present
  3. Zero the debug directory timestamp(s) if present
  4. Overwrite the `.comment` section contents with NULs
  5. Strip `.buildid` section contents (leave header, zero body)
  6. Randomize (or clear) the CheckSum field

All edits are done in place. No external tools required - pure Python byte
manipulation over the PE headers, so this runs inside the Mythic container
without adding dependencies.
"""

import os
import struct
import pathlib
from typing import Dict, Callable, Optional, List, Tuple

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# PE constants we need. Kept inline to avoid a pefile dependency.
_DOS_MAGIC = b"MZ"
_PE_MAGIC = b"PE\x00\x00"
_IMAGE_FILE_HEADER_SIZE = 20
_IMAGE_SECTION_HEADER_SIZE = 40
# Section body scrubbing is limited to `.comment` because it is the only
# section guaranteed safe to zero at runtime - it holds nothing but the GCC
# version identification string (`GCC: (GNU) X.Y.Z`) and is never referenced
# by code, unwind, or runtime metadata.
#
# Earlier versions of this plugin also scrubbed `.buildid` and the `.debug_*`
# family. That broke debug (`-g -O0`) builds: MinGW emits pseudo-relocation
# and runtime references into those sections, and Windows refused to load
# the resulting binary with "This app can't run on your PC". For release
# builds the problem is moot - the Makefile already passes
# `-Wl,--strip-all -Wl,--build-id=none -fno-ident` which removes those
# sections outright. Leaving them alone is correct in both configurations.
_SECTIONS_TO_ZERO = {b".comment"}


class PESanitizePlugin(ErebusPlugin):
    """Post-compile PE metadata scrubber."""

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="pe_sanitize",
            version="1.0.0",
            author="Whispergate",
            description="Scrub MinGW / compiler fingerprints from built PE files",
            category=PluginCategory.PAYLOAD,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "sanitize_pe": self.sanitize_pe,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def sanitize_pe(
        self,
        pe_path: str,
        zero_timestamp: bool = True,
        zero_checksum: bool = True,
        scrub_comment_sections: bool = True,
    ) -> Dict[str, object]:
        """Sanitize a PE file in place.

        Returns a dict describing what was changed, suitable for logging
        into the IOC bundle.
        """
        path = pathlib.Path(pe_path)
        if not path.is_file():
            raise FileNotFoundError(f"PE not found: {pe_path}")

        with open(path, "r+b") as f:
            data = bytearray(f.read())
            report = self._scrub(data, zero_timestamp, zero_checksum, scrub_comment_sections)
            f.seek(0)
            f.write(data)
            f.truncate()
        report["path"] = str(path)
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _scrub(
        self,
        data: bytearray,
        zero_timestamp: bool,
        zero_checksum: bool,
        scrub_comment_sections: bool,
    ) -> Dict[str, object]:
        report: Dict[str, object] = {
            "timestamp_zeroed": False,
            "checksum_zeroed": False,
            "sections_scrubbed": [],
            "debug_dir_timestamps_zeroed": 0,
            "export_dir_timestamp_zeroed": False,
        }

        if len(data) < 64 or data[:2] != _DOS_MAGIC:
            raise ValueError("Not a PE file (DOS magic missing)")

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != _PE_MAGIC:
            raise ValueError("Not a PE file (NT magic missing)")

        coff_off = e_lfanew + 4
        machine, n_sections, timestamp = struct.unpack_from("<HHI", data, coff_off)
        opt_hdr_off = coff_off + _IMAGE_FILE_HEADER_SIZE
        opt_magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
        is_pe32_plus = (opt_magic == 0x20B)

        # 1. COFF timestamp
        if zero_timestamp:
            struct.pack_into("<I", data, coff_off + 4, 0)
            report["timestamp_zeroed"] = True

        # 2. Optional header CheckSum (offset 0x40 from start of opt header
        #    for both PE32 and PE32+)
        if zero_checksum:
            struct.pack_into("<I", data, opt_hdr_off + 0x40, 0)
            report["checksum_zeroed"] = True

        # Data directories start at 0x60 (PE32) / 0x70 (PE32+) from opt header
        data_dir_off = opt_hdr_off + (0x70 if is_pe32_plus else 0x60)
        # Export = index 0, Debug = index 6. Each entry is 8 bytes
        # (VirtualAddress, Size).
        export_va, export_sz = struct.unpack_from("<II", data, data_dir_off + 0)
        debug_va, debug_sz = struct.unpack_from("<II", data, data_dir_off + 6 * 8)

        # Sections live after the full optional header; size from COFF
        # SizeOfOptionalHeader field at coff_off+16 (word).
        size_opt_hdr = struct.unpack_from("<H", data, coff_off + 16)[0]
        sections_off = opt_hdr_off + size_opt_hdr

        # Build a VA -> file offset mapping for RVA translation.
        sections: List[Tuple[bytes, int, int, int, int]] = []
        for i in range(n_sections):
            off = sections_off + i * _IMAGE_SECTION_HEADER_SIZE
            name = bytes(data[off:off + 8]).rstrip(b"\x00")
            virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", data, off + 8)
            sections.append((name, virt_addr, virt_size, raw_ptr, raw_size))

        def rva_to_offset(rva: int) -> Optional[int]:
            for _, va, vs, rp, rs in sections:
                if va <= rva < va + max(vs, rs):
                    return rp + (rva - va)
            return None

        # 3. Export directory timestamp (RVA+4 field)
        if export_va and export_sz:
            exp_off = rva_to_offset(export_va)
            if exp_off is not None:
                struct.pack_into("<I", data, exp_off + 4, 0)
                report["export_dir_timestamp_zeroed"] = True

        # 4. Debug directory entries (each is 28 bytes; TimeDateStamp at +4)
        if debug_va and debug_sz:
            dbg_off = rva_to_offset(debug_va)
            if dbg_off is not None:
                entries = debug_sz // 28
                for i in range(entries):
                    struct.pack_into("<I", data, dbg_off + i * 28 + 4, 0)
                report["debug_dir_timestamps_zeroed"] = entries

        # 5. Scrub compiler-comment / buildid / .debug_* section bodies
        if scrub_comment_sections:
            for name, _, _, rp, rs in sections:
                # Match prefix-style so `.debug_*` all hit
                hit = False
                for target in _SECTIONS_TO_ZERO:
                    if name == target or (target.endswith(b"_")
                                          and name.startswith(target)):
                        hit = True
                        break
                if hit and rp and rs:
                    data[rp:rp + rs] = b"\x00" * rs
                    report["sections_scrubbed"].append(name.decode("ascii", "replace"))

        return report


if __name__ == "__main__":
    p = PESanitizePlugin()
    valid, err = p.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
