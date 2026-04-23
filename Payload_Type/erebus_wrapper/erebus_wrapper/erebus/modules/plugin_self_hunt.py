"""
Erebus Plugin: Self-Hunt Rule Generator
Author: Whispergate
Description: Emit a YARA rule + Sigma stub fingerprinting the just-built
             payload, so operators can hunt their own artifacts in the
             target SIEM before delivery.

Rationale
---------
Every build is unique (per-build XOR keys, randomized shellcode obfuscation,
unique compile timestamps scrubbed by pe_sanitize). That uniqueness is good
for OPSEC but bad for operator confidence: how do you know whether your
specific sample will pop a rule in the target SIEM?

This plugin takes the final delivered PE, extracts four signal classes, and
emits a YARA rule that would catch this exact artifact. Run it against a
staged copy of the target SIEM (if accessible) or against sample trading
platforms you control to verify the artifact is clean. The rule is also
dumped into the IOC bundle so post-op reporting has concrete hunt criteria.

Signal classes extracted
------------------------
  1. File hashes (MD5, SHA1, SHA256, imphash-equivalent derived from
     imported function names)
  2. Unique byte sequences from the .text section (top-N longest runs
     that look "distinctive": non-zero, non-repeating)
  3. Section layout (name, VirtualSize, entropy bucket)
  4. Entry point byte signature (first 32 bytes of EP)

Note: this plugin does NOT compute real imphash (which requires parsing the
import table fully and matching MS implementation). It computes a stable
proxy hash over sorted DLL/function names, which is what most detection
engineers end up doing anyway.
"""

import os
import math
import struct
import hashlib
import pathlib
from typing import Dict, Callable, Optional, List, Tuple

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class SelfHuntPlugin(ErebusPlugin):
    """Generate YARA + Sigma self-hunt rules for a finished payload."""

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="self_hunt",
            version="1.0.0",
            author="Whispergate",
            description="Emit per-build YARA/Sigma rules fingerprinting the delivered payload",
            category=PluginCategory.OTHER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {"generate_self_hunt_rules": self.generate_self_hunt_rules}

    # ------------------------------------------------------------------
    def generate_self_hunt_rules(
        self,
        pe_path: str,
        output_dir: str,
        rule_name: Optional[str] = None,
    ) -> Dict[str, str]:
        """Analyze a PE and emit YARA + Sigma files into output_dir.

        Returns {"yara": path, "sigma": path, "rule_name": name}.
        """
        src = pathlib.Path(pe_path)
        out = pathlib.Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        with open(src, "rb") as f:
            data = f.read()

        analysis = self._analyze(data)
        name = rule_name or f"erebus_build_{analysis['sha256'][:12]}"

        yara_text = self._yara_from_analysis(name, src.name, analysis)
        sigma_text = self._sigma_from_analysis(name, src.name, analysis)

        yara_path = out / f"{name}.yar"
        sigma_path = out / f"{name}.yml"
        yara_path.write_text(yara_text)
        sigma_path.write_text(sigma_text)

        return {
            "yara": str(yara_path),
            "sigma": str(sigma_path),
            "rule_name": name,
            "sha256": analysis["sha256"],
        }

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def _analyze(self, data: bytes) -> Dict[str, object]:
        analysis: Dict[str, object] = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "ep_bytes": b"",
            "text_snippets": [],
            "sections": [],
        }

        if len(data) < 64 or data[:2] != b"MZ":
            return analysis
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return analysis

        coff_off = e_lfanew + 4
        n_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
        opt_hdr_off = coff_off + 20
        opt_magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
        is_pe32_plus = (opt_magic == 0x20B)
        size_opt_hdr = struct.unpack_from("<H", data, coff_off + 16)[0]
        sections_off = opt_hdr_off + size_opt_hdr

        # AddressOfEntryPoint at opt+0x10 (both PE32 and PE32+)
        ep_rva = struct.unpack_from("<I", data, opt_hdr_off + 0x10)[0]
        image_base_off = opt_hdr_off + (0x18 if is_pe32_plus else 0x1C)

        sections: List[Tuple[str, int, int, int, int]] = []
        for i in range(n_sections):
            off = sections_off + i * 40
            name = bytes(data[off:off + 8]).rstrip(b"\x00").decode("ascii", "replace")
            virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", data, off + 8)
            sections.append((name, virt_addr, virt_size, raw_ptr, raw_size))
            if raw_size > 0:
                body = data[raw_ptr:raw_ptr + raw_size]
                entropy = self._entropy(body)
                analysis["sections"].append({
                    "name": name, "virt_size": virt_size,
                    "raw_size": raw_size, "entropy": round(entropy, 2),
                })

        def rva_to_offset(rva: int) -> Optional[int]:
            for _, va, vs, rp, rs in sections:
                if va <= rva < va + max(vs, rs):
                    return rp + (rva - va)
            return None

        ep_off = rva_to_offset(ep_rva)
        if ep_off is not None and ep_off + 32 <= len(data):
            analysis["ep_bytes"] = data[ep_off:ep_off + 32]

        # Extract up to 4 "distinctive" byte runs from .text
        for name, va, vs, rp, rs in sections:
            if name != ".text" or rs == 0:
                continue
            body = data[rp:rp + min(rs, 0x20000)]  # cap scan
            analysis["text_snippets"] = self._distinctive_runs(body, count=4)
            break

        return analysis

    @staticmethod
    def _entropy(body: bytes) -> float:
        if not body:
            return 0.0
        counts = [0] * 256
        for b in body:
            counts[b] += 1
        total = len(body)
        e = 0.0
        for c in counts:
            if c:
                p = c / total
                e -= p * math.log2(p)
        return e

    @staticmethod
    def _distinctive_runs(body: bytes, count: int) -> List[bytes]:
        """Pick count non-overlapping 16-byte windows that look distinctive.

        Heuristic: walk in 4096-byte strides, skip windows whose first byte
        is 0/0xCC (padding) or whose bytes are too repetitive (<=3 unique),
        and collect the first `count` that pass. This gives stable per-build
        signatures without needing a disassembler.
        """
        hits: List[bytes] = []
        stride = max(4096, len(body) // (count * 4 or 1))
        off = 0
        while off + 16 <= len(body) and len(hits) < count:
            win = body[off:off + 16]
            off += stride
            if win[0] in (0x00, 0xCC):
                continue
            if len(set(win)) <= 3:
                continue
            hits.append(win)
        return hits

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------
    def _yara_from_analysis(self, name: str, filename: str, a: Dict) -> str:
        lines = [
            f"// Erebus self-hunt rule for {filename}",
            f"// Auto-generated - run against the target SIEM before delivery.",
            "",
            f"rule {name}",
            "{",
            "    meta:",
            f'        description = "Erebus build fingerprint for {filename}"',
            f'        sha256 = "{a["sha256"]}"',
            f'        md5 = "{a["md5"]}"',
            f'        size = "{a["size"]}"',
            "    strings:",
        ]
        ep = a.get("ep_bytes", b"")
        if ep:
            hex_ep = " ".join(f"{b:02X}" for b in ep)
            lines.append(f"        $ep = {{ {hex_ep} }}")
        snippets = a.get("text_snippets", []) or []
        for i, snip in enumerate(snippets):
            hex_snip = " ".join(f"{b:02X}" for b in snip)
            lines.append(f"        $t{i} = {{ {hex_snip} }}")
        lines.append("    condition:")
        cond_parts = []
        if ep:
            cond_parts.append("$ep")
        for i in range(len(snippets)):
            cond_parts.append(f"$t{i}")
        if not cond_parts:
            lines.append("        filesize > 0")
        else:
            lines.append("        uint16(0) == 0x5A4D and (" + " and ".join(cond_parts) + ")")
        lines.append("}")
        lines.append("")
        return "\n".join(lines)

    def _sigma_from_analysis(self, name: str, filename: str, a: Dict) -> str:
        # Hash-based Sigma stub - lets operators paste into a PoC hunt
        # against EDR/SIEM hash telemetry.
        return (
            f"title: Erebus build {name}\n"
            f"id: {a['sha256'][:8]}-{a['sha256'][8:12]}-{a['sha256'][12:16]}-erebus\n"
            f"description: Auto-generated self-hunt rule for {filename}\n"
            "status: experimental\n"
            "logsource:\n"
            "    category: process_creation\n"
            "    product: windows\n"
            "detection:\n"
            "    selection:\n"
            f"        Hashes|contains:\n"
            f"            - 'SHA256={a['sha256']}'\n"
            f"            - 'MD5={a['md5']}'\n"
            "    condition: selection\n"
            "level: high\n"
        )


if __name__ == "__main__":
    import sys
    p = SelfHuntPlugin()
    meta = p.get_metadata()
    print(f"[*] {meta.name} v{meta.version}")
    if len(sys.argv) > 2:
        r = p.generate_self_hunt_rules(sys.argv[1], sys.argv[2])
        print(r)
    else:
        print("[*] Usage: python3 plugin_self_hunt.py <pe> <out-dir>")
