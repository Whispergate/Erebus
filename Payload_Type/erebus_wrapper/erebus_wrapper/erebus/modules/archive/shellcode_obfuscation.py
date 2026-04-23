"""Pure helpers for the shellcode obfuscation phase.

This module owns the deterministic (pure-Python) parts of the shellcrypt
invocation pipeline: command vector construction and key/IV parsing out of
shellcrypt's C-format stdout. It deliberately does NOT invoke subprocess -
the caller (builder.py) runs the commands, handles the async protocol, and
threads the results back through the build response. Keeping the side
effects in the caller avoids requiring the plugin to import asyncio or
take an injected run-callable just to be testable.

Consumed by `plugin_shellcode_obfuscation.py` which exposes these as
registered plugin functions so builder.py can call them via the normal
auto-discovery path.

Why this split exists (R2a refactor):
    Before the extraction, ~200 LOC of shellcrypt argument construction and
    key/IV regex parsing lived inline inside build(). That made it hard to
    unit-test the command vectors against a fixture - any check required
    standing up a FakeWrapper and running build() through the subprocess
    mocks. Post-R2a each helper is a 10-line pure function with a
    parameter dict in / list or tuple out.
"""

import re
from typing import Optional, Tuple


def build_obfuscation_cmd(
    shellcrypt_path: str,
    input_path: str,
    output_path: str,
    *,
    encryption_method: str,
    loader_type: str,
    shellcode_format: str,
    compression_method: Optional[str] = None,
    encoding_method: Optional[str] = None,
    encryption_key: Optional[str] = None,
) -> list:
    """Build the main shellcrypt invocation for the obfuscation pass.

    `encryption_method`, `compression_method`, `encoding_method` must already
    be the shellcrypt CLI tokens (e.g. "xor", "lznt1", "base64"), not the
    builder-facing parameter values - the caller is responsible for any
    mapping through ENCRYPTION_METHODS / COMPRESSION_METHODS / ENCODING_METHODS.
    Pass None (or "NONE") to skip the corresponding flag.

    `shellcode_format` is the raw builder parameter value ("C", "CSharp",
    "Raw"); we only use it to decide whether to append `-a shellcode` since
    "Raw" uses a different flag path downstream.
    """
    cmd = [
        "python",
        shellcrypt_path,
        "-i", input_path,
        "-e", encryption_method,
    ]
    # Output format key is driven by loader_type, not shellcode_format -
    # ClickOnce always emits csharp, other loaders emit C. The historical
    # default (unknown loader type) is also C.
    if loader_type == "ClickOnce":
        cmd += ["-f", "csharp"]
    else:
        cmd += ["-f", "c"]

    if shellcode_format != "Raw":
        cmd += ["-a", "shellcode"]

    if compression_method and compression_method != "NONE":
        cmd += ["-c", compression_method]
    if encoding_method and encoding_method != "NONE":
        cmd += ["-d", encoding_method]
    if encryption_key and encryption_key != "NONE":
        cmd += ["-k", encryption_key]

    cmd += ["-o", output_path]
    return cmd


def build_key_extraction_cmd(
    shellcrypt_path: str,
    input_path: str,
    *,
    encryption_method: str,
    compression_method: Optional[str] = None,
    encoding_method: Optional[str] = None,
    encryption_key: Optional[str] = None,
) -> list:
    """Build the secondary shellcrypt invocation that re-runs in C format
    so we can parse the key/IV bytes out of stdout.

    This is always C-format regardless of loader type, because the key/IV
    extraction regex only understands the C `unsigned char key[] = {...}`
    shape shellcrypt emits in that mode.
    """
    cmd = [
        "python",
        shellcrypt_path,
        "-i", input_path,
        "-e", encryption_method,
        "-f", "c",
        "-a", "shellcode",
    ]
    if encryption_key and encryption_key != "NONE":
        cmd += ["-k", encryption_key]
    if compression_method and compression_method != "NONE":
        cmd += ["-c", compression_method]
    if encoding_method and encoding_method != "NONE":
        cmd += ["-d", encoding_method]
    return cmd


def build_raw_key_cmd(
    shellcrypt_path: str,
    input_path: str,
    *,
    encryption_method: str,
    encryption_key: Optional[str] = None,
) -> list:
    """Build the shellcrypt invocation for the Raw shellcode format path.

    Used when the operator selects Shellcode Format = "Raw"; the caller
    writes the returned `unsigned char key[] = {...}` array to the
    encrypted_shellcode_path_sc file so the C loader can pick it up.
    """
    cmd = [
        "python",
        shellcrypt_path,
        "-i", input_path,
        "-e", encryption_method,
        "-f", "c",
        "-a", "shellcode",
    ]
    if encryption_key and encryption_key != "NONE":
        cmd += ["-k", encryption_key]
    return cmd


_KEY_RE = re.compile(r"unsigned char\s+key\[\]\s*=\s*\{([^}]+)\}")
_IV_RE = re.compile(r"unsigned char\s+iv\[\]\s*=\s*\{([^}]+)\}")


def parse_key_iv(shellcrypt_c_source: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract comma-separated key and IV byte strings from shellcrypt C.

    Returns (key_str, iv_str) where each is the normalized "0x01, 0x02, ..."
    joined content of the corresponding array literal, or None if that
    array wasn't present in the source. Builder.py threads these into the
    config.hpp template's ENCRYPTION_KEY / ENCRYPTION_IV fields.

    The regex uses `[^}]+` so it only matches single-line array literals,
    which matches what shellcrypt emits (keys/IVs are always on one line).
    """
    key_str = None
    iv_str = None
    m = _KEY_RE.search(shellcrypt_c_source)
    if m:
        key_str = ", ".join(x.strip() for x in m.group(1).split(",") if x.strip())
    m = _IV_RE.search(shellcrypt_c_source)
    if m:
        iv_str = ", ".join(x.strip() for x in m.group(1).split(",") if x.strip())
    return key_str, iv_str


def extract_raw_key_array(shellcrypt_c_source: str) -> str:
    """Slice the `unsigned char key[] = { ... };` block out of shellcrypt C.

    Used by the Raw-format path that writes a literal C key declaration
    into the loader source tree. Returns the full declaration (starting
    at `unsigned char key` through the terminating `};`), or an empty
    string if the marker isn't present.
    """
    start = shellcrypt_c_source.find("unsigned char key")
    if start < 0:
        return ""
    end = shellcrypt_c_source.find("};", start)
    if end < 0:
        return ""
    return shellcrypt_c_source[start:end + 2]
