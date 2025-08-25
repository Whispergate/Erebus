import os
from pathlib import PurePath
from distutils.dir_util import copy_tree
import asyncio
import tempfile

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ErebusWrapper(PayloadType):
    name = "erebus_wrapper"
    file_extension = "bin"
    author = "@Lavender-exe"
    note = """Erebus is a modern initial access wrapper aimed at decreasing the development to deployment time, when preparing for intrusion operations. Erebus comes with multiple techniques out of the box to craft complex chains, and assist in bypassing the toughest security measures."""
    supported_os = [
        SupportedOS.Windows
        # SupportedOS.Linux, Not Supported Yet
    ]

    wrapper = True
    wrapped_payloads = []

    supports_dynamic_loading = False
    c2_profiles = []

    agent_path = PurePath(".") / "erebus_wrapper"
    agent_icon_path = agent_path / "Erebus.svg"
    agent_code_path = agent_path

    build_parameters = [
        BuildParameter(
            name = "Architecture",
            parameter_type = BuildParameterType.ChooseOne,
            description = "Select Architecture.",
            choices = ["Any_CPU", "x64", "x86"],
            default_value = "x64"
        ),
        BuildParameter(
            name = "DLL Hijacking",
            parameter_type = BuildParameterType.File,
            description = "Upload a DLL for hijacking.",
        ),
        BuildParameter(
            name = "DLL",
            parameter_type = BuildParameterType.File,
            description = "Upload a DLL for hijacking.",
        ),
    ]

    build_steps = [
        BuildStep(step_name = "Gathering Files",
                  step_description = "Copy files to temporary location"),
        BuildStep(step_name = "Creating Payload",
                  step_description = "Creating a payload based on the selected techniques"),
        BuildStep(step_name = "Adding Trigger",
                  step_description = "Creating trigger to execute given payload"),
        BuildStep(step_name = "Creating Decoy",
                  step_description= "Creating a placeholder decoy file"),
        BuildStep(step_name = "Containerising",
                  step_description = "Adding payload into chosen container"),
    ]

    async def payloads(self) -> None:
        """Creates a payload based on the provided shellcode/agent

        Raises:
            NotImplementedError: Function not implemented yet.

        TODO:
            - Take in payload.
            - Check that it is in shellcode format (File Header Check).
            - Add different techniques to build payload:
                - AppDomain Injection (Local and Remote)
                - ClickOnce (Local and Remote)
                - Dll Proxying -> Select bw/Sideloading & Proxying
                    -> Additional checks
                    -> Will need to get the exports
                - MSI + MST
                - MSIX (Unsigned and Signed)
        """
        raise NotImplementedError

    async def triggers(self) -> None:
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

    async def containers(self) -> None:
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

            working_path = PurePath(agent_build_path.name) / ""
            working_path = str(working_path)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName = "Gathering Files",
                StepStdout = "Gathered files to generate shellcode",
                StepSuccess = True
            ))

            with open(working_path, "wb") as file:
                file.write(self.wrapped_payload)
                response.status = BuildStatus.Success
                response.build_message = "Files Gathered for Conversion."

            command = ""

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Building",
                StepStdout="Converted payload to shellcode",
                StepSuccess=True,
            ))

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=agent_build_path.name
            )

            stdout, stderr = await process.communicate()

            if stdout:
                output += f"[stdout]\n{stdout.decode()}"
            if stderr:
                output += f"[stderr]\n{stderr.decode()}"

            if os.path.exists(working_path):
                response.payload = open(working_path, "rb").read()
                response.status = BuildStatus.Success
                response.build_message = "Shellcode Generated!"
                return response
            else:
                response.payload = b""
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Building",
                    StepStdout="Failed to convert given file to the specified output",
                    StepSuccess=False,
                ))
                response.build_message = "Failed to convert given file to the specified output."
                response.build_stderr = output + "\n" + working_path
        except Exception as e:
            raise RuntimeError(str(e) + "\n" + output) from e

        return response
