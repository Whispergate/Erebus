"""Fake mythic_container modules for offline test harness.

builder.py imports `from mythic_container.PayloadBuilder import *` and friends.
Outside the Mythic docker image those packages aren't installed. This module
installs minimal stand-ins into `sys.modules` BEFORE builder.py is imported
so tests can exercise build() on the host.

The stubs are permissive: they supply enough surface area (types, decorators,
RPC coroutines) that builder.py parses and runs, but deliberately do nothing
over the wire. Tests capture what build() calls by inspecting the recorded
RPC invocations on `rpc_log`.
"""

import sys
import types
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, List, Optional


# ---------------------------------------------------------------------------
# Recorder - tests inspect these after calling build()
# ---------------------------------------------------------------------------

rpc_log: List[dict] = []
# Tests push canned file content here, keyed by AgentFileId; build() pops it.
file_content_fixtures: dict = {}


def reset_stub_state():
    rpc_log.clear()
    file_content_fixtures.clear()


# ---------------------------------------------------------------------------
# PayloadBuilder stand-ins
# ---------------------------------------------------------------------------

class SupportedOS(Enum):
    Windows = "windows"
    Linux = "linux"
    MacOS = "macos"


class AgentType(Enum):
    Agent = "agent"
    Wrapper = "wrapper"
    Service = "service"
    CommandAugment = "command_augment"


class HideConditionOperand(Enum):
    EQ = "eq"
    NotEQ = "neq"
    In = "in"
    NotIn = "nin"
    Contains = "contains"
    NotContains = "not_contains"


@dataclass
class HideCondition:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class BuildStatus(Enum):
    Success = "success"
    Error = "error"


class BuildParameterType(Enum):
    String = "String"
    ChooseOne = "ChooseOne"
    ChooseMultiple = "ChooseMultiple"
    Array = "Array"
    Boolean = "Boolean"
    Date = "Date"
    Dictionary = "Dictionary"
    Number = "Number"
    File = "File"
    FileMultiple = "FileMultiple"
    TypedArray = "TypedArray"


@dataclass
class BuildParameter:
    name: str
    parameter_type: Any = BuildParameterType.String
    description: str = ""
    default_value: Any = None
    choices: list = field(default_factory=list)
    required: bool = False
    verifier_regex: str = ""
    crypto_type: bool = False
    group_name: str = ""
    # Accept any additional kwargs silently - the real Mythic class has many.
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@dataclass
class BuildStep:
    step_name: str = ""
    step_description: str = ""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@dataclass
class BuildResponse:
    status: Any = None
    payload: bytes = b""
    build_message: str = ""
    build_stderr: str = ""
    build_stdout: str = ""
    updated_filename: str = ""
    # Real BuildResponse takes `status=BuildStatus.Error` positional kwarg.
    def __init__(self, status=None, **kwargs):
        self.status = status
        self.payload = kwargs.get("payload", b"")
        self.build_message = kwargs.get("build_message", "")
        self.build_stderr = kwargs.get("build_stderr", "")
        self.build_stdout = kwargs.get("build_stdout", "")
        self.updated_filename = kwargs.get("updated_filename", "")


class PayloadType:
    """Base class for the builder. Tests subclass ErebusWrapper, which
    inherits from this; we just need a permissive base that accepts any
    class-level attributes Mythic normally validates.
    """
    name: str = ""
    author: str = ""
    supported_os: list = []
    wrapper: bool = False
    wrapped_payloads: list = []
    note: str = ""
    supports_dynamic_loading: bool = False
    mythic_encrypts: bool = True
    build_parameters: list = []
    c2_profiles: list = []
    agent_icon_path: str = ""
    build_steps: list = []
    agent_path: Any = None
    agent_code_path: Any = None
    agent_browserscript_path: Any = None
    file_extension: str = ""
    semver: str = "0.0.0"

    def __init__(self):
        # Tests set self.uuid, self.wrapped_payload, self._params directly
        # before invoking build().
        self.uuid: str = "stub-uuid"
        self.wrapped_payload: Optional[bytes] = None

    def get_parameter(self, name: str):
        """Override in tests via a params dict attached as self._params."""
        return getattr(self, "_params", {}).get(name)


# ---------------------------------------------------------------------------
# MythicCommandBase stand-ins
# ---------------------------------------------------------------------------

class CommandBase:
    pass


# ---------------------------------------------------------------------------
# MythicRPC stand-ins - async, record-only
# ---------------------------------------------------------------------------

class _RPCResponse:
    def __init__(self, success=True, content=b"", files=None, error=""):
        self.Success = success
        self.Content = content
        self.Files = files or []
        self.Error = error


@dataclass
class MythicRPCPayloadUpdateBuildStepMessage:
    PayloadUUID: str = ""
    StepName: str = ""
    StepStdout: str = ""
    StepSuccess: bool = True
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@dataclass
class MythicRPCFileGetContentMessage:
    AgentFileId: str = ""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@dataclass
class MythicRPCFileSearchMessage:
    AgentFileId: str = ""
    Filename: str = ""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


async def SendMythicRPCPayloadUpdatebuildStep(msg):
    rpc_log.append({
        "kind": "build_step",
        "PayloadUUID": msg.PayloadUUID,
        "StepName": msg.StepName,
        "StepStdout": msg.StepStdout,
        "StepSuccess": msg.StepSuccess,
    })
    return _RPCResponse(success=True)


async def SendMythicRPCFileGetContent(msg):
    content = file_content_fixtures.get(msg.AgentFileId, b"")
    rpc_log.append({
        "kind": "file_get_content",
        "AgentFileId": msg.AgentFileId,
        "matched": msg.AgentFileId in file_content_fixtures,
    })
    return _RPCResponse(success=bool(content), content=content)


async def SendMythicRPCFileSearch(msg):
    rpc_log.append({
        "kind": "file_search",
        "AgentFileId": getattr(msg, "AgentFileId", ""),
        "Filename": getattr(msg, "Filename", ""),
    })
    return _RPCResponse(success=False, files=[])


# ---------------------------------------------------------------------------
# Install into sys.modules so `from mythic_container.X import *` works
# ---------------------------------------------------------------------------

def _install_optional_dep_stubs():
    """Provide bare-minimum stubs for optional packages some plugins import
    at validate() time. These exist in the Mythic docker image but not on
    host test runners. We only stub the attributes plugins actually touch
    during validate(), not their full API - any real use will crash.
    """
    # py7zr: archive_container only does `import py7zr` in validate().
    if "py7zr" not in sys.modules:
        stub = types.ModuleType("py7zr")
        stub.SevenZipFile = object  # placeholder
        sys.modules["py7zr"] = stub
    # openpyxl: payload_maldocs validate() imports it (R3a relaxed the
    # validate() so VBA gens work without openpyxl, but the import still
    # happens under try/except - stubbing avoids the warning noise in
    # test output).
    if "openpyxl" not in sys.modules:
        stub = types.ModuleType("openpyxl")
        stub.Workbook = object
        sys.modules["openpyxl"] = stub


def install():
    """Create fake mythic_container package and subpackages in sys.modules."""
    _install_optional_dep_stubs()
    pkg = types.ModuleType("mythic_container")
    pkg.__path__ = []  # mark as package
    sys.modules["mythic_container"] = pkg

    # PayloadBuilder surface
    pb = types.ModuleType("mythic_container.PayloadBuilder")
    pb.PayloadType = PayloadType
    pb.SupportedOS = SupportedOS
    pb.AgentType = AgentType
    pb.HideCondition = HideCondition
    pb.HideConditionOperand = HideConditionOperand
    pb.BuildParameter = BuildParameter
    pb.BuildParameterType = BuildParameterType
    pb.BuildStep = BuildStep
    pb.BuildResponse = BuildResponse
    pb.BuildStatus = BuildStatus
    sys.modules["mythic_container.PayloadBuilder"] = pb

    # MythicCommandBase surface (minimal - builder.py only wildcard-imports)
    mcb = types.ModuleType("mythic_container.MythicCommandBase")
    mcb.CommandBase = CommandBase
    # Re-export the PayloadBuilder names - `from MythicCommandBase import *`
    # grabs whatever's in the module, and builder.py uses BuildStatus / etc.
    for n in ("PayloadType", "SupportedOS", "BuildParameter", "BuildParameterType",
              "BuildStep", "BuildResponse", "BuildStatus"):
        setattr(mcb, n, getattr(pb, n))
    sys.modules["mythic_container.MythicCommandBase"] = mcb

    # MythicRPC surface
    rpc = types.ModuleType("mythic_container.MythicRPC")
    rpc.SendMythicRPCPayloadUpdatebuildStep = SendMythicRPCPayloadUpdatebuildStep
    rpc.SendMythicRPCFileGetContent = SendMythicRPCFileGetContent
    rpc.SendMythicRPCFileSearch = SendMythicRPCFileSearch
    rpc.MythicRPCPayloadUpdateBuildStepMessage = MythicRPCPayloadUpdateBuildStepMessage
    rpc.MythicRPCFileGetContentMessage = MythicRPCFileGetContentMessage
    rpc.MythicRPCFileSearchMessage = MythicRPCFileSearchMessage
    sys.modules["mythic_container.MythicRPC"] = rpc

    return pkg
