"""
Erebus Plugin - ClickOnce Container
Author: Whispergate
Description: Plugin for creating ClickOnce deployment packages

This plugin demonstrates:
1. How to inherit from ErebusPlugin
2. How to wrap existing container_clickonce module
3. How to create ClickOnce bundles for .NET payload delivery
"""

import pathlib
from typing import Dict, Callable

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory

try:
    from erebus_wrapper.erebus.modules.archive import container_clickonce
except ImportError:
    from archive import container_clickonce

class ClickOnceContainerPlugin(ErebusPlugin):
    """
    Plugin for creating ClickOnce deployment containers.
    
    This plugin provides functionality to package .NET payloads into
    ClickOnce deployment bundles with manifests and deployment files.
    """
    
    def __init__(self):
        """Initialize the ClickOnce container plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.DEFAULT_ROOT = self.REPO_ROOT / "agent_code"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="clickonce_container",
            version="1.0.0",
            author="Whispergate",
            description="Creates ClickOnce deployment packages for .NET payload delivery",
            category=PluginCategory.CONTAINER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "build_clickonce": self.build_clickonce,
        }
    
    def validate(self) -> tuple[bool, str]:
        """Validate that required dependencies are available"""
        try:
            import json
            return (True, None)
        except ImportError as e:
            return (False, f"Missing required dependency: {e}")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] ClickOnce Container plugin loaded - Supporting .NET deployment packages")
    
    # ==================== Plugin Functions ====================
    
    def build_clickonce(
        self,
        spec_name: str = "spec.json",
        out_dir_name: str = "clickonce"
    ) -> pathlib.Path:
        """
        Create a ClickOnce deployment package.
        
        Args:
            spec_name: Specification file name (JSON format)
            out_dir_name: Output directory name
            
        Returns:
            pathlib.Path: Path to the created ClickOnce container directory
            
        Raises:
            RuntimeError: If ClickOnce package creation fails
        """
        return container_clickonce.build_clickonce(
            spec_name=spec_name,
            out_dir_name=out_dir_name
        )


def get_plugin() -> ClickOnceContainerPlugin:
    """Factory function to get plugin instance"""
    return ClickOnceContainerPlugin()


if __name__ == "__main__":
    _plugin = ClickOnceContainerPlugin()
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
