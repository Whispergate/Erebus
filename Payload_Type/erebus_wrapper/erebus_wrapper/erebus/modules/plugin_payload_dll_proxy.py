"""
Erebus Plugin - DLL Proxy Generator
Author: Whispergate
Description: Generates DLL proxy definitions for DLL hijacking attacks

This plugin analyzes legitimate DLLs and generates proxy export definitions
that can be used to create hijacking DLLs. The generated proxies forward
calls to the original DLL while allowing injection of malicious code.
"""

import pathlib
import asyncio
from typing import Dict, Callable, Optional

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class DllProxyPlugin(ErebusPlugin):
    """
    Plugin for generating DLL proxy/hijack definitions.
    """
    
    def __init__(self):
        """Initialize the DLL proxy plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.HIJACK_DIR = self.AGENT_CODE / "hijack"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="dll_proxy",
            version="1.0.0",
            author="Whispergate",
            description="Generates DLL proxy definitions for DLL hijacking attacks",
            category=PluginCategory.PAYLOAD,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "generate_proxies": self.generate_proxies,
            "generate_proxies_sync": self.generate_proxies_sync,
        }
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate that pefile library is available"""
        try:
            import pefile
            return (True, None)
        except ImportError:
            return (False, "pefile library not found. Please install with: pip install pefile")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] DLL Proxy plugin loaded - Supporting DLL hijacking generation")
    
    def _get_payload_dll_proxy(self):
        """Lazy import for archive.payload_dll_proxy"""
        try:
            from .archive import payload_dll_proxy
        except ImportError:
            from archive import payload_dll_proxy
        return payload_dll_proxy
    
    # ==================== Plugin Functions ====================
    
    async def generate_proxies(self, dll_file: pathlib.Path, dll_file_name: str) -> str:
        """
        Generate proxy export definitions for DLL hijacking (async version).
        """
        try:
            if not dll_file.exists():
                raise FileNotFoundError(f"DLL file not found: {dll_file}")
            
            payload_dll_proxy = self._get_payload_dll_proxy()
            return await payload_dll_proxy.generate_proxies(str(dll_file), dll_file_name)
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate DLL proxies: {e}")
    
    def generate_proxies_sync(self, dll_file: pathlib.Path, dll_file_name: str) -> str:
        """
        Generate proxy export definitions for DLL hijacking (synchronous version).
        """
        try:
            return asyncio.run(self.generate_proxies(dll_file, dll_file_name))
        except Exception as e:
            raise RuntimeError(f"Failed to generate DLL proxies (sync): {e}")


if __name__ == "__main__":
    print("Testing DLL Proxy Plugin...")
    
    plugin = DllProxyPlugin()
    
    metadata = plugin.get_metadata()
    print(f"Plugin: {metadata.name} v{metadata.version}")
    print(f"Category: {metadata.category.value}")
    print(f"Description: {metadata.description}")
    
    is_valid, error = plugin.validate()
    if is_valid:
        print("✓ Plugin validation passed - pefile library available")
    else:
        print(f"✗ Plugin validation failed: {error}")
    
    print("\nRegistered functions:")
    for func_name in plugin.register().keys():
        print(f"  - {func_name}")
    
    print("\nTesting complete!")