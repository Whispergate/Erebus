"""Erebus Plugin: Loader Config Helpers.

Thin wrapper around `archive/loader_config.py` - exposes the
`build_loader_config_data` helper via the plugin auto-discovery registry
so builder.py can call it without an explicit archive-module import.
"""

from typing import Dict, Callable

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from .archive import loader_config as _lc
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from archive import loader_config as _lc


class LoaderConfigPlugin(ErebusPlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="loader_config",
            version="1.0.0",
            author="Whispergate",
            description="Pure helper for building the config.hpp Jinja context dict",
            category=PluginCategory.PAYLOAD,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "build_loader_config_data": _lc.build_loader_config_data,
        }

    def validate(self):
        return (True, None)


if __name__ == "__main__":
    p = LoaderConfigPlugin()
    print(p.get_metadata())
    print(list(p.register().keys()))
