"""Erebus Plugin: Shellcode Obfuscation helpers.

Thin ErebusPlugin wrapper that exposes the pure command-construction and
key/IV parsing helpers from `archive/shellcode_obfuscation.py` through the
plugin auto-discovery registry. Builder.py calls these functions by their
registered names (`build_obfuscation_cmd`, `build_key_extraction_cmd`,
`build_raw_key_cmd`, `parse_key_iv`, `extract_raw_key_array`) via the
module-level globals() injection performed at import time.

No state, no subprocess, no Mythic RPC. The async subprocess invocation
lives in the caller because it's coupled to build()'s `output` accumulator
and the Mythic build-step response flow; splitting that apart would
require a context object and breaks the "plugins are pure" convention.
"""

from typing import Dict, Callable

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from .archive import shellcode_obfuscation as _sc
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from archive import shellcode_obfuscation as _sc


class ShellcodeObfuscationPlugin(ErebusPlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="shellcode_obfuscation",
            version="1.0.0",
            author="Whispergate",
            description="Pure helpers for constructing shellcrypt CLI vectors and parsing its output",
            category=PluginCategory.PAYLOAD,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "build_obfuscation_cmd": _sc.build_obfuscation_cmd,
            "build_key_extraction_cmd": _sc.build_key_extraction_cmd,
            "build_raw_key_cmd": _sc.build_raw_key_cmd,
            "parse_key_iv": _sc.parse_key_iv,
            "extract_raw_key_array": _sc.extract_raw_key_array,
        }

    def validate(self):
        return (True, None)


if __name__ == "__main__":
    p = ShellcodeObfuscationPlugin()
    print(p.get_metadata())
    print(list(p.register().keys()))
