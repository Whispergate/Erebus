+++
title = "Plugins"
chapter = false
weight = 2
pre = "<b>2. </b>"
+++

## Overview

Erebus ships most of its build functionality as plugins auto-discovered at startup. The plugin loader scans `erebus/modules/plugin_*.py` for files that inherit from `ErebusPlugin`, instantiates each one, runs its `validate()` hook, and registers every function returned by `register()` into the builder's global namespace so `builder.py` can call them directly. See the `_PLUGIN_FUNCTIONS` list at the top of [builder.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/builder.py) for the exact set of plugin-provided functions the builder consumes.

This page is the **operator-facing catalog**: what ships, what each plugin does, which BuildParameters it consumes, and what it drops into `payload/`. For authoring your own plugins, see [Plugin Development]({{% relref "plugin-development.md" %}}). For per-plugin tradecraft and hardening notes, see [OPSEC]({{% relref "opsec.md" %}}).

## Plugin categories

| Category | Purpose |
|---|---|
| `TRIGGER` | Victim-clickable artefacts that launch the compiled loader (`.lnk`, `.bat`, `.msi`, `.msc`, `.html`, ClickOnce) |
| `CONTAINER` | Distribution wrappers (`ISO`, `7z`, `Zip`, `MSI`, `Electron`) |
| `PAYLOAD` | Loader-adjacent transforms (DLL proxy generation, MalDoc generation, XLL add-ins) |
| `CODESIGNER` | AuthentiCode signing of produced artefacts (self-signed, URL-spoofed, provided cert) |
| `OTHER` | Utility functions that don't fit the above |

## Trigger plugins

### LNK

*Windows shortcut (`.lnk`) that executes a trigger binary with configurable args, icon, and optional decoy chain. Built natively on Linux via `pylnk3` - no Windows host required.*

- **Module:** [plugin_trigger_lnk.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_lnk.py)
- **Consumes:** `0.9a Trigger Binary`, `0.9b Trigger Command`, `0.13 Decoy File`
- **Key features:**
  - Configurable target binary + command-line arguments
  - Icon resolution from any system DLL (e.g. `shell32.dll,0`)
  - Optional decoy file execution chain
  - Pure-Python; runs inside the Mythic Docker container
- **Output:** `payload/<trigger>.lnk`

### BAT

*Batch-script (`.bat`) trigger that chains the trigger binary and a decoy document display.*

- **Module:** [plugin_trigger_bat.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_bat.py)
- **Consumes:** `0.9a Trigger Binary`, `0.9b Trigger Command`, `0.13 Decoy File`
- **Key features:**
  - Minimal two-line batch template
  - Environment-variable tricks for path obfuscation
  - Staged execution timing via `timeout` delays
- **Output:** `payload/<trigger>.bat`

### MSI Trigger

*MSI package used as a direct execution trigger (distinct from the MSI container - the trigger variant contains the compiled loader as a CustomAction rather than wrapping a pre-existing binary).*

- **Module:** [plugin_trigger_msi.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_msi.py)
- **Consumes:** `0.9 Trigger Type = MSI`, plus the `5.x` MSI Options section
- **Key features:** CustomAction-based execution, configurable install scope and conditions.
- **Output:** `payload/<trigger>.msi`

### MSC (GrimReaper)

*Windows Management Console snap-in (`.msc`) activated by Explorer via `mmc.exe`. Uses a custom `ConsoleTaskpad` structure with a Mark-of-the-Web bypass variant.*

- **Module:** [plugin_trigger_msc.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_msc.py)
- **Consumes:** `0.9 Trigger Type = MSC`
- **Key features:**
  - Process lineage parents under `mmc.exe` (a legitimate signed Windows binary)
  - No file-extension warning dialog on Explorer double-click
  - XML-based, bypasses some AV file-scanning heuristics
- **Output:** `payload/<trigger>.msc`

### ClickOnce Trigger

*ClickOnce application manifest (`.application`) that downloads and runs a .NET loader via the Windows ClickOnce deployment platform.*

- **Module:** [plugin_trigger_clickonce.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_clickonce.py)
- **Consumes:** `0.9 Trigger Type = ClickOnce`
- **Key features:** Manifest signing support, hash verification, deployment-URL-based lure.
- **Output:** `payload/<trigger>.application` + satellite files

### HTML Smuggling

*Self-contained `.html` page with the loader XOR-obfuscated (per-build random 16-byte key) and base64-embedded. JavaScript reverses both layers at runtime and reconstructs a `Blob` for download, so the encoded payload never traverses the network and gateway base64 scanners see nothing.*

- **Module:** [plugin_trigger_html_smuggling.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_html_smuggling.py)
- **Consumes:** `0.9 Trigger Type = HTML`
- **Key features:**
  - Per-build random XOR key - no two pages share a decoder fingerprint
  - Randomised JavaScript variable identifiers
  - Configurable page title, heading, body text, button label, and download filename (malleable lure)
  - Optional auto-download with configurable delay
- **Output:** `payload/<trigger>.html`

### ClickFix

*Fake CAPTCHA / verification HTML page that silently copies a configured command (typically a PowerShell download cradle) to the clipboard via `navigator.clipboard.writeText`, then walks the victim through Win+R → Ctrl+V → Enter to execute it. Defeats file-based AV entirely - no binary artefact leaves the browser.*

- **Module:** [plugin_trigger_html_smuggling.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_html_smuggling.py) *(shares the module with HTML Smuggling)*
- **Consumes:** `0.9 Trigger Type = ClickFix`, `0.9c ClickFix Command`
- **Key features:**
  - Malleable branding: `brand_name`, `brand_color`, heading/message, per-step instruction text, button label
  - Command escaped for safe JS embedding
  - Works on all modern browsers without plugins or permission prompts
- **Output:** `payload/<trigger>.html`

## Container plugins

### Archive (7z / Zip)

*Compressed archive containers with optional password protection and file-attribute hiding.*

- **Module:** [plugin_archive_container.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_archive_container.py)
- **Consumes:** `3.0 Container Type = 7z|Zip`, `3.1 Compression Level`, `3.2 Archive Password`
- **Key features:**
  - 7z with LZMA2 compression + optional AES-256 + header encryption (`-mhe`)
  - ZIP with ZipCrypto or AES password protection
  - Hide non-trigger files from the visible archive listing via file attributes
- **Output:** `payload/<name>.{7z,zip}`

### ISO

*ISO9660/Joliet disk image that Explorer mounts as a drive when double-clicked.*

- **Module:** [plugin_container_iso.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_iso.py)
- **Consumes:** `3.0 Container Type = ISO`, `4.0 ISO Volume ID`, `4.1 ISO enable Autorun`, `4.2 ISO Backdoor File`
- **Key features:**
  - Custom volume label (appears in Explorer)
  - Optional `autorun.inf` generation
  - Joliet-extension file hiding
  - Optional backdoor mode - inject the payload into an existing uploaded ISO
- **Output:** `payload/<name>.iso`

### MSI

*Windows Installer database created via `wixl` (msitools), optionally backdooring an existing MSI.*

- **Module:** [plugin_container_msi.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_msi.py)
- **Consumes:** `3.0 Container Type = MSI`, `5.0` – `5.9` MSI Options
- **Key features:**
  - Create-from-scratch MSI via WiX source generation
  - Backdoor an existing MSI with multiple attack vectors: `execute`, `run-exe`, `load-dll`, `dotnet`, `script`
  - CAB-stream bundling for additional payload files
  - Configurable install scope (User / Machine), execution conditions, custom action names
- **Output:** `payload/<name>.msi`

### ClickOnce Container

*ClickOnce deployment package (`.application` + application manifest + deployed exe), hash-verified.*

- **Module:** [plugin_container_clickonce.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_clickonce.py)
- **Consumes:** `3.0 Container Type = ClickOnce`
- **Key features:** Full ClickOnce manifest generation, SHA-256 file hashing, trusted-publisher execution model.
- **Output:** `payload/<name>/` (deployment tree)

### Electron Fake-Installer

*Single portable Windows `.exe` built with `electron-builder`. Wraps the compiled loader as an `extraResources` tree and presents a Next / Install / Finish wizard. The wizard stages the embedded loader to `%TEMP%\inst-<uuid>` and spawns it detached + hidden - but only after passing a two-gate guardrail system.*

- **Module:** [plugin_container_electron.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_electron.py)
- **Consumes:** `3.0 Container Type = Electron`, `3.E0` – `3.E9p` Electron Options
- **Key features:**
  - **Two build modes** - `In-Container (Wine)` (one-step Linux build via wine for rcedit/winCodeSign) or `Deferred (Erebus.Helper)` (stage source + `build_electron.bat` for a Windows host)
  - **PE resource rewriting** - all six Windows Properties → Details fields (FileDescription, ProductName, ProductVersion, FileVersion, Copyright, CompanyName) are operator-controlled via `3.E0`/`3.E1`/`3.E2`/`3.E7`/`3.E8`
  - **Custom icon upload** (`3.E6a`) accepting PNG/JPEG/GIF/BMP/WEBP/TIFF/SVG; SVG is rasterised to 512×512 via `cairosvg`, then Pillow produces a multi-size ICO (16/24/32/48/64/128/256) embedded via rcedit
  - **Three entry formats** - `exe` (direct `CreateProcess`), `dll` (`rundll32.exe <dll>,<entry>`), `xll` (`excel.exe /e <xll>`)
  - **Two-gate guardrail system** - interaction token (dwell time + real mousemove required before the token is issued) + 15 environment checks (debugger, sandbox env vars, default bad usernames/hostnames, operator-supplied white/blocklists, min screen size, min CPU count, min RAM, max idle time, pre-spawn delay). Guardrail failures are silent: the wizard still shows fake progress → Finish even when the loader never ran.
- **Output:** `payload/erebus.exe` (portable fake-installer)

## Payload plugins

### DLL Proxy Generation

*Generates a DLL proxy DEF file for DLL sideloading chains.*

- **Module:** [plugin_payload_dll_proxy.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_payload_dll_proxy.py)
- **Consumes:** `0.0 Main Payload Type = Hijack`, `1.0 DLL Hijacking` (uploaded source DLL)
- **Key features:**
  - Automatic export parsing from the uploaded target DLL via `pefile`
  - Generates a `proxy.def` that forwards all target exports back to the original DLL
  - Integrates with the C++ loader compilation pipeline so the generated proxy gets compiled + linked automatically
- **Output:** `payload/erebus.dll` (proxy DLL with embedded shellcode)

### MalDocs (Excel VBA + XLL)

*Creates Excel documents (XLSM/XLSX/XLAM) with VBA payloads or compiles XLL Add-In DLLs. VBA is compiled to a valid `vbaProject.bin` directly on Linux via `agent_code/vba_compiler/`.*

- **Module:** [plugin_payload_maldocs.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_payload_maldocs.py)
- **Consumes:** `0.9 Create MalDoc`, `0.9a` – `0.9p` MalDoc Options
- **Key features:**
  - **Three output modes**: `VBA Module Only` (`.bas` for manual import), `Create/Backdoor Excel` (full workbook), `XLL Add-In DLL` (native Excel add-in)
  - **Four VBA loader techniques**: `VirtualAlloc+CreateThread` (classic), `EnumSystemLocalesA` (callback-based), `QueueUserAPC` (no new thread), `Process Hollowing` (notepad.exe host)
  - **Dynamic payload discovery** - `FindPayload` VBA function searches `ThisWorkbook.Path`, `%TEMP%`, `%APPDATA%`, `%USERPROFILE%\Desktop|Downloads|Documents`, OneDrive-synced shell folders at runtime. Path quoting via `Chr(34)` handles spaces. Macro exits silently if the payload is not found.
  - **Linux-native build** - VBA is compiled on the Mythic Docker container via the built-in MS-OVBA-compliant compiler; optional Windows-side COM re-injection via `erebus_helper.py` is available for higher-fidelity output via `build_maldoc.bat`
  - **XLL support** - generates C/C++ XLL source with configurable injection method, compiler (MSVC/MinGW), guardrail injection, and extra linker flags; XLL compilation is deferred to a Windows host via `erebus_helper.py xll`
  - **Execution triggers**: AutoOpen, OnClose, OnSave
  - **VBA obfuscation** toggle (variable renaming, string splitting, dead-code insertion)
- **Output:** `payload/<name>.{xlsm,xlsx,xlam}`, or `payload/<name>.bas` + optional `build_maldoc.bat`, or staged XLL source + `build_xll.bat`

## CodeSigner plugin

### CodeSigner

*Applies AuthentiCode signatures to loader binaries and container outputs via `osslsigncode`. Runs post-compile.*

- **Module:** [plugin_codesigner.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_codesigner.py)
- **Consumes:** `6.0 Codesign Loader`, `6.1 Codesign Type`, `6.2` – `6.6` Codesign Options
- **Key features (three signing modes):**
  - **SelfSign** - OpenSSL generates an X.509 cert with operator-supplied CN and Organisation Name; signs the payload with it.
  - **Spoof URL** - fetches the SSL certificate details from a target URL and clones them into a self-signed cert. Matches a legitimate organisation's metadata without a real chain of trust.
  - **Provide Certificate** - operator uploads a PFX/P12 file (plus optional password). Signed output has a real chain of trust; revocation exposure is the tradeoff.
- **Output:** replaces the unsigned artefact in `payload/` with a signed copy.

## Plugin dispatch

`builder.py` declares a `_PLUGIN_FUNCTIONS` list at the top of the file; at import time, the plugin loader resolves each name through the auto-discovered plugins and injects the callable into `builder.py`'s global namespace. This means plugin functions are invoked **directly as function calls** from the builder - no wrapper layer.

BuildParameter dispatch follows a predictable pattern:

1. The operator selects a value (e.g. `3.0 Container Type = Electron`).
2. `builder.py`'s `containerise_payload` method switches on that value and calls the corresponding plugin function (e.g. `build_electron_installer(...)`).
3. The plugin reads the rest of its `3.E*` BuildParameters, does its work, and returns a `pathlib.Path` to the produced artefact.

See the `match` statement in `containerise_payload` and the per-trigger-type dispatch in the trigger section of `build()` for the full plumbing.

## Related documentation

- **[Plugin Development]({{% relref "plugin-development.md" %}})** - writing, validating, and testing new plugins.
- **[Development]({{% relref "development.md" %}})** - full BuildParameter reference and build-step pipeline.
- **[OPSEC]({{% relref "opsec.md" %}})** - per-plugin tradecraft considerations and improvement suggestions.
