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
| `TRIGGER` | Victim-clickable artefacts that launch the compiled loader - **Windows:** `.lnk`, `.bat`, `.msi`, `.msc`, `.html`, `.hta`, `.url`, `.js`/`.wsf`, `.chm`, `.svg`, ClickOnce · **Linux:** `.sh`, `.desktop` · **macOS:** `.command`, `.scpt`, `.pkg` · **Cross-platform:** HTML Smuggling, QR |
| `CONTAINER` | Distribution wrappers (`ISO`, `VHD`, `7z`, `Zip`, `MSI`, `Electron`, `AppInstaller`/`MSIX`). Supports two-layer chaining via `3.0T Outer Transport`. |
| `PAYLOAD` | Loader-adjacent transforms (DLL proxy generation, MalDoc generation, XLL add-ins, PE/DLL/\.NET → shellcode via Donut, Word/PowerPoint documents, decoy document lures) |
| `CODESIGNER` | AuthentiCode signing of produced artefacts (self-signed, URL-spoofed, provided cert) |
| `OTHER` | Utility functions: PE metadata sanitiser, self-hunt IOC scanner, C2 redirector config generator, phishing page generator |

## Trigger plugins

> **0.0 Target OS selection** - The `0.0 Target OS` BuildParameter (top of the parameter list) gates which trigger set is visible. Setting it to `Windows` shows the Windows triggers below and hides the Linux/macOS ones. `Linux` shows Bash and Desktop (plus HTML/QR). `macOS` shows Command, AppleScript, and PKG (plus HTML/QR). Windows-specific sub-parameters (`0.9a Trigger Binary`, `0.9b Trigger Command`, etc.) are also hidden when a non-Windows OS is selected.

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

### HTA

*HTML Application (`.hta`) file executed by `mshta.exe`. Supports VBScript (default) or JScript; window is immediately minimised and self-closes after launch.*

- **Module:** [plugin_trigger_hta.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_hta.py)
- **Consumes:** `0.9 Trigger Type = HTA`, `0.9a Trigger Binary`, `0.9b Trigger Command`
- **Key features:**
  - Process lineage: `explorer.exe → mshta.exe` (signed Windows binary)
  - VBScript or JScript scripting engine (configurable)
  - Configurable `HTA:APPLICATION` name shown briefly in taskbar
  - Optional decoy document opened in parallel
  - No SmartScreen warning when opened from a mounted ISO/VHD
- **Output:** `payload/<trigger>.hta`

### URL / Internet Shortcut

*Windows internet shortcut (`.url`) that triggers SMB authentication or WebDAV auto-mount when double-clicked. Best combined with an ISO or VHD outer container for MOTW bypass.*

- **Module:** [plugin_trigger_url.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_url.py)
- **Consumes:** `0.9 Trigger Type = URL`, `0.9a Trigger URL`
- **Key features:**
  - SMB/UNC mode (`file://ATTACKER/share/payload.exe`) - captures NTLM credentials; combine with Responder/ntlmrelayx
  - WebDAV mode (`http://ATTACKER/payload.exe`) - auto-mounts share, avoids local disk write
  - Configurable icon (shell32.dll index) shown in Explorer
  - Files inside ISO/VHD do not inherit MOTW from the outer container
- **Output:** `payload/<trigger>.url`

### JScript / WSF

*JScript (`.js`) or Windows Script File (`.wsf`) trigger executed by `wscript.exe` / `cscript.exe`.*

- **Module:** [plugin_trigger_jscript.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_jscript.py)
- **Consumes:** `0.9 Trigger Type = JScript`
- **Key features:**
  - `.js`: plain JScript via `ActiveXObject("WScript.Shell").Run()`
  - `.wsf`: wraps JScript in XML `<job><script>` envelope - breaks many single-string AV signature patterns
  - Supports mixed VBScript + JScript in a single `.wsf` file for additional evasion
  - Randomised variable and function identifiers per build
- **Output:** `payload/<trigger>.{js,wsf}`

### CHM

*Compiled HTML Help (`.chm`) file that auto-executes a command via the `hhctrl.ocx` ShortCut ActiveX object when double-clicked. Executed by `hh.exe` (signed Windows binary). Compilation is deferred to a Windows host.*

- **Module:** [plugin_trigger_chm.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_chm.py)
- **Consumes:** `0.9 Trigger Type = CHM`, `0.9a Trigger Binary`, `0.9b Trigger Command`
- **Key features:**
  - Process lineage: `explorer.exe → hh.exe` (Microsoft HTML Help, a signed binary)
  - ShortCut Item1 ActiveX fires on `body onload` - no user click required inside the CHM
  - Configurable window title and lure body text
  - Emits a `build_chm.bat` runbook for Windows-side compilation via `hhc.exe`; alternatively compile via `erebus_helper.py chm`
- **Output:** `payload/chm_project/` (source tree + `build_chm.bat`); `.chm` produced after Windows-side compilation

### SVG Smuggling

*SVG image file with an embedded JavaScript payload blob that reconstructs and auto-downloads the loader binary when opened in any modern browser. Targets mail gateways that strip `.html`/`.htm` attachments but pass `.svg` as an image.*

- **Module:** [plugin_trigger_svg_smuggling.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_svg_smuggling.py)
- **Consumes:** `0.9 Trigger Type = SVG`
- **Key features:**
  - SVG rendered natively by Chrome, Edge, Firefox - `<script>` executes without a download prompt
  - Per-build random XOR key + randomised variable identifiers (same technique as HTML Smuggling)
  - Base64 payload split across multiple `<text>` elements to break single-string regex signatures
  - Configurable download filename
- **Output:** `payload/<trigger>.svg`

---

### Bash (Linux / macOS)

*Bash script (`.sh`) trigger that backgrounds the payload via `nohup` and optionally opens a decoy file. Available when `0.0 Target OS = Linux` or `0.0 Target OS = macOS`.*

- **Module:** [plugin_trigger_bash.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_bash.py)
- **Consumes:** `0.9-L Linux Trigger Type = Bash` (Linux) or `0.9-M macOS Trigger Type = Bash` (macOS), `0.9a Trigger Binary`, `0.9b Trigger Command`, `0.13 Decoy File`
- **Key features:**
  - `nohup bash -c '...' >/dev/null 2>&1 &` - process detaches immediately; parent shell exits clean
  - Base64 eval obfuscation wraps the command in `eval "$(echo <b64> | base64 -d)"` to break static string scanning
  - Decoy opener adapts to platform: `xdg-open` on Linux, `open` on macOS
- **Output:** `payload/update.sh`

### Desktop (Linux)

*XDG `.desktop` application launcher that executes the payload when double-clicked in a graphical file manager (Nautilus, Dolphin, Thunar, etc.). Available when `0.0 Target OS = Linux`.*

- **Module:** [plugin_trigger_desktop.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_desktop.py)
- **Consumes:** `0.9-L Linux Trigger Type = Desktop`, `0.9a Trigger Binary`, `0.9b Trigger Command`
- **Key features:**
  - Standard `[Desktop Entry]` format - `Type=Application`, `Terminal=false`, `StartupNotify=false`
  - `Exec=bash -c "... >/dev/null 2>&1 &"` runs payload silently without a terminal window
  - `Name=` and `Icon=` masquerade as a PDF document (`Icon=application-pdf`)
  - Files delivered inside a ZIP archive bypass GNOME 42+ download quarantine marking
- **Output:** `payload/document.desktop`

### Command (macOS)

*macOS `.command` file that Terminal.app executes when double-clicked in Finder. Backgrounds the payload via `nohup` then closes the Terminal window via `osascript`. Available when `0.0 Target OS = macOS`.*

- **Module:** [plugin_trigger_command.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_command.py)
- **Consumes:** `0.9-M macOS Trigger Type = Command`, `0.9a Trigger Binary`, `0.9b Trigger Command`, `0.13 Decoy File`
- **Key features:**
  - `cd "$(dirname "$0")"` resolves payload path relative to the script - works from inside a ZIP extract
  - `nohup bash -c '...' >/dev/null 2>&1 &` detaches the payload from Terminal.app's process group
  - `osascript` closes the Terminal window after execution so no window lingers
  - Optional decoy via `open <file> &`
  - Deliver inside a ZIP to avoid Gatekeeper quarantine on the `.command` file (macOS ≤ 12 does not propagate xattr into ZIP contents)
- **Output:** `payload/setup.command`

### AppleScript (macOS)

*AppleScript (`.scpt`) trigger executed via `osascript`. Uses `do shell script` to run the payload hidden with no Terminal window. Available when `0.0 Target OS = macOS`.*

- **Module:** [plugin_trigger_applescript.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_applescript.py)
- **Consumes:** `0.9-M macOS Trigger Type = AppleScript`, `0.9a Trigger Binary`, `0.9b Trigger Command`, `0.13 Decoy File`
- **Key features:**
  - `do shell script "<cmd> >/dev/null 2>&1 &"` - no Terminal window, process detaches immediately
  - Command string reassembled from ASCII character codes (`character id N`) at runtime to break static string signatures
  - Optional `open "<decoy>"` after execution
  - Combine with a `.command` wrapper that calls `osascript update.scpt` in the background for Finder double-click delivery
- **Output:** `payload/update.scpt`

### PKG (macOS)

*macOS PKG installer that executes the payload via a `postinstall` bash script running as root inside Installer.app. Available when `0.0 Target OS = macOS`.*

- **Module:** [plugin_trigger_pkg.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_pkg.py)
- **Consumes:** `0.9-M macOS Trigger Type = PKG`
- **Key features:**
  - `scripts/postinstall` - `chmod +x`, `nohup "$payload" >/dev/null 2>&1 &`, `exit 0`. Installer.app shows "Installation was successful" regardless of whether the loader fires.
  - `PackageInfo` XML stub generated alongside the scripts for manual assembly
  - If `pkgbuild` is present on the build host, assembles a real `.pkg` via `pkgbuild --root ... --scripts ...`
  - If `pkgbuild` is unavailable (Linux Docker build host), emits the raw `pkg_project/` directory with instructions to assemble on a macOS host via `pkgbuild`
  - Sign with `productsign` + an Apple Developer ID Installer cert to pass Gatekeeper on macOS 12+
- **Output:** `payload/SystemUpdate.pkg` (if `pkgbuild` available) or `payload/pkg_project/` (raw scripts + PackageInfo for deferred assembly)

---

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

### VHD

*Fixed Virtual Hard Disk (`.vhd`) container. Windows mounts it on double-click; files inside do not inherit Mark-of-the-Web from the outer download. Bypasses ISO-blocking policies that specifically target `.iso` extension.*

- **Module:** [plugin_container_vhd.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_vhd.py)
- **Consumes:** `3.0 Container Type = VHD`, `4.0 ISO Volume ID` (volume label reused)
- **Key features:**
  - Fixed VHD with FAT16 filesystem - no external tools required (pure-Python fallback; mtools `mformat`/`mcopy` used when available)
  - Files inside the VHD do not inherit MOTW - full MOTW bypass without MotW-stripping tools
  - Different extension from ISO bypasses per-extension gateway/proxy blocks on `.iso`
  - Drop-in replacement for the ISO container in any delivery chain
- **Output:** `payload/payload.vhd`

### AppInstaller / MSIX

*MSIX application package or `.appinstaller` manifest that fetches and installs an MSIX from an attacker-controlled HTTPS host. Delivery is through the signed Windows `appinstaller.exe` binary with no elevation prompt on sideload-enabled targets.*

- **Module:** [plugin_container_msix.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_msix.py)
- **Consumes:** `3.0 Container Type = AppInstaller`, `3.AI0 MSIX Hosting URL`, `3.AI1 MSIX Package Name`, `3.AI2 MSIX Display Name`
- **Key features:**
  - **AppInstaller mode (default)** - generates a `.appinstaller` XML manifest; victim opens it, Windows fetches and installs the MSIX at the configured URL automatically
  - **MSIX mode** - produces the full MSIX package source tree + `build_msix.bat` for Windows-side signing via `makeappx.exe` + `signtool.exe`
  - Self-signed MSIX installs on Developer Mode targets and sideloading-enabled enterprise workstations without elevation
  - Threat actor precedent: used by Magniber ransomware and TA505/FIN7 delivery chains
- **Output:** `payload/setup.appinstaller` + `payload/msix_src/` (package source for deferred Windows build)

### Electron Fake-Installer

*Single portable Windows `.exe` built with `electron-builder`. Wraps the compiled loader as an `extraResources` tree and presents a Next / Install / Finish wizard. The wizard stages the embedded loader to `%TEMP%\inst-<uuid>` and spawns it detached + hidden - but only after passing a two-gate guardrail system.*

- **Module:** [plugin_container_electron.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_electron.py)
- **Consumes:** `3.0 Container Type = Electron`, `3.E0` – `3.E9p` Electron Options, `3.P0` – `3.P3` Persistence Options
- **Key features:**
  - **Two build modes** - `In-Container (Wine)` (one-step Linux build via wine for rcedit/winCodeSign) or `Deferred (Erebus.Helper)` (stage source + `build_electron.bat` for a Windows host)
  - **PE resource rewriting** - all six Windows Properties → Details fields (FileDescription, ProductName, ProductVersion, FileVersion, Copyright, CompanyName) are operator-controlled via `3.E0`/`3.E1`/`3.E2`/`3.E7`/`3.E8`
  - **Custom icon upload** (`3.E6a`) accepting PNG/JPEG/GIF/BMP/WEBP/TIFF/SVG; SVG is rasterised to 512×512 via `cairosvg`, then Pillow produces a multi-size ICO (16/24/32/48/64/128/256) embedded via rcedit
  - **Three entry formats** - `exe` (direct `CreateProcess`), `dll` (`rundll32.exe <dll>,<entry>`), `xll` (`excel.exe /e <xll>`)
  - **Two-gate guardrail system** - interaction token (dwell time + real mousemove required before the token is issued) + 15 environment checks (debugger, sandbox env vars, default bad usernames/hostnames, operator-supplied white/blocklists, min screen size, min CPU count, min RAM, max idle time, pre-spawn delay). Guardrail failures are silent: the wizard still shows fake progress → Finish even when the loader never ran.
  - **Persistence** (`3.P0` – `3.P3`) - optionally copy the loader to a permanent location before spawn and register one of four persistence mechanisms: Registry Run Key, Registry RunOnce, Startup Folder, or Scheduled Task. Copy is made to `%APPDATA%` or `%LOCALAPPDATA%` (operator-controlled). DLL/XLL formats write a `.bat` wrapper into the startup folder when the Startup Folder method is selected.
- **Output:** `payload/erebus.exe` (portable fake-installer)

### Container Chaining (`3.0T Outer Transport`)

*Any inner container (Electron, MSI, VHD, ISO, ZIP, 7z, AppInstaller) can be wrapped in an outer transport layer (ISO, VHD, ZIP, 7z) by setting `3.0T Outer Transport`. The inner artefact is copied into a fresh staging directory and packaged into the outer format.*

**Useful chains:**

| Inner | Outer | Effect |
|---|---|---|
| `Electron` | `ISO` | ISO disc containing setup.exe - MOTW bypass, Explorer mounts and shows the exe |
| `Electron` | `VHD` | Same as above but bypasses ISO-specific gateway/policy blocks |
| `MSI` | `ISO` | ISO containing an installer - common enterprise delivery chain |
| `MSI` | `VHD` | VHD disc containing installer.msi |
| `Zip` | `ISO` | ISO wrapping a password-protected archive |

Set `3.0T Outer Transport = None` (default) for no outer wrapping.

## Payload plugins

### Donut (PE / DLL / .NET → Shellcode)

*Converts a PE executable, DLL, or .NET assembly into raw position-independent shellcode via the `donut-shellcode` Python package, then feeds the output directly into the Shellcrypt obfuscation pipeline. Allows Erebus to accept PE/DLL inputs instead of raw shellcode.*

- **Module:** [plugin_payload_donut.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_payload_donut.py)
- **Key features:**
  - Supports `x86`, `x64`, and `x86+x64` dual-arch output
  - Output is treated as raw shellcode and passes through the full Shellcrypt compression → encryption → encoding chain
  - `donut_available()` check at build time; graceful error if `donut-shellcode` package is not installed
- **Requires:** `pip install donut-shellcode` on the Mythic Docker container (or host running the builder)

### OfficeDocs (Word / PowerPoint)

*Generates macro-enabled Office documents beyond the Excel-centric MalDoc plugin. All formats are pure-Python OOXML construction - no python-pptx, no LibreOffice required.*

- **Module:** [plugin_payload_officedoc.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_payload_officedoc.py)
- **Key features:**
  - **DOTM Remote Template Injection** - clean DOCX with an `<Relationship>` pointing to an attacker-hosted `.dotm`. Macros live on the remote template, not in the delivered attachment; survives email gateway scanning. WINWORD.EXE fetches the template on `Document_Open`.
  - **PPTM** - PowerPoint macro-enabled presentation with `Presentation_Open` / `Document_Open` VBA trigger.
  - **PPAM** - PowerPoint Add-In marked `IsAddIn=true`. Installs to `%APPDATA%\Microsoft\AddIns\` and re-executes on every PowerPoint launch after first open (implicit persistence).
- **Output:** `payload/<name>.{docx,pptm,ppam}` + optional `build_dotm.bat` for the hosted template

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
- **Consumes:** `0.9 Create MalDoc`, `0.9a` – `0.9v` MalDoc Options
- **Key features:**
  - **Three output modes**: `VBA Module Only` (`.bas` for manual import), `Create/Backdoor Document` (full workbook), `XLL Add-In DLL` (native Excel add-in)
  - **Four VBA loader techniques**: `VirtualAlloc+CreateThread` (classic), `EnumSystemLocalesA` (callback-based), `QueueUserAPC` (self-APC via SleepEx alertable wait), `AddressOfEntryPoint Injection` (overwrite child process entry point; no RWX allocation, no VirtualAllocEx)
  - **HTTP shellcode staging** (`0.9v`) - when a Mythic base URL is supplied, the builder RC4-encrypts the shellcode at build time, uploads it to the Mythic file store via `SendMythicRPCFileCreate`, and embeds a compact `GetBuf()` VBA downloader (~80 lines) instead of any inline shellcode bytes. Eliminates VBA module-size limits (previously caused OOM errors with >1 MB payloads). Accepts self-signed TLS certificates (`WinHttp Option(4) = &H3300`, `MSXML2.ServerXMLHTTP` fallback).
  - **Dual-layer obfuscation at rest** - in HTTP staging mode both the shellcode RC4 key and the staging URL are stored as RC4-encrypted `Array()` byte sequences in VBA source; neither appears in plaintext anywhere in the compiled document. URL is decrypted at runtime via `StrConv(Rc4D(urlEnc, urlKey), vbUnicode)`.
  - **Dynamic payload discovery** - `FindPayload` VBA function searches `ThisWorkbook.Path`, `%TEMP%`, `%APPDATA%`, `%USERPROFILE%\Desktop|Downloads|Documents`, OneDrive-synced shell folders at runtime. Path quoting via `Chr(34)` handles spaces. Macro exits silently if the payload is not found.
  - **Linux-native build** - VBA is compiled on the Mythic Docker container via the built-in MS-OVBA-compliant compiler; optional Windows-side COM re-injection via `erebus_helper.py` is available for higher-fidelity output via `build_maldoc.bat`
  - **XLL support** - generates C/C++ XLL source with configurable injection method, compiler (MSVC/MinGW), guardrail injection, and extra linker flags; XLL compilation is deferred to a Windows host via `erebus_helper.py xll`
  - **Execution triggers**: AutoOpen, OnClose, OnSave
  - **VBA obfuscation** toggle (variable renaming, string splitting, dead-code insertion)
- **Output:** `payload/<name>.{xlsm,xlsx,xlam}`, or `payload/<name>.bas` + optional `build_maldoc.bat`, or staged XLL source + `build_xll.bat`

### Decoy Document Generator

*Generates convincing lure documents (DOCX stub, XLSX stub) shown to the victim while the loader executes in the background. Templates cover invoice, HR policy, job offer, IT security notice, and NDA lure types.*

- **Module:** [plugin_trigger_decoy_doc.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_decoy_doc.py)
- **Key features:**
  - Five built-in lure templates: `invoice`, `hr_policy`, `job_offer`, `it_notice`, `nda`
  - Operator-supplied company name, recipient name, and optional letterhead logo (PNG/JPG embedded)
  - Document written to `%TEMP%` and deleted after display; separate from the `0.13 Decoy File` static upload path
- **Output:** `payload/<lure>.{docx,xlsx}`

## Infra / Utility plugins

### Redirector Config Generator

*Generates C2 redirector configurations (Apache mod_rewrite `.htaccess`, Nginx `location` block, Caddy `Caddyfile`) from operator-supplied C2 profile parameters. All non-matching traffic is forwarded to a configurable decoy redirect.*

- **Module:** [plugin_infra_redirector.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_infra_redirector.py)
- **Key features:**
  - Apache, Nginx, and Caddy output formats (one per build or all three)
  - URI pattern + User-Agent filter - only requests matching the C2 profile are proxied to the team server
  - Catch-all 302 redirect to a configurable decoy site so sandbox re-fetches see a normal response
  - Operator supplies team server IP, C2 URI regex, UA regex, and decoy URL
- **Output:** `payload/redirector/` containing `.htaccess`, `nginx.conf`, and `Caddyfile`

### Phishing Page Generator

*Generates static HTML credential-capture phishing pages that mimic enterprise login portals, plus a lightweight credential-capture backend stub (PHP or Python/Flask).*

- **Module:** [plugin_infra_phishing.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_infra_phishing.py)
- **Supported templates:** `o365` (Outlook Web App), `sharepoint` (file-sharing gate), `docusign` (signing prompt), `adfs` (AD Federation Services), `okta` (SSO login)
- **Key features:**
  - Pure static HTML - no python-pptx / Flask dependency at generation time
  - JS `POST /capture` submits credentials; PHP stub or Python/Flask backend logs and optional GoPhish webhook forwards them
  - After POST, victim receives a 302 to the real site (transparent to victim)
  - All branding fields (org name, colour, logo URL) are operator-configurable
- **Output:** `payload/phishing/<template>/` (HTML + capture backend stub)

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
