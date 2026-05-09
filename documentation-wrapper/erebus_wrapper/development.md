+++
title = "Development"
chapter = false
weight = 1
pre = "<b>1. </b>"
+++

## Project overview

Erebus is a Mythic C2 wrapper payload type that takes raw shellcode and produces a chained initial-access artefact: loader → obfuscation → signing → trigger/maldoc → container. Everything runs inside the Mythic Docker container; Windows-only steps that can't be run on Linux (VBA COM re-injection, XLL compilation) are deferred to a Windows host via the bundled `erebus_helper.py` companion.

### Key capabilities

- **Multiple loaders** - Shellcode Loader (C++, 8 injection methods), ClickOnce (.NET 7, 6 injection methods), and DLL Hijacking proxy generation.
- **Obfuscation pipeline** - compression / encryption / encoding chain via Shellcrypt, with RC4, XOR, AES-ECB, and AES-CBC all supported by the C++ loader via BCrypt.
- **Custom shellcode** - upload raw bytes from any external C2 (Cobalt Strike, Havoc, Sliver, msfvenom) to replace Mythic's payload. PE/DLL/.NET assemblies can be converted to shellcode via the Donut plugin.
- **Triggers** - LNK, BAT, MSI, MSC, ClickOnce, HTML Smuggling, ClickFix, HTA, URL shortcut, JScript/WSF, CHM, and SVG Smuggling.
- **Containers** - ISO, VHD, 7z, Zip, MSI, Electron fake-installer, and AppInstaller/MSIX. Any inner container can be wrapped in an outer ISO/VHD/ZIP/7z transport via `3.0T Outer Transport`.
- **MalDocs** - Linux-native Excel document generation (XLSM/XLSX/XLAM) with a built-in MS-OVBA-compliant `vbaProject.bin` compiler, four VBA loader techniques, runtime payload discovery, XLL add-in generation, and an optional Windows-side COM re-injection path. Word (DOTM remote template injection) and PowerPoint (PPTM/PPAM) formats via the OfficeDocs plugin.
- **Code signing** - self-signed, URL-spoofed, or operator-supplied PFX/P12 certificates via `osslsigncode`.
- **Loader guardrails** - compile-time anti-analysis checks (debugger, hardware breakpoints, timing, sandbox env, host/user/IP whitelists) baked into both loader code paths.
- **Runtime guardrails** - the Electron container ships a renderer-side interaction gate (dwell time + real mouse movement) and a main-process environment gate (debugger / sandbox env / username / hostname / screen / CPU / RAM / idle / pre-spawn delay).
- **Infra tooling** - C2 redirector config generator (Apache/Nginx/Caddy) and phishing page generator (O365/SharePoint/DocuSign/ADFS/Okta).

## Build pipeline

```
            ┌─────────────────────┐
            │   Start Build       │
            └──────────┬──────────┘
                       │
            ┌──────────▼──────────┐
            │  Input Shellcode    │
            │   from Mythic       │
            │  (or custom upload) │
            └──────────┬──────────┘
                       │
         ┌─────────────▼──────────────┐
         │  Main Payload Type?        │
         │  Loader / Hijack           │
         └──┬──────────────────────┬──┘
    ┌───────┘                      └────────┐
    │                                       │
┌───▼──────────────────┐   ┌──────────────▼───────────┐
│  Loader Type?        │   │  DLL Hijacking Config    │
│  Shellcode / Click   │   │  - Upload target DLL     │
│  Once                │   │  - Generate proxy.def    │
└──┬──────────────┬────┘   └──────────────┬───────────┘
   │              │                       │
┌──▼────┐  ┌──────▼─────┐                 │
│Shcode │  │ClickOnce   │                 │
│Loader │  │Config      │                 │
│Config │  │- Method    │                 │
│- Inj  │  │- Target    │                 │
│- Tgt  │  │- AppDomain │                 │
└──┬────┘  └──────┬─────┘                 │
   │              │                       │
   └──────────────┼───────────────────────┘
                  │
 ┌────────────────▼─────────────────┐
 │  Shellcode Obfuscation           │
 │  (Shellcrypt)                    │
 │  ┌─────────────────────────────┐ │
 │  │ Compression: LZNT1/RLE/NONE │ │
 │  │ Encryption: RC4/XOR/AES     │ │
 │  │ Encoding: BASE64/ALPHA32/…  │ │
 │  └─────────────────────────────┘ │
 └────────────────┬─────────────────┘
                  │
       ┌──────────▼───────────┐
       │  Compile Loader      │
       │  (C++ / .NET)        │
       └──────────┬───────────┘
                  │
      ┌───────────▼───────────┐
      │ Sign Payload?         │
      │ Self/Spoof/Provide    │
      └───────────┬───────────┘
                  │
      ┌───────────▼──────────┐
      │  Create MalDoc?      │
      │  XLSM/XLAM/XLL       │
      └───────────┬──────────┘
                  │
      ┌───────────▼──────────┐
      │ Add Trigger?         │
      │ LNK/BAT/MSI/MSC/     │
      │ HTML/ClickFix/       │
      │ ClickOnce            │
      └───────────┬──────────┘
                  │
     ┌────────────▼────────────┐
     │ Package Container?          │
     │ ISO/VHD/7z/Zip/MSI/Electron│
     │ AppInstaller               │
     │ + optional Outer Transport │
     └───────────┬─────────────┘
                 │
      ┌──────────▼─────────┐
      │ Final Payload Out  │
      └──────────┬─────────┘
                 │
          ┌──────▼────────┐
          │ Build         │
          │ Complete      │
          └───────────────┘
```

### Pipeline stages

1. **Input & header check** - Mythic passes raw shellcode (or the operator supplies custom shellcode via `0.0a Enable Custom Shellcode`). The builder rejects PE files via an MZ-header check and fails the build cleanly.
2. **Shellcode obfuscation** - Shellcrypt applies compression → encryption → encoding → output formatting in sequence; the key and IV are rendered into the loader config template.
3. **Loader configuration** - Jinja2 templates in [agent_code/templates/](Payload_Type/erebus_wrapper/erebus_wrapper/agent_code/templates/) (`config.hpp`, `InjectionConfig.cs`, `guardrail.hpp`, `proxy.def`) are rendered with user parameters + obfuscation metadata.
4. **Loader compilation** - the Shellcode Loader is built via MinGW-w64 from [Erebus.Loaders/Erebus.Loader/](Payload_Type/erebus_wrapper/erebus_wrapper/agent_code/Erebus.Loaders/Erebus.Loader/); ClickOnce uses `dotnet publish` from [Erebus.Loaders/Erebus.ClickOnce/](Payload_Type/erebus_wrapper/erebus_wrapper/agent_code/Erebus.Loaders/Erebus.ClickOnce/).
5. **Code signing** - if `6.0 Codesign Loader = True`, the compiled artefact is signed via `osslsigncode` with a self-signed, URL-spoofed, or operator-provided certificate.
6. **MalDoc generation** (optional) - when `0.8 Output Extension Source = MalDoc`, the builder produces an XLSM/XLSX/XLAM document with VBA or an XLL add-in source tree.
7. **Trigger generation** (optional) - when `0.8 Output Extension Source = Trigger`, a delivery trigger (LNK/BAT/MSI/MSC/HTML/ClickFix/ClickOnce) is created that executes the compiled loader.
8. **Containerisation** - the `payload/` directory (loader + trigger + decoy) is packaged into the final delivery format: ISO, 7z, Zip, MSI, or Electron portable exe.
9. **Delivery** - the final container + `IOCs.txt` + optional `build_*.bat` runbooks for deferred Windows-side steps are returned to Mythic.

Each stage reports its progress to Mythic via the Build Step Reference section below. For per-stage tradecraft considerations and hardening suggestions, see [OPSEC]({{% relref "opsec.md" %}}).

## Build parameter reference

Every BuildParameter defined in [builder.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/builder.py) is listed once, in order.

### 0.0 – 0.0b · Main Payload Type & Custom Shellcode

- **0.0 Main Payload Type** - `Loader` (Shellcode Loader or ClickOnce) or `Hijack` (DLL proxy hijacking). Determines which downstream parameters are visible.
- **0.0a Enable Custom Shellcode** - when `True`, the operator uploads a raw shellcode blob via `0.0b` that replaces the Mythic-generated payload entirely. Use this to wrap payloads from Cobalt Strike, Havoc, Sliver, or msfvenom.
- **0.0b Custom Shellcode File** - raw binary shellcode upload. Rejected if it has a PE `MZ` header (the MZ check catches accidentally uploading a compiled exe).

### 0.1 – 0.2a · Loader selection

- **0.1 Loader Type** - `Shellcode Loader` or `ClickOnce`. Only visible when `Main Payload Type = Loader`.
- **0.2 Loader Format** - output format for the Shellcode Loader: `exe`, `dll`, or `xll`. Each maps to a different compile target in the loader Makefile.
- **0.2a Loader Architecture** - `x64` or `x86`.

### 0.3 – 0.3a · Loader build configuration

- **0.3 Loader Build Configuration** - `Debug` or `Release` for the Shellcode Loader (also supports `test` for per-injection-type test builds).
- **0.3 ClickOnce Build Configuration** - `Debug` or `Release` for the ClickOnce loader.
- **0.3a ClickOnce Architecture** - `x64` or `x86` target for the .NET publish.

### 0.4 – 0.7 · Injection configuration

- **0.4 Shellcode Loader - Injection Type** - the C++ loader's injection technique:
  - `1` - `NtMapViewOfSection` (section-mapping injection, remote)
  - `2` - `CreateFiber` (fiber-based, self)
  - `3` - `EarlyCascade` (remote APC, pre-main-thread — via `NtQueueApcThread`)
  - `4` - `PoolParty` (worker factory thread pool, remote)
  - `5` - `NtQueueApcThread` (APC injection into existing thread, remote)
  - `6` - `ModuleStomp` (self — map a legitimate DLL, overwrite `.text`; VAD shows file-backed memory)
  - `7` - `KernelCallbackTable` (self — overwrite `PEB.KernelCallbackTable` entry, trigger via `SendMessage(WM_COPYDATA)`; no new thread)
  - `8` - `TxfHollow` (remote — transacted NTFS ghost section via `NtCreateTransaction`; rolls back NTFS transaction after mapping, leaving a phantom VAD path)
- **0.5 Shellcode Loader - Target Process** - target process for remote injection methods (ignored for `CreateFiber`).
- **0.6 ClickOnce - Injection Method** - the .NET loader's injection technique: `createfiber`, `earlycascade`, `poolparty`, `classic` (CreateRemoteThread), `enumdesktops` (self-callback), or `appdomain`.
- **0.7 ClickOnce - Target Process** - target process for ClickOnce remote injection methods.

### 0.5a – 0.5l · Shellcode Loader guardrails

Compile-time anti-analysis checks baked into the C++ loader. All are hidden unless `0.5a = True`.

- **0.5a Enable Guardrails** - master switch.
- **0.5b Check IsDebuggerPresent** - PEB-based debugger check.
- **0.5c Check Remote Debugger** - `CheckRemoteDebuggerPresent` equivalent.
- **0.5d Check Debugger Processes** - scans running processes for known debuggers (x64dbg, windbg, ollydbg, ida, …).
- **0.5e Check Hardware Breakpoints** - `Dr0`–`Dr7` register scan.
- **0.5f Check Timing Anomalies** - `RDTSC` / `GetTickCount` delta check for single-stepping.
- **0.5f1 Check Sandbox Environment** - VM artefact scan (MAC prefixes, loaded drivers, etc.).
- **0.5g Hostname Whitelist** - comma-separated list of allowed hostnames.
- **0.5h Block Analysis Hostnames** - comma-separated list of blocked hostnames.
- **0.5i Block Analysis Usernames** - comma-separated list of blocked usernames.
- **0.5j IP Whitelist** - comma-separated list of allowed local IPs.
- **0.5k IP Blacklist** - comma-separated list of blocked local IPs.
- **0.5l Domain Whitelist** - comma-separated list of allowed AD domains.

The DLL-hijack path has an equivalent set under `1.1` – `1.1k` (see below).

### 0.5m – 0.5o · Evasion backends

Shared between the Shellcode Loader and DLL-hijack paths (both render into `config.hpp`). ClickOnce path is unaffected.

- **0.5m Syscall Backend** - `TartarusGate` (built-in indirect-syscall shim page, default) or `SysWhispers3` (generated `Sw3Nt*` stubs). Hidden when `0.1 Loader Type = ClickOnce`.
- **0.5n Callstack Spoofing** - enable `SpoofCall()` dispatch for Nt* calls. `InitCallstackSpoof()` runs in `RunEvasionPatches()` and locates an `add rsp, 0x68; ret` gadget inside the configured module list (see `0.5o`). Call sites fill `SpoofContext` and jump through the gadget, leaving a fake return frame pointing at the host module. Hidden for ClickOnce and x86.
- **0.5o Callstack Spoof Modules** - comma-separated module names scanned, in order, for the gadget. First match wins. PEB-walk only - modules must already be mapped in the host process. Default: `ntdll.dll,kernel32.dll,kernelbase.dll`. Hidden unless `0.5n = True`. Displacement is fixed at `0x68` to match the `sub rsp, 112` frame in `callstack_spoof_gas.S`; changing it requires matching ASM edits. Operators can swap in modules that blend with the target host's benign telemetry (e.g. `user32.dll` in GUI procs, `winhttp.dll` in network tools) so the first spoofed frame above the Nt* call looks unremarkable.

### 0.8 · Output Extension Source

- **0.8 Output Extension Source** - `Trigger` or `MalDoc`. Determines whether the `0.9*` block renders as trigger parameters or MalDoc parameters.

### 0.9 – 0.9c · Trigger configuration

Only visible when `0.8 = Trigger`.

- **0.9 Trigger Type** - `LNK`, `BAT`, `MSI`, `MSC`, `HTML`, `ClickFix`, `ClickOnce`, `HTA`, `URL`, `JScript`, `CHM`, or `SVG`.
- **0.9a Trigger Binary** - binary invoked by the trigger (hidden for MSI, MSC, HTML, ClickFix, ClickOnce, SVG, URL).
- **0.9b Trigger Command** - command-line arguments passed to the trigger binary (also used as the target URL for `URL` type).
- **0.9c ClickFix Command** - PowerShell or cmd command copied to the victim's clipboard when they click the fake CAPTCHA "verify" button. Only visible when `0.9 = ClickFix`.

### 0.9 – 0.9p · MalDoc configuration

Only visible when `0.8 = MalDoc`. Note that `0.9` is multiplexed: the same parameter name appears in both trigger and MalDoc modes with different semantics.

- **0.9 Create MalDoc** - `None`, `Create/Backdoor Excel`, or `VBA Module Only` (just export the `.bas`).
- **0.9a MalDoc Type** - `Create New` or `Backdoor Existing`.
- **0.9b Excel Source File** - upload an existing `.xlsm` / `.xlam` / `.xls` to backdoor.
- **0.9c VBA Execution Trigger** - `AutoOpen`, `OnClose`, or `OnSave`.
- **0.9d Excel Document Name** - display name shown in the window title and document properties.
- **0.9e Obfuscate VBA** - toggle obfuscation pass on the generated VBA source.
- **0.9f MalDoc Injection Type** - `Command Execution` (WinAPI shell call) or `Shellcode Injection` (direct VBA shellcode loader).
- **0.9f1 MalDoc Trigger Binary** - binary invoked in Command Execution mode (parallel to `0.9a`).
- **0.9f2 MalDoc Trigger Command** - arguments passed to `0.9f1` (parallel to `0.9b`).
- **0.9g VBA Loader Technique** - `VirtualAlloc + CreateThread`, `EnumSystemLocalesA Callback`, `QueueUserAPC Injection`, or `Process Hollowing`. Only visible when `0.9f = Shellcode Injection`.
- **0.9h XLL Payload Type** - toggles XLL add-in generation. When set, the builder emits an XLL C/C++ source tree + `build_xll.bat` runbook for deferred Windows-side compilation via `erebus_helper.py xll`.
- **0.9i XLL Injection Method** - injection technique inside the XLL (`CreateThread` in-process or `ProcessInject` remote).
- **0.9j XLL Target Process** - target for remote XLL injection.
- **0.9k XLL Compiler** - `MSVC` or `MinGW`.
- **0.9l XLL Guardrail Includes** / **0.9m XLL Guardrail Code** / **0.9n XLL Guardrail Extra Libs** - custom guardrail injection into the XLL source template.
- **0.9o XLL Decoy XLSX** - optional decoy XLSX file shipped alongside the XLL.
- **0.9p MalDoc Output Format** - `XLSM`, `XLSX`, or `XLAM`.

### 0.13 · Decoy file

- **0.13 Decoy File Inclusion** - toggle to include a decoy document in the final payload.
- **0.13 Decoy File** - upload a PDF / DOCX / XLSX / etc. When omitted, a generic example decoy is used.

### 1.0 – 1.1k · DLL Hijacking

Only visible when `0.0 Main Payload Type = Hijack`.

- **1.0 DLL Hijacking** - upload the target DLL that the compiled loader will proxy.
- **1.0a Hijack Loader Architecture** - `x64` or `x86`.
- **1.0b Hijack Build Configuration** - `Debug` or `Release`.
- **1.1 Use Built-in Guardrails** - master switch for the hijack-path guardrails.
- **1.1a – 1.1k** - same set as `0.5a` – `0.5l` but rendered into the hijack loader config (debugger / remote debugger / debugger processes / hardware breakpoints / timing / host, user, IP, domain whitelists + blocklists).

### 2.0 – 2.3 · Shellcrypt options

- **2.0 Compression Type** - `NONE`, `LZNT1`, or `RLE`.
- **2.1 Encryption Type** - `NONE`, `XOR`, `RC4`, `AES-ECB`, or `AES-CBC`. All four non-null options are supported by the Shellcode Loader via BCrypt.
- **2.2 Encryption Key** - operator-supplied key, or `NONE` to auto-generate. AES keys must match their required length (16/24/32 bytes).
- **2.3 Encoding Type** - `NONE`, `BASE64`, `ASCII85`, `ALPHA32`, or `WORDS256`.

See [OPSEC]({{% relref "opsec.md" %}}) for the tradecraft considerations on each obfuscation stage.

### 3.0 – 3.2 · Container selection

- **3.0 Container Type** - `ISO`, `VHD`, `7z`, `Zip`, `MSI`, `Electron`, or `AppInstaller`. See [Plugins → Container plugins]({{% relref "plugins.md" %}}) for the full per-container description.
- **3.0T Outer Transport** - `None` (default), `ISO`, `VHD`, `ZIP`, or `7z`. When set to anything other than `None`, the inner container produced by `3.0` is wrapped inside this outer transport layer. Useful for MOTW bypass (Electron inside ISO/VHD) or policy bypass (Electron inside VHD when ISO is blocked). Volume label for ISO/VHD outer transport is taken from `4.0 ISO Volume ID`.
- **3.1 Compression Level** - `0` – `9`; only visible for `7z` and `Zip`.
- **3.2 Archive Password** - optional password for `7z` and `Zip` archives.

### 3.AI0 – 3.AI2 · AppInstaller / MSIX container

Only visible when `3.0 Container Type = AppInstaller`.

- **3.AI0 MSIX Hosting URL** - HTTPS URL where the MSIX package will be served (e.g. `https://cdn.example.com/update/app.msix`). Embedded verbatim in the `.appinstaller` manifest. The operator must build the MSIX via `build_msix.bat` on Windows and upload it to this URL before delivering the manifest to the victim.
- **3.AI1 MSIX Package Name** - MSIX identity package name (no spaces). Shown in **Settings → Apps**. Default `"Microsoft.WindowsUpdate"`.
- **3.AI2 MSIX Display Name** - Friendly display name shown in the App Installer UI and **Settings → Apps**. Default `"Windows Update Assistant"`.

### 3.E0 – 3.E8 · Electron container

All hidden unless `3.0 Container Type = Electron`. These map to PE resource fields baked into the portable exe via electron-builder's `rcedit` pass, plus the wizard's runtime config.

- **3.E0 Electron Product Name** - wizard window title + PE `ProductName`. Default `"Acme Installer"`.
- **3.E1 Electron Publisher** - `package.json.author` → PE `CompanyName`. Default `"Acme Corporation"`.
- **3.E2 Electron Version** - `package.json.version` → PE `ProductVersion` + `FileVersion`. Default `"1.0.0"`.
- **3.E3 Electron Architecture** - `x64` (default) or `ia32`.
- **3.E4 Electron Entry Format** - spawn mechanism: `exe` (direct `CreateProcess`), `dll` (`rundll32.exe <dll>,<entry>`), or `xll` (`excel.exe /e <xll>`).
- **3.E5 Electron DLL Entry Point** - rundll32 export name. Only visible when `3.E4 = dll`. Default `"DllMain"`.
- **3.E6 Electron Build Mode** - `In-Container (Wine)` (npm + electron-builder under wine, default) or `Deferred (Erebus.Helper)` (stage source + `build_electron.bat` for a Windows host).
- **3.E6a Electron Custom Icon** - optional PNG/JPEG/GIF/BMP/WEBP/TIFF/SVG upload. SVG is rasterised to 512×512 via `cairosvg`; Pillow then produces a multi-size ICO (16/24/32/48/64/128/256) embedded in the exe's PE resources.
- **3.E7 Electron File Description** - `package.json.description` → PE `FileDescription`. Default `"Setup"`.
- **3.E8 Electron Copyright** - `electron-builder.yml.copyright` → PE `LegalCopyright`. Default empty.

### 3.P0 – 3.P3 · Electron persistence

All hidden unless `3.0 Container Type = Electron` AND `3.P0 = True`. When enabled, the loader is copied to a permanent location and a persistence mechanism is registered **before** the loader is spawned for the first time.

- **3.P0 Enable Persistence** - master switch. Default `False`.
- **3.P1 Persistence Method** - one of:
  - `Registry Run Key` - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (executes on every login)
  - `Registry RunOnce` - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (executes on next login only, then removes itself)
  - `Startup Folder` - copies the exe to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`; DLL/XLL formats write a `.bat` launcher wrapper instead
  - `Scheduled Task` - `schtasks /sc onlogon /rl limited` (runs at login without UAC prompt)
- **3.P2 Persistence Name** - display name / registry value name / task name. Defaults to `3.E0 Electron Product Name` if left empty.
- **3.P3 Persistence Install Dir** - `%APPDATA%` (default) or `%LOCALAPPDATA%`. Controls where the loader copy is written before the persistence pointer is registered.

### 3.E9 – 3.E9p · Electron runtime guardrails

All hidden unless `3.0 Container Type = Electron` AND `3.E9 = True`. The guardrails defer the `%TEMP%\inst-<uuid>` loader copy and the spawn until **both** a renderer-side interaction gate and a main-process environment gate pass. Failures are silent - the wizard still shows fake progress → Finish, but the loader is never staged.

- **3.E9 Enable Electron Guardrails** - master switch. Default `True`.
- **3.E9a Dwell Time (ms)** - minimum wizard-visible time before the Install button is enabled. Default `2500`.
- **3.E9b Require Mouse Movement** - require a real non-zero-delta `mousemove` event before enabling Install. Default `True`.
- **3.E9c Check Debugger** - rejects if a Node inspector / debugger is attached. Default `True`.
- **3.E9d Check Sandbox Env Vars** - rejects on `SBIEHOME`, `SANDBOXIE_CURRENT_DIR`, `CUCKOO_AGENT`, `JOEBOX_AGENT`, `ANALYST_USERNAME`. Default `True`.
- **3.E9e Check Default Bad Usernames** - rejects common sandbox usernames (`sandbox`, `malware`, `analyst`, `WDAGUtilityAccount`, …). Default `True`.
- **3.E9f Check Default Bad Hostnames** - rejects hostnames containing `sandbox`, `cuckoo`, `vbox`, `qemu`, … Default `True`.
- **3.E9g Hostname Whitelist** / **3.E9h Hostname Blocklist** - operator-supplied comma-separated lists.
- **3.E9i Username Whitelist** / **3.E9j Username Blocklist** - operator-supplied comma-separated lists.
- **3.E9k Min Screen Width** / **3.E9l Min Screen Height** - defeats 800×600 / 1024×768 sandbox VMs. Defaults `1280`/`720`.
- **3.E9m Min CPU Count** - rejects hosts with fewer than N logical CPUs. Default `2`.
- **3.E9n Min Memory (MB)** - rejects hosts with less than N MB RAM. Default `2048`.
- **3.E9o Max Idle Seconds** - rejects if system idle time > N seconds. Default `0` (off).
- **3.E9p Pre-Spawn Delay (ms)** - sleep N ms *after* all other checks pass but *before* the file copy. Use 5000–15000 to time out short-lived sandbox detonation windows. Default `0` (off).

### 4.0 – 4.2 · ISO container

Only visible when `3.0 Container Type = ISO`.

- **4.0 ISO Volume ID** - volume label shown in Explorer. Default `"EREBUS"`.
- **4.1 ISO enable Autorun** - generate `autorun.inf` (note: AutoRun is ignored on hard-disk-class volumes since Windows 7; Explorer still displays the custom icon/label).
- **4.2 ISO Backdoor File** - upload an existing ISO to inject the payload into rather than creating a fresh one.

### 5.0 – 5.9 · MSI container

Only visible when `3.0 Container Type = MSI`.

- **5.0 MSI Product Name** - application name shown in the MSI installer UI. Default `"System Updater"`.
- **5.1 MSI Manufacturer** - company name. Default `"Microsoft Corporation"`.
- **5.2 MSI Install Scope** - `User` (AppData install, no admin) or `Machine` (Program Files, may require admin).
- **5.3 Enable MSI Backdoor** - toggle backdoor-an-existing-MSI mode.
- **5.4 MSI Backdoor File** - upload the target MSI.
- **5.5 MSI Attack Type** - `execute` (CustomAction direct command), `run-exe` (Binary table extraction), `load-dll` (DllEntry), `dotnet` (.NET assembly), or `script` (VBScript/JScript).
- **5.6 MSI Entry Point** - required for `load-dll`, `dotnet`, and `script` attack types (function name to invoke).
- **5.7 MSI Command Arguments** - command-line arguments for `execute` / `run-exe` attack types.
- **5.8 MSI Execution Condition** - MSI condition expression (default `"NOT REMOVE"` = install-only).
- **5.9 MSI Custom Action Name** - identifier for the custom action (empty = random).

### 6.0 – 6.6 · Code signing

Only visible when `6.0 Codesign Loader = True`.

- **6.0 Codesign Loader** - master switch.
- **6.1 Codesign Type** - `SelfSign`, `Spoof URL`, or `Provide Certificate`.
- **6.2 Codesign CN** - Common Name for self-signed certs.
- **6.3 Codesign Orgname** - Organization Name for self-signed certs.
- **6.4 Codesign Spoof URL** - target URL to clone SSL cert details from. Only visible when `6.1 = Spoof URL`.
- **6.5 Codesign Cert** - upload a PFX/P12 file. Only visible when `6.1 = Provide Certificate`.
- **6.6 Codesign Cert Password** - password for the uploaded cert. Leave empty if the cert has no password.

See [OPSEC → Code Signing]({{% relref "opsec.md" %}}) for what each signing mode actually buys the operator.

## Build step reference

Each build stage is reported to Mythic via `SendMythicRPCPayloadUpdatebuildStep`. Step names use MITRE ATT&CK technique IDs where applicable.

| # | StepName | Triggers | Description |
|---|---|---|---|
| 1 | `[T1005] - Gathering Files` | Always | Copy `agent_code/` into the temp build dir |
| 2 | `[T1027] - Header Check` | Always | Reject PE files via MZ-header check |
| 3 | `[T1027] - Shellcode Obfuscation` | Always | Run Shellcrypt (compression → encryption → encoding) |
| 4 | `[T1518] - Gathering DLL Exports for Hijacking` | `Main Payload Type = Hijack` | Extract DLL exports via `pefile` for proxy generation |
| 5 | `[T1027.011] - Compiling DLL Payload` | `Main Payload Type = Hijack` or Shellcode Loader w/ `0.2 = dll` | Compile hijacking DLL or loader DLL via MinGW |
| 6 | `[T1559.002] - Compiling XLL Add-In` | `0.9h XLL Payload Type` set | Emit XLL C/C++ source + `build_xll.bat` for deferred Windows build |
| 7 | `[T1027] - Compiling Shellcode Loader` | Shellcode Loader w/ `0.2 = exe` | Compile C++ loader exe |
| 8 | `[T1027] - Compiling ClickOnce Loader` | ClickOnce | `dotnet publish` the ClickOnce project |
| 9 | `[T1027] - Compiling Test Payloads` | `0.3 Loader Build Configuration = test` | Build one loader per injection method for testing |
| 10 | `[T1553.006] - Sign Shellcode Loader` | `6.0 Codesign Loader = True` | AuthentiCode sign the produced binary |
| 11 | `[T1566.001] - Creating MalDoc` | `0.8 = MalDoc` | Generate XLSM/XLSX/XLAM document + VBA payload |
| 12 | `[T1218.007] - Staging MSI` | `5.3 Enable MSI Backdoor = True` | Backdoor an uploaded MSI with the compiled loader |
| 13 | `[T1137.006] - Adding Trigger` | `0.8 = Trigger` | Generate the configured trigger artefact |
| 14 | `[T1036.008] - Creating Decoy` | `0.13 Decoy File Inclusion = True` | Stage the decoy file into `payload/` |
| 15 | `[T1027] - Containerising` | Always (non-Electron/AppInstaller containers) | Package `payload/` into ISO / VHD / 7z / Zip / MSI; apply outer transport if `3.0T ≠ None` |
| 16 | `[T1608.001] - Wrapping Payload in Electron Installer` | `3.0 Container Type = Electron` | Build the Electron portable exe via wine (or stage source for deferred build) |
| 17 | `[T1608.001] - Building AppInstaller Manifest` | `3.0 Container Type = AppInstaller` | Generate `.appinstaller` XML manifest + MSIX source tree; emit `build_msix.bat` |

Each step reports `StepStdout`, `StepSuccess`, and optional diagnostic output to Mythic. Build failures terminate the pipeline immediately and the operator sees the failed step in the Mythic UI.

## Output conventions

After a successful build the `payload/` directory contains (depending on selected options):

```
payload/
├── erebus.{exe,dll,xll}          # compiled loader
├── <trigger>.{lnk,bat,msi,msc,html,application}  # if trigger selected
├── <maldoc>.{xlsm,xlsx,xlam}    # if MalDoc selected
├── <decoy>.{pdf,docx,xlsx}      # if decoy included
├── electron_src/                # if Electron + deferred build mode
├── build_*.bat                  # runbooks for Windows-side deferred steps
├── erebus_helper.py             # bundled Windows-side build helper
└── IOCs.txt                     # hashes + metadata for every artefact
```

The final containerised artefact (`.iso`, `.7z`, `.zip`, `.msi`, or the portable Electron `.exe`) is returned to Mythic as the payload file. Everything inside `payload/` is included in the container unless a trigger's visible-extension filter applies (ISO, 7z, Zip hide non-trigger files via file attributes so the victim sees only the clickable artefact).

### Deferred build runbooks

Windows-only build steps that can't run inside the Linux Docker container emit a `.bat` runbook pointing to `erebus_helper.py`:

| Runbook | Emitted when | Runs |
|---|---|---|
| `build_xll.bat` | XLL payload type set | `erebus_helper.py xll` - compiles the staged XLL source tree with MSVC or MinGW |
| `build_maldoc.bat` | MalDoc + optional Windows COM re-injection | `erebus_helper.py xlsm|xlam|xlsx` - re-injects VBA via Excel COM for higher-fidelity output |
| `build_electron.bat` | `3.E6 Electron Build Mode = Deferred (Erebus.Helper)` | `erebus_helper.py electron` - runs `npm install` + `electron-builder --win` on the Windows host |
| `build_chm.bat` | `0.9 Trigger Type = CHM` | Compiles the CHM project tree with `hhc.exe` (HTML Help Workshop) |
| `build_msix.bat` | `3.0 Container Type = AppInstaller` | Signs and packages the MSIX source tree with `makeappx.exe` + `signtool.exe` (Windows SDK required) |

`erebus_helper.py` is auto-exported as a single-file bundle of the `Erebus.Helper/` suite and shipped alongside the runbooks in `payload/`. Operators should strip these artefacts from the final archive before delivery if they don't intend to use them - see [OPSEC → Erebus.Helper Deferred Builds]({{% relref "opsec.md" %}}).

## Templates and agent code structure

### Jinja templates

`agent_code/templates/` contains the Jinja2 templates rendered at build time with user parameters and shellcrypt output:

| Template | Consumed by | Purpose |
|---|---|---|
| `config.hpp` | Shellcode Loader (C++) | Compression/encoding/encryption type IDs, injection type, target process, guardrail flags, shellcrypt key + IV |
| `InjectionConfig.cs` | ClickOnce (.NET) | Same as `config.hpp` but in C# form, plus ClickOnce-specific injection method |
| `guardrail.hpp` | Shellcode Loader (C++) | Compile-time guardrails with host/user/IP whitelists |
| `proxy.def` | DLL Hijack | DLL export forwarding definition |
| `electron_config.js.j2` | Electron container | Wizard runtime config: product metadata, entry format, GUARDRAILS block, PERSISTENCE block |
| `template.xlsm` / `template.xlsx` | MalDocs | Base Excel workbook documents |

### Agent code layout

```
agent_code/
├── templates/              # Jinja2 templates (above)
├── shellcrypt/             # Shellcode obfuscation engine (submodule)
├── vba_compiler/           # Linux-native MS-OVBA vbaProject.bin compiler
├── Erebus.Loaders/
│   ├── Erebus.Loader/      # C++ Shellcode Loader source (submodule)
│   ├── Erebus.ClickOnce/   # .NET 7 ClickOnce loader source
│   └── Erebus.Electron/    # Electron fake-installer project
├── Erebus.Helper/          # Windows-side build helper (submodule)
├── hijack/                 # DLL hijack proxy C++ source
├── shellcode/              # Per-build shellcode staging
├── decoys/                 # Default decoy files
└── container/              # Container-specific static assets
```

## Extending the builder

### Adding a new BuildParameter

Append a `BuildParameter` entry to the list in [builder.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/builder.py), following the `section.suffix Description` naming convention:

```python
BuildParameter(
    name = "0.9 Example Parameter",
    parameter_type = BuildParameterType.String,
    description = "One-line description shown in the Mythic UI",
    default_value = "default",
    required = True,
    hide_conditions = [
        HideCondition(name="0.0 Main Payload Type",
                      operand=HideConditionOperand.EQ,
                      value="Hijack"),
    ]
)
```

Read it at build time with `self.get_parameter("0.9 Example Parameter")`. Use `HideCondition` to gate visibility on other parameter values so the UI doesn't show irrelevant options. Remember to update this documentation file and the matching plugin catalog entry in [Plugins]({{% relref "plugins.md" %}}).

### Adding a new container type

Containers are plugins. See [Plugin Development → Writing a plugin]({{% relref "plugin-development.md" %}}) for the full walkthrough. Short version:

1. Create `plugin_container_<name>.py` in [erebus/modules/](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/) following the pattern in [plugin_container_iso.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_iso.py).
2. Implement `build_<name>(build_path, ...)` → `pathlib.Path`.
3. Add `"build_<name>"` to `_PLUGIN_FUNCTIONS` at the top of `builder.py`.
4. Add `"<Name>"` to the `3.0 Container Type` choices list.
5. Add a `case "<Name>":` branch to `containerise_payload`.

### Adding a new trigger type

Triggers are also plugins. Follow the same pattern as a container but register the function under `create_<name>_trigger` and wire it into the `match` statement in the trigger dispatch section of `builder.build()`. Update `0.9 Trigger Type` choices and `0.9a/0.9b` visibility conditions.

### Adding a new injection method

Injection methods are not plugins - they live inside the loader source code:

- **C++ (Shellcode Loader)** - add the implementation under [Erebus.Loader/](Payload_Type/erebus_wrapper/erebus_wrapper/agent_code/Erebus.Loaders/Erebus.Loader/), update the switch statement in `injection_factory.cpp`, and add the new ID to `0.4 Shellcode Loader - Injection Type`.
- **.NET (ClickOnce)** - add a new class under [Erebus.ClickOnce/Injections/](Payload_Type/erebus_wrapper/erebus_wrapper/agent_code/Erebus.Loaders/Erebus.ClickOnce/Injections/) implementing `InjectionMethod`, register it in `InjectionFactory.cs`, and add the method name to `0.6 ClickOnce - Injection Method`.

Both loaders ship as git submodules; changes to them are committed in the respective submodule repositories.

### Adding a new obfuscation method

Obfuscation methods live inside [agent_code/shellcrypt/](Payload_Type/erebus_wrapper/erebus_wrapper/agent_code/shellcrypt/) which is a git submodule. Add the encrypt/decrypt/compress/encode function to the relevant shellcrypt class, then expose it via the `COMPRESSION_METHODS` / `ENCRYPTION_METHODS` / `ENCODING_METHODS` dicts at the top of `builder.py`. The loader must also implement the reverse operation; see `config.hpp` template for the conditional compilation pattern used to select the decryption routine at compile time.
