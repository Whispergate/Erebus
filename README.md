<p align="center">
 <img src="agent_icons/ErebusBannerText.png" alt="Erebus Banner" style="width: 800px;"/>
</p>

# Erebus
Erebus is a modern initial access wrapper aimed at decreasing the development to deployment time, when preparing for intrusion operations. Erebus comes with multiple techniques out of the box to craft complex chains, and assist in bypassing the toughest security measures.

This project is meant to be an extension to your offensive capabilities, and is by no means a silver bullet against all environments. If you would like to add your own techniques or modify the existing ones then check out the project's documentation page for more info.

## How to Install

Within Mythic you can run the `mythic-cli` binary to install this in one of three ways:

* `sudo ./mythic-cli install github https://github.com/Whispergate/Erebus` to install the main branch
* `sudo ./mythic-cli install github https://github.com/Whispergate/Erebus branchname` to install a specific branch of that repo
* `sudo ./mythic-cli install folder /path/to/local/folder/cloned/from/github` to install from an already cloned down version of an agent repo

If Mythic is already running, start the container with:
```bash
sudo ./mythic-cli start erebus_wrapper
```

## Documentation

View the rendered documentation by clicking on **Docs -> Agent Documentation** in the upper right-hand corner of the Mythic interface.

## Features

### Loaders
- **Shellcode Loader** - Native C++ loader (exe/dll/xll) with 11 injection techniques, indirect syscalls, callstack spoofing, and compile-time guardrails
- **ClickOnce** - .NET 7 single-file publish with 7 injection methods
- **VM Loader** - RISC VM-based loader with per-build randomised opcodes, XOR key derivation, and encrypted instruction set. Supports 3 self-injection types
- **DLL Hijacking** - Proxy DLL generation with export forwarding from any target DLL for sideloading chains
- **Linux Loaders** - ELF executable and shared object (.so) for LD_PRELOAD delivery, with 4 injection techniques
- **macOS Loaders** - Mach-O executable and dylib with MAP_JIT and Mach thread injection

### Injection Techniques

| # | Technique | Type |
|---|-----------|------|
| 1 | NtMapViewOfSection | Remote |
| 2 | CreateFiber | Self |
| 3 | EarlyCascade | Remote |
| 4 | PoolParty (RemoteTpDirectInsertion) | Remote |
| 5 | NtQueueApcThread | Remote |
| 6 | ModuleStomp | Self |
| 7 | KernelCallbackTable | Self |
| 8 | TxfHollow | Remote |
| 9 | PoolPartyJobApc (RemoteTpJobDirectInsertion) | Remote |
| 10 | ProcessHollow | Remote |
| 11 | FunctionStomp | Self |

Linux supports `mmap_thread`, `memfd_exec`, `process_vm_writev`, and `ptrace` injection. macOS supports `mmap_pthread` (MAP_JIT) and `mach_thread`.

### Triggers

**Windows (23):** LNK, BAT, MSI, MSC, HTA, URL, JScript/WSF, CHM, HTML Smuggling, HTML Encrypted (PBKDF2 password-gated), HTML Geofenced (country-code filtering), SVG Smuggling, ClickFix (clipboard-lure CAPTCHA), SearchMS, UDL, QR, AppDomain, VSCode Extension (.vsix), OneNote, CMSTP, Regsvr32/Squiblydoo, XSL Transform, InstallUtil

**Linux (4):** Bash, XDG Desktop, HTML Smuggling, QR

**macOS (8):** .command, AppleScript, PKG Installer, App Bundle (unsigned), App Bundle (ad-hoc signed), DMG, HTML Smuggling, QR

### Containers
`ISO`, `VHD`, `7z`, `Zip`, `MSI`, `Electron` (fake NSIS installer with interaction-gated guardrails), `AppInstaller`/`MSIX`

Any inner container can be wrapped in an outer ISO, VHD, ZIP, or 7z transport for two-layer delivery chains.

### MalDocs
- Excel: XLSM, XLSX, XLAM, XLL Add-In DLL
- Word: DOCM, DOC, DOCX with remote template injection (DOTM fetch on open)
- PowerPoint: PPTM, PPAM Add-In
- 4 VBA loader techniques: `VirtualAlloc+CreateThread`, `EnumSystemLocalesA`, `QueueUserAPC`, `Process Hollowing`
- VBA compiled natively on Linux without Office installed
- HTTP shellcode staging: RC4-encrypted shellcode uploaded to Mythic file store at build time, fetched and decrypted by VBA at runtime. No shellcode bytes or plaintext URLs in the document

### Obfuscation Pipeline
Shellcrypt chain: compression (`LZNT1`/`RLE`) -> encryption (`RC4`/`XOR`/`AES-ECB`/`AES-CBC`) -> encoding (`BASE64`/`ASCII85`/`ALPHA32`/`WORDS256`) with per-build auto-generated or operator-supplied keys.

### Evasion Stack
- **Indirect Syscalls** - TartarusGate (default, x64), SysWhispers3 (x64), Heaven's Gate (x86 WoW64, 32-bit process issuing native 64-bit syscalls)
- **Callstack Spoofing** - Configurable gadget-host module list (defaults to ntdll/kernel32/kernelbase)
- **NTDLL Unhook** - 4 levels from disabled to selective Nt* function unhooking
- **AMSI Bypass** - 5 tiers (0-4) including a patchless hardware breakpoint + VEH variant that writes no bytes to amsi.dll
- **ETW Bypass** - 4 tiers (0-3) including EtwEventWrite, EtwEventWriteFull, and provider unregistration
- **Sleep Obfuscation** - 5 modes: None, WaitableTimer, Ekko-lite (XOR PE sections), Exhaustion (Fibonacci burn + API hammering + memory touch), Full Ekko (Ekko-lite + stack XOR + PE header wipe)
- **Compile-time Guardrails** - IsDebuggerPresent, remote debugger, debugger processes, hardware breakpoints, timing anomalies, sandbox environment checks, host/user/IP/domain allowlists
- **PE Sanitisation** - Strips MinGW fingerprints, rich header, PE timestamp, debug directory
- **Self-Hunt Rules** - Per-build YARA + Sigma rule generation for operator validation

### Code Signing
Self-signed, URL-spoofed (clone a legitimate website's cert details), or operator-provided PFX/P12 certificates applied via `osslsigncode`.

### Persistence
**Electron container:** Registry Run Key, RunOnce, Startup Folder, Scheduled Task

**Standalone plugins:** COM Hijacking (T1546.015), WMI Event Subscription (T1546.003), macOS LaunchAgent (T1543.001)

### Additional Capabilities
- **Shellcode Sources** - Mythic-wrapped C2 agent or any external C2 (Cobalt Strike, Havoc, Sliver, msfvenom) via custom shellcode upload
- **Donut Integration** - Convert PE/.NET assemblies to shellcode
- **MSI Backdooring** - Inject payload into existing MSI installers
- **Redirector Config Generation** - Apache .htaccess, Nginx, Caddyfile, Terraform stubs
- **Phishing Page Generation** - Credential capture page with redirect and GoPhish webhook support
- **Decoy Documents** - Custom decoy file inclusion for social engineering
- **IOC Tracking** - Automated hash collection and IOC report generation
- **Build All Configurations** - Matrix build of all trigger/container combinations
- **Plugin System** - Drop-in Python plugins for triggers, containers, loaders, and persistence. No core code changes needed

## Known Issues
- VBA Address of Entry Point injection is not functional as of v0.1.0
- DLL hijacking may skip mangled C++ export names during proxy generation
- CHM and OneNote triggers require Erebus.Helper (deferred build on Windows)

## Bug Fixes

### [v0.2.0]
- Switched to async build calls to prevent container appearing offline during payload compilation
- Fixed DLL proxy generation issues with ordinal-only exports
- Fixed DLL hijacking payload builder
- Fixed shellcrypt option bug
- Fixed VSCode extension trigger (switched to spawn process)
- Added patchless AMSI bypass (HW-BP + VEH)
- Added VSCode extension (.vsix) trigger plugin
- Added OneNote trigger plugin
- Added LOLBAS triggers (CMSTP, Regsvr32, XSL Transform, InstallUtil)
- Added injection types 9-11 (PoolPartyJobApc, ProcessHollow, FunctionStomp)
- Added standalone persistence plugins (COM Hijack, WMI Subscription, LaunchAgent)
- Added Full Ekko sleep obfuscation with stack XOR and PE header wipe
- Fixed docs container crashing on ambiguous page references

### [v0.1.0]
- Fixed VBA loader and added staged loader via Mythic Direct Files Download
- Added Electron fake-installer container with interaction-gated guardrails
- Added HTML smuggling, SVG smuggling, ClickFix triggers
- Added callstack spoofing (configurable gadget-host modules)
- Added SysWhispers3 and Heaven's Gate syscall implementations
- Added PE sanitisation and self-hunt rule generation
- Added DOCM, DOC, PPTM, PPAM, remote template injection maldocs
- Added compile-time execution guardrails
- Added Linux and macOS loader support
- Refactored codebase for plugin architecture

### [v0.0.2]
- Fixed issues with XLL source code saving
- Generated build_xll.bat for native Windows recompilation
- Improved error handling and output messages during build process
- Fixed MSI Backdoor injector
- Added MSC GrimReaper trigger
- Added support for larger shellcodes (Apollo, Athena, etc.)

### [v0.0.1]
- Minor issues with build steps
- Loader decompression bugs

## Contributions

This project would not be possible without the awesome support and tooling from these operators, thank you all!

- Mariusz Banach ([Mgeeky](https://github.com/mgeeky))
- Jordan Jay ([0xLegacyy](https://github.com/iilegacyyii/)):
  - [Shellcrypt](https://github.com/iilegacyyii/Shellcrypt)
- Cody Thomas ([its-a-feature](https://github.com/its-a-feature)):
  - [Mythic Red Team Framework](https://github.com/its-a-feature/Mythic)
  - [Apollo Agent](https://github.com/MythicAgents/Apollo)
  - [Service Wrapper](https://github.com/MythicAgents/service_wrapper)
  - Helping out with my silly questions
