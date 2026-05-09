+++
title = "Erebus"
chapter = true
weight = 100
+++

![Erebus Banner](/wrappers/erebus_wrapper/ErebusBannerText.png?width=700px)

Erebus is an initial access wrapper payload type for [Mythic C2](https://github.com/its-a-feature/Mythic). It takes raw shellcode (Mythic-generated *or* supplied from any external C2) and produces a ready-to-deliver artefact chained through the operator's choice of loader, obfuscation pipeline, code-signing flow, container format, and execution trigger.

## What's in the box

### Loaders
- **Shellcode Loader** - native C++ executable or DLL with eight injection techniques (`NtMapViewOfSection`, `CreateFiber`, `EarlyCascade`, `PoolParty`, `NtQueueApcThread`, `ModuleStomp`, `KernelCallbackTable`, `TxfHollow`), full BCrypt decryption support, and configurable compile-time guardrails.
- **ClickOnce** - .NET 7 single-file publish with six injection methods (`createfiber`, `earlycascade`, `poolparty`, `classic`, `enumdesktops`, `appdomain`).
- **DLL Hijacking** - proxy-DLL generation from any upload-target DLL for sideloading chains.

### Shellcode sources
- Mythic-wrapped C2 agent (default).
- Any external C2 output - Cobalt Strike, Havoc, Sliver, msfvenom - via `0.0a Enable Custom Shellcode` + `0.0b Custom Shellcode File`.

### Obfuscation pipeline
Shellcrypt chain of compression (`LZNT1`/`RLE`) → encryption (`RC4`/`XOR`/`AES-ECB`/`AES-CBC`) → encoding (`BASE64`/`ASCII85`/`ALPHA32`/`WORDS256`) with operator-supplied or auto-generated keys, rendered into `C`, `CSharp`, or `Raw` output formats.

### Containers
`ISO` · `VHD` · `7z` · `Zip` · `MSI` · **`Electron`** · **`AppInstaller`**/**`MSIX`** — the Electron container wraps the compiled loader inside a portable fake-installer `.exe` with a two-gate guardrail system (interaction token + environment checks) that defers the `%TEMP%` loader copy until after real user interaction and configurable anti-sandbox checks pass. Optional persistence (Registry Run Key/RunOnce, Startup Folder, Scheduled Task) via `3.P0`–`3.P3`. Any inner container can be wrapped in an outer ISO/VHD/ZIP/7z transport via `3.0T Outer Transport`.

### Triggers
`LNK` · `BAT` · `MSI` · `MSC` · `ClickOnce` · **`HTML Smuggling`** (XOR+base64 Blob reconstruction) · **`ClickFix`** (clipboard-lure CAPTCHA page) · **`HTA`** (`mshta.exe`) · **`URL`** (internet shortcut, SMB/WebDAV) · **`JScript`**/**`WSF`** (`wscript.exe`) · **`CHM`** (`hh.exe` ShortCut ActiveX, deferred build) · **`SVG Smuggling`** (browser-rendered SVG with JS blob).

### MalDocs
XLSM / XLSX / XLAM + XLL Add-In DLL support. VBA is compiled directly on Linux via a built-in MS-OVBA-compliant `vbaProject.bin` compiler; an optional Windows-side COM re-injection path via `erebus_helper.py` is available for higher-fidelity output. Four VBA loader techniques (`VirtualAlloc+CreateThread`, `EnumSystemLocalesA`, `QueueUserAPC`, `Process Hollowing`), runtime payload discovery, and configurable AutoOpen / OnClose / OnSave execution triggers. Word and PowerPoint documents (DOTM remote template injection, PPTM, PPAM add-in) via the OfficeDocs plugin.

### Code signing
Self-signed, URL-spoofed (clone a legitimate website's cert details), or operator-provided PFX/P12 certificates, applied via `osslsigncode` to any loader or container output.

### Evasion
Compile-time guardrails on both the C++ and C# loaders (`IsDebuggerPresent`, remote debugger, debugger processes, hardware breakpoints, timing anomalies, sandbox env, host/user/IP whitelists), runtime guardrails on the Electron fake-installer container, and decoy file support for social-engineering chains. Indirect syscalls via `TartarusGate` or `SysWhispers3`, ntdll unhook, AMSI/ETW runtime patching, and operator-configurable callstack spoofing (any gadget-host module list, defaults to `ntdll`/`kernel32`/`kernelbase`). VAD-evasion injection methods include `ModuleStomp` (file-backed VAD) and `KernelCallbackTable` (PEB KCT hijack, no new thread). `TxfHollow` maps a phantom section via a rolled-back NTFS transaction for a clean VAD path.

## Getting started

```bash
sudo ./mythic-cli install github https://github.com/Whispergate/Erebus.git
```

Then create an Erebus payload from the Mythic UI and tune parameters from the sections below.

## Documentation

- **[Development]({{% relref "development.md" %}})** - build pipeline, full BuildParameter reference, build-step reference, and how to extend the builder.
- **[Plugins]({{% relref "plugins.md" %}})** - catalog of the plugins shipped with Erebus, their parameters, and what each one produces.
- **[Plugin Development]({{% relref "plugin-development.md" %}})** - writing your own plugins against the `ErebusPlugin` base class.
- **[OPSEC]({{% relref "opsec.md" %}})** - per-component tradecraft considerations and hardening improvements for both operators and developers.

## Authors

- [@Lavender-exe](https://github.com/Lavender-exe) - Project Author
- [@Hunter](https://github.com/hunterino-sec) - Project Author

## Contributors

- [@iilegacyyii](https://github.com/iilegacyyii) - Project Support and [Shellcrypt](https://github.com/iilegacyyii/Shellcrypt) Author
- [@mgeeky](https://github.com/mgeeky) - Project Support and Inspiration
- [@its-a-feature](https://github.com/its-a-feature) - Project Support and [Mythic C2 Server](https://github.com/its-a-feature/Mythic) Author

{{% children %}}
