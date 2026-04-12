+++
title = "Erebus"
chapter = true
weight = 100
+++

## Summary
![Erebus Banner](/wrappers/erebus_wrapper/ErebusBannerText.png?width=700px)
Erebus is a modern initial access wrapper aimed at decreasing the development to deployment time, when preparing for intrusion operations. Erebus comes with multiple techniques out of the box to craft complex chains, and assist in bypassing the toughest security measures.

### Highlighted Wrapper Features
**Loader Types:**
  - Shellcode Loader (C++ with 5 injection methods)
  - ClickOnce (.NET with 5 injection methods)
  - DLL Hijacking (Proxy-based execution)

**Shellcode Source:**
  - Mythic-wrapped C2 agent (default)
  - Custom external shellcode upload (Cobalt Strike, Havoc, Sliver, etc.) via `Enable Custom Shellcode`

**Shellcode Obfuscation Pipeline:**
  - Compression: LZNT1, RLE, or None
  - Encryption: RC4, XOR
  - Encoding: BASE64, ALPHA32, ASCII85, WORDS256
  - Output formats: C, C#, Raw

**Injection Methods (Shellcode Loader):**
  - NtMapViewOfSection (Type 1)
  - CreateFiber (Type 2)
  - EarlyCascade / NtQueueApcThread (Type 3)
  - PoolParty (Type 4)

**Injection Methods (ClickOnce):**
  - CreateFiber
  - EarlyCascade
  - PoolParty
  - Classic CreateRemoteThread
  - EnumDesktops callback injection
  - AppDomain Injection

**Container Formats:**
  - ISO (Bootable media with optional autorun)
  - MSI (Windows Installer packages)
  - 7z (High compression archives)
  - ZIP (Standard archives with optional encryption)
  - **Electron fake-installer** (single portable .exe that presents a Next/Install/Finish wizard, extracts the embedded loader to `%TEMP%`, and spawns it hidden & detached — includes a two-gate interaction + environment guardrails system that defers the file copy until after real user interaction AND configurable anti-sandbox checks pass)

**Trigger Mechanisms:**
  - **LNK** - Windows shortcut (.lnk) with configurable icon, target binary, and command chain
  - **BAT** - Batch script chaining the trigger binary with decoy display
  - **MSI** - Windows Installer package with custom action
  - **MSC** - Windows Management Console snap-in (Explorer-triggered)
  - **HTML Smuggling** - Self-contained HTML page with XOR+base64 obfuscated payload that reconstructs a Blob in-browser and triggers a download, defeating gateway base64 scanning
  - **ClickFix** - Fake CAPTCHA/verification lure page that silently copies a PowerShell/cmd command to the clipboard and walks the victim through Win+R → Ctrl+V → Enter to execute it

**Delivery & Evasion:**
  - Code Signing (Self-signed, spoofed, or legitimate certificates)
  - MalDocs (Excel) Support:
    - VBA Module Export (.bas files for direct import into Excel)
    - 4 VBA Loader Techniques (VirtualAlloc, EnumLocales, QueueUserAPC, ProcessHollowing)
    - XLL Add-In DLL payloads (native Excel add-in execution)
    - Dynamic payload discovery - VBA enumerates the filesystem to locate the payload by name at runtime rather than relying on a hardcoded path
    - Output formats: XLSM, XLSX, XLAM
    - Windows-side COM injection via `erebus_helper` (deferred build)
  - Decoy File Support (Social engineering with fake content)
  - Configurable Injection Parameters (Target process, injection type)

**Obfuscated Shellcode Generation**
  - Dynamic configuration of obfuscation chains
  - Multiple encryption key options (custom or auto-generated)
  - Output format customization per loader type

## Authors

- @[Lavender-exe](https://github.com/Lavender-exe) - Project Author
- @[Hunter](https://github.com/hunterino-sec) - Project Author

### Contributors

- @[iilegacyyii](https://github.com/iilegacyyii) - Project Support & [Shellcrypt](https://github.com/iilegacyyii/Shellcrypt) Author
- @[mgeeky](https://github.com/mgeeky) - Project Support & Inspiration
- @[its-a-feature](https://github.com/its-a-feature) - Project Support & [Mythic C2 Server](https://github.com/its-a-feature/Mythic) Author
- All the open-source devs that made this possible, thank you for your continued maintenance & contributions!

## Table of Contents

{{% children %}}