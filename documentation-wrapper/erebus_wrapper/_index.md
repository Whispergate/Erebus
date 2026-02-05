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

**Shellcode Obfuscation Pipeline:**
  - Compression: LZNT1, RLE, or None
  - Encryption: RC4, XOR
  - Encoding: BASE64, ALPHA32, ASCII85, WORDS256
  - Output formats: C, C#, Raw

**Injection Methods:**
  - NtQueueApcThread
  - NtMapViewOfSection
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

**Delivery & Evasion:**
  - Code Signing (Self-signed, spoofed, or legitimate certificates)
  - LNK Trigger Mechanisms (Shortcut-based execution chains)
  - MalDocs (Excel) Support:
    - VBA Module Export (.bas files for direct import into Excel)
    - 4 VBA Loader Techniques (VirtualAlloc, EnumLocales, QueueUserAPC, ProcessHollowing)
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