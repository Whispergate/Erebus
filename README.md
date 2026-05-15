<p align="center">
 <img src="agent_icons/ErebusBannerText.png" alt="Erebus Banner" style="width: 800px;"/>
</p>

# Erebus
Erebus is a modern initial access wrapper aimed at decreasing the development to deployment time, when preparing for intrusion operations. Erebus comes with multiple techniques out of the box to craft complex chains, and assist in bypassing the toughest security measures.

This project is meant to be an extension to your offensive capabilities, and is by no means a silver bullet against all environments. If you would like to add your own techniques or modify the existing ones then check out the project's documentation page for more info.

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

## How to install an agent in this format within Mythic

When it's time for you to test out your install or for another user to install your agent, it's pretty simple. Within Mythic you can run the `mythic-cli` binary to install this in one of three ways:

* `sudo ./mythic-cli install github https://github.com/Whispergate/Erebus` to install the main branch
* `sudo ./mythic-cli install github https://github.com/Whispergate/Erebus branchname` to install a specific branch of that repo
* `sudo ./mythic-cli install folder /path/to/local/folder/cloned/from/github` to install from an already cloned down version of an agent repo

Now, you might be wondering _when_ should you or a user do this to properly add your agent to their Mythic instance. There's no wrong answer here, just depends on your preference. The three options are:

* Mythic is already up and going, then you can run the install script and just direct that agent's containers to start (i.e. `sudo ./mythic-cli start erebus_wrapper` and if that agent has its own special C2 containers, you'll need to start them too via `sudo ./mythic-cli start erebus_wrapper`).
* Mythic is already up and going, but you want to minimize your steps, you can just install the agent and run `sudo ./mythic-cli start`. That script will first _stop_ all of your containers, then start everything back up again. This will also bring in the new agent you just installed.
* Mythic isn't running, you can install the script and just run `sudo ./mythic-cli start`.

## Documentation

View the rendered documentation by clicking on **Docs -> Agent Documentation** in the upper right-hand corner of the Mythic interface.

## Features

- **Payload Generation**: Shellcode loader, VBA macros, XLL Add-Ins, DLL hijacking, and maldocs
- **Execution Methods**: CreateThread, AddressOfEntryPoint Injection, QueueUserAPC, EnumLocales, and more
- **VBA Payloads**: Command execution, PowerShell, Schtasks, WMI, Rundll32, Regsvr32, and shellcode injection
- **Maldoc Creation**: Template-based XLSM generation with VBA injection
- **MSI Backdooring**: Multiple attack vectors for MSI installer injection
- **Code Signing**: Self-signed, URL spoofing, and custom certificate support
- **Obfuscation**: VBA obfuscation, shellcode encryption, and compression
- **IOC Tracking**: Automated hash collection and IOC report generation
- **Decoy Files**: Custom decoy file inclusion for social engineering
- **Plugin System**: Easily add your own plugins using the plugin system for internal use-cases

## Roadmap
### Features
- [x] Execution Guardrails
- [x] Extended support for larger shellcodes (Apollo, Athena, etc.)
- [x] Increased Modularity & Customisation Support (Templating)
- [x] Extended DLL Hijacking Shellcode Obfuscation Support (More decryption, decoding, and decompression support)
  - [x] Decoding
  - [x] Decryption
  - [x] Decompression
- [x] Complete XLSM/XLAM phishing payloads
- [x] LNK Triggers
- [x] MSC Snap-In and GrimReaper triggers
- [x] Hidden MSI/ISO container files
- [x] Maldocs VBA generator

### Known Issues
- VBA: Address of Entry Point Injection is not functional as of v0.1.0
- Container goes offline during compilation of some payloads, just wait for ~>5 minutes for it to finish working

### Bug Fixes

#### [v0.0.2]
- Fixed issues with XLL source code saving
- Generated build_xll.bat for native Windows recompilation
- Improved error handling and output messages during build process
- Fixed MSI Backdoor injector
- Added MSC GrimReaper Trigger
- Added support for larger shellcodes (Apollo, Athena, etc.)

#### [v0.0.1]
- Minor issues with build steps
- Loader Decompression bugs 
