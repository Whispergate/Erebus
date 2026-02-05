+++
title = "Development"
chapter = false
weight = 15
pre = "<b>1. </b>"
+++

## Project Overview

The Erebus wrapper is a comprehensive initial access toolkit designed to generate obfuscated payloads with multiple delivery mechanisms, injection techniques, and container options. It provides flexibility in shellcode obfuscation, encryption, encoding, and various execution methods through different loader types.

### Key Features

- **Multiple Loader Types**: Shellcode Loader (C++) and ClickOnce (.NET)
- **Flexible Obfuscation**: Compression, encryption, and encoding of shellcode
- **Multiple Injection Methods**: 5+ injection techniques for both loaders
- **Container Support**: ISO, 7z, ZIP, and MSI packaging
- **Code Signing**: Self-signed, spoofed, or provided certificates
- **Trigger Mechanisms**: LNK-based triggers, BAT script triggers, and MSI package triggers with decoy files
- **DLL Hijacking**: Proxy-based DLL hijacking capability
- **MSI Backdooring**: Multiple attack vectors for injecting payloads into existing MSI installers

## High Level Flow Chart

The comprehensive build workflow for Erebus is shown below:

```
                            ┌─────────────────────┐
                            │   Start Build       │
                            └──────────┬──────────┘
                                       │
                            ┌──────────▼──────────┐
                            │  Input Shellcode    │
                            │   from Mythic       │
                            └──────────┬──────────┘
                                       │
                         ┌─────────────▼──────────────┐
                         │  Main Payload Type?        │
                         │  Loader / Hijack           │
                         └──┬──────────────────────┬──┘
                    ┌───────┘                      └────────┐
                    │                                       │
        ┌───────────▼──────────┐             ┌──────────────▼───────────┐
        │  Loader Type?        │             │  DLL Hijacking Config    │
        │  Shellcode/ClickOnce │             │  - Upload DLL            │
        └──┬──────────────┬────┘             │  - Create Proxy          │
           │              │                  └──────────────┬───────────┘
    ┌──────▼────┐  ┌──────▼─────┐                           │
    │Shellcode  │  │ClickOnce   │                           │
    │Loader Cfg │  │Cfg         │                           │
    │- Injection│  │- Method    │                           │
    │- Target   │  │- Target    │                           │
    └──────┬────┘  └──────┬─────┘                           │
           │              │                                 │
           └──────────────┼─────────────────────────────────┘
                          │
         ┌────────────────▼─────────────────┐
         │  Shellcode Obfuscation           │
         │  (Shellcrypt)                    │
         │  ┌─────────────────────────────┐ │
         │  │ Compression: LZNT1/RLE/NONE │ │
         │  │ Encryption: RC4/XOR         │ │
         │  │ Encoding: ALPHA32/BASE64    │ │
         │  └─────────────────────────────┘ │
         └────────────────┬─────────────────┘
                          │
           ┌──────────────▼───────────────┐
           │  Output Format?              │
           │  C/CSharp/Python/Go/Nim...   │
           └────────────────┬─────────────┘
                            │
             ┌──────────────▼───────────────┐
             │  Obfuscated Shellcode        │
             │  Ready                       │
             └────────────────┬─────────────┘
                              │
               ┌──────────────▼───────────────┐
               │  Compilation Path?           │
               │  Shellcode/ClickOnce/Hijack  │
               └──┬─────────────────┬─────┬───┘
         ┌────────┘                 │     └───────┐
         │                          │             │
    ┌────▼────────┐  ┌──────────────▼───┐  ┌──────▼──────┐
    │ Compile C++ │  │Compile .NET      │  │Compile DLL  │
    │ Shellcode   │  │ClickOnce         │  │ Proxy       │
    │ Loader      │  │                  │  │             │
    └────┬────────┘  └──────────┬───────┘  └──────┬──────┘
         │                      │                 │
         └──────────────┬───────┴─────────────────┘
                        │
                 ┌──────▼──────────┐
                 │ Payload         │
                 │ Compiled        │
                 └──────┬──────────┘
                        │
              ┌─────────▼──────────┐
              │ Sign Payload?      │
              │ Self/Spoof/Provide │
              └──────────┬─────────┘
                         │
              ┌──────────▼──────────┐
              │ Add Trigger?        │
              │ LNK/BAT/MSI/CO      │
              └──────────┬──────────┘
                         │
            ┌────────────▼────────────┐
            │ Package Container?      │
            │ ISO/7z/ZIP/MSI          │
            └──────────┬──────────────┘
                       │
             ┌─────────▼──────────┐
             │ Create MalDoc?     │
             │ New/Backdoor       │
             └──────────┬─────────┘
                        │
             ┌──────────▼─────────┐
             │ Output Final       │
             │ Payload            │
             └──────────┬─────────┘
                        │
                 ┌──────▼────────┐
                 │ Build         │
                 │ Complete      │
                 └───────────────┘
```

**Build Process Stages:**

1. **Input** → Receive shellcode from Mythic C2
2. **Configuration** → Select payload type and loader configuration
3. **Obfuscation** → Apply compression, encryption, and encoding
4. **Compilation** → Compile selected loader with obfuscated shellcode
5. **Signing** → Optional code signing (self-signed, spoofed, or provided)
6. **Triggering** → Add execution trigger (LNK, BAT, MSI, or ClickOnce)
7. **Packaging** → Container the payload (ISO, 7z, ZIP, or MSI)
8. **MalDocs** → Optional Excel document generation or injection
9. **Output** → Final packaged payload ready for delivery

## Build Workflow

### 1. Payload Type Selection
- **Loader**: Uses Shellcode Loader or ClickOnce
- **Hijack**: Uses DLL proxy hijacking

### 2. Shellcode Obfuscation
- **Input**: Raw shellcode binary from Mythic
- **Compression**: LZNT1, RLE, or NONE
- **Encryption**: RC4 or XOR
  - Currently supported: RC4 (stream cipher), XOR (simple XOR encryption)
  - Available but not yet supported by loaders (TODO): AES128_CBC, AES256_CBC, AES256_ECB, CHACHA20, SALSA20, XOR_COMPLEX
- **Encoding**: ALPHA32, ASCII85, BASE64, WORDS256, or NONE
- **Output Format**: C, CSharp, or Raw
  - Additional formats available for custom loaders: Nim, Go, Python, PowerShell, VBA, VBScript, Rust, JavaScript, Zig

### 3. Loader Compilation
- **Shellcode Loader**: C++ executable/DLL with configurable injection
- **ClickOnce**: .NET application with manifests
- Configuration applied based on user parameters

### 4. Optional Code Signing
- Sign with selected certificate (self-signed, spoofed, or provided)
- Build step name: `Sign Shellcode Loader`

### 5. Optional Trigger or MalDoc
- **Trigger Option**: Create LNK, BAT, MSI, or ClickOnce trigger with decoy execution
  - Build step name: `Adding Trigger`
- **MalDoc Option**: Create or backdoor Excel document with VBA payload
  - Build step name: `Creating MalDoc`
  - Supports AutoOpen, OnClose, or OnSave triggers
  - VBA loader techniques: VirtualAlloc, EnumLocales, QueueUserAPC, or ProcessHollowing

### 6. Containerization
- Package in ISO, 7z, ZIP, or MSI
- Build step name: `Containerising`

### 7. Delivery
- Output final packaged payload

## Build Parameters Reference

### Main Payload Selection (Section 0.0-0.2)
- **0.0 Main Payload Type**: Choose "Loader" or "Hijack"
  - **Loader**: Uses Shellcode Loader (C++) or ClickOnce (.NET) - requires Raw shellcode format for Loader
  - **Hijack**: Uses DLL proxy hijacking - requires C format shellcode
- **0.1 Loader Type**: Select "Shellcode Loader" or "ClickOnce" (visible when Main Payload Type = Loader)
- **0.1 Loader Type** (alternate): Select "EXE" or "DLL" (visible when Main Payload Type = Shellcode Loader)

### Shellcode Loader Configuration (Section 0.3-0.5)
- **0.3 Loader Build Configuration**: Debug or Release build
- **0.4 Shellcode Loader - Injection Type**:
  - 1 = NtQueueApcThread (APC injection to suspended thread - Remote)
  - 2 = NtMapViewOfSection (Section mapping injection - Remote)
  - 3 = CreateFiber (Fiber-based execution - Self)
  - 4 = EarlyCascade (Early Bird APC injection - Remote)
  - 5 = PoolParty (Worker Factory thread pool injection - Remote)
- **0.5 Shellcode Loader - Target Process**: Process name for remote injection

### ClickOnce Configuration (Section 0.3-0.7)
- **0.3 ClickOnce Build Configuration**: Debug or Release build
- **0.4 ClickOnce RID**: Runtime Identifier (default: win-x64) for .NET publishing
- **0.6 ClickOnce - Injection Method**:
  - createfiber: Fiber-based self-injection
  - earlycascade: Early Bird APC injection (remote)
  - poolparty: Worker Factory thread pool injection (remote)
  - classic: Classic CreateRemoteThread injection (remote)
  - enumdesktops: EnumDesktops callback injection (self)
  - appdomain: AppDomain injection for .NET assemblies (self)
- **0.7 ClickOnce - Target Process**: Target process for remote injection (default: explorer.exe)
  - Only visible for remote injection methods

### DLL Hijacking (Section 1.0)
- **1.0 DLL Hijacking**: Upload DLL for proxy-based hijacking
  - Only visible when Main Payload Type = Hijack
  - **Requirements**: 
    - Shellcode Format (2.4) must be set to C
    - Shellcode will be compiled into a proxy DLL
  - **Note**: Currently supports XOR encryption only; does not support encoded or compressed payloads

### Output Extension Source (Section 0.8)
- **0.8 Output Extension Source**: Choose primary delivery mechanism
  - Trigger: Use LNK/BAT/MSI/ClickOnce trigger files as main payload
  - MalDoc: Use Excel document with VBA payload as main payload
  - Determines which options are visible for sections 0.9 onwards

### Trigger Configuration (Section 0.9-0.9b)
- **0.9 Trigger Type**: Select trigger mechanism for payload execution
  - LNK: Windows shortcut file (.lnk) trigger
  - BAT: Batch script (.bat) trigger
  - MSI: Windows Installer package trigger
  - ClickOnce: ClickOnce application trigger
  - Only visible when Output Extension Source = Trigger
  - Default: BAT
- **0.9a Trigger Binary**: Executable to run when trigger is activated
  - Default: "C:\Windows\System32\conhost.exe"
  - Hidden for MSI and ClickOnce triggers (they have custom execution paths)
  - This binary is executed alongside the payload
- **0.9b Trigger Command**: Command arguments to pass to trigger binary
  - Default: "--headless cmd.exe /Q /c erebus.exe | decoy.pdf"
  - Hidden for MSI and ClickOnce triggers
  - Example usage: chains execution of payload with decoy document display

### MalDoc Configuration (Section 0.9-0.9g)
- **0.9 Create MalDoc**: MalDoc generation option
  - None: No Excel document (disable MalDoc)
  - Create/Backdoor Excel: Generate new or modify existing Excel file
  - VBA Module Only: Export only the VBA payload module (.bas file)
  - Only visible when Output Extension Source = MalDoc
  - Default: None
- **0.9a MalDoc Type**: Choose Excel document creation mode
  - Create New: Generate fresh XLSM document with payload
  - Backdoor Existing: Inject payload into uploaded Excel file
  - Only visible when Create MalDoc != None
  - Default: Create New
- **0.9b Excel Source File**: Upload existing Excel file to backdoor
  - Accepts: XLSM, XLS, XLAM file formats
  - Only visible when MalDoc Type = Backdoor Existing
  - Optional: if not provided, creates new document
- **0.9c VBA Execution Trigger**: Macro execution trigger method
  - AutoOpen: Executes when document is opened (most reliable)
  - OnClose: Executes when document is closed
  - OnSave: Executes when document is saved
  - Only visible when Create MalDoc != None
  - Default: AutoOpen
- **0.9d Excel Document Name**: Display name/title for the Excel document
  - Default: "Invoice"
  - Only visible when Create MalDoc != None
  - This appears in window title and document properties
- **0.9e Obfuscate VBA**: Obfuscate VBA code to evade detection
  - Boolean flag (True/False)
  - Only visible when Create MalDoc != None
  - Default: True
  - Recommended: Always enable for operational security
- **0.9f MalDoc Injection Type**: Payload injection method in VBA
  - Command Execution: Execute trigger binary via WinAPI calls
  - Shellcode Injection: Inject obfuscated shellcode directly into VBA
  - Only visible when Create MalDoc != None
  - Default: Command Execution
- **0.9g VBA Loader Technique**: VBA shellcode loader technique (if using Shellcode Injection)
  - VirtualAlloc + CreateThread: Classic memory allocation + thread execution
  - EnumSystemLocalesA Callback: API callback-based execution
  - QueueUserAPC Injection: Asynchronous Procedure Call injection
  - Process Hollowing: Remote process injection with suspended execution
  - Only visible when MalDoc Injection Type = Shellcode Injection
  - Default: VirtualAlloc + CreateThread
  - For details on loader techniques, see VBA Loader Techniques section below

### Decoy File (Section 0.13)
- **0.13 Decoy File Inclusion**: Include decoy file in final payload
  - Boolean flag (True/False)
  - Only visible when Main Payload Type = Loader
  - Default: False
  - Enables social engineering with legitimate-looking documents
- **0.13 Decoy File**: Upload decoy file to include
  - Accepts: PDF, XLSX, DOCX, or other file types
  - Only visible when Decoy File Inclusion = True
  - If none uploaded, a generic example file will be used automatically

### Shellcrypt Options (Section 2.0-2.4)
- **2.0 Compression Type**: LZNT1, RLE, or NONE
  - LZNT1: LZNT1 compression (Windows compression format)
  - RLE: Run-Length Encoding compression
  - NONE: No compression
- **2.1 Encryption Type**: RC4 or XOR
  - RC4: RC4 stream cipher (default for most scenarios)
  - XOR: Simple XOR encryption (basic obfuscation)
  - Note: Additional encryption methods (AES128_CBC, AES256_CBC, AES256_ECB, CHACHA20, SALSA20, XOR_COMPLEX) are available in shellcrypt but not yet supported by loader decompilation routines (TODO: Add decryption support to loaders)
- **2.2 Encryption Key**: Custom key or "NONE" for auto-generate
  - If set to "NONE", a random key will be automatically generated
  - Custom keys should match the required length for the encryption method
- **2.3 Encoding Type**: ALPHA32, ASCII85, BASE64, WORDS256, or NONE
  - ALPHA32: Alphanumeric encoding
  - ASCII85: Base85 ASCII encoding
  - BASE64: Standard Base64 encoding
  - WORDS256: Word-based encoding (space-separated numbers)
  - NONE: No encoding
- **2.4 Shellcode Format**: C, CSharp, or Raw
  - C: Output shellcode in C format (for C++ loaders)
  - CSharp: Output shellcode in C# format (for .NET loaders)
  - Raw: Output raw binary shellcode
  - Note: Nim, Go, Python, PowerShell, VBA, VBScript, Rust, JavaScript, and Zig formats commented out (uncomment for custom loaders)

### Container Options (Section 3.0-3.2)
- **3.0 Container Type**: ISO, 7z, ZIP, or MSI
  - ISO: Bootable ISO media (optical disc image)
  - 7z: 7-Zip compressed archive format (highest compression)
  - ZIP: Standard ZIP archive format
  - MSI: Windows Installer package
- **3.1 Compression Level**: 0-9 (where 9 = maximum compression)
  - Only visible for 7z and ZIP containers
  - 0: No compression (fastest)
  - 5: Medium compression (balanced)
  - 9: Maximum compression (slowest, best compression ratio)
- **3.2 Archive Password**: Optional archive password
  - Only visible for 7z and ZIP containers
  - Leave empty for no password protection

### ISO-Specific Options (Section 4.0-4.2)
- **4.0 ISO Volume ID**: Volume name shown in Windows Explorer
  - Default: "EREBUS"
  - Only visible when Container Type = ISO
- **4.1 ISO Enable Autorun**: Enable AutoRun.inf for automatic execution
  - Only visible when Container Type = ISO
  - Boolean flag (True/False)
  - If enabled, creates AutoRun.inf to trigger payload on disc mount
- **4.2 ISO Backdoor File**: Upload existing ISO to modify and inject payload
  - Only visible when Container Type = ISO
  - Optional: if none uploaded, creates new ISO from scratch

### MSI-Specific Options (Section 5.0-5.8)
- **5.0 MSI Product Name**: Application name shown in MSI installation UI
  - Default: "System Updater"
  - Only visible when Container Type = MSI
- **5.1 MSI Manufacturer**: Company name shown in MSI metadata and UI
  - Default: "Microsoft Corporation"
  - Only visible when Container Type = MSI
- **5.2 MSI Install Scope**: Installation scope (User or Machine)
  - User: Installs to AppData (no admin required)
  - Machine: Installs to Program Files (admin required)
  - Only visible when Container Type = MSI
- **5.3 MSI Backdoor File**: Upload existing MSI to modify and inject payload
  - Only visible when Container Type = MSI
  - Optional: if none uploaded, creates new MSI from scratch
  - When provided, allows hijacking existing installer for injection
- **5.4 MSI Attack Type**: Attack vector for MSI backdoor injection
  - execute: Run command via CustomAction (stealthiest, no output visible)
  - run-exe: Extract and execute EXE from Binary table (visible execution)
  - load-dll: Load native DLL via DllEntry (in-process execution)
  - dotnet: Load .NET assembly (auto-detected from file type)
  - script: Execute VBScript/JScript (requires entry point function name)
  - Only visible when backdooring an existing MSI file
- **5.5 MSI Entry Point**: DLL export function or script function name
  - Required for: load-dll, dotnet, and script attack types
  - For load-dll: DLL export function name (e.g., "DllMain", "Entry")
  - For dotnet: Assembly function name to call
  - For script: VBScript/JScript function name to execute
- **5.6 MSI Command Arguments**: Command line arguments
  - Only used for execute and run-exe attack types
  - Passed directly to the executed command/EXE
- **5.7 MSI Execution Condition**: MSI condition for payload execution
  - Default: "NOT REMOVE" (executes only on install, not uninstall)
  - Examples: "NOT REMOVE", "UPGRADINGPRODUCTCODE", "REMOVE<>ALL"
  - See WiX condition reference for advanced options
- **5.8 MSI Custom Action Name**: Identifier for the custom action
  - Leave empty for random auto-generation
  - Custom value: Use specific name for consistency in MSI tables

### Code Signing (Section 6.0-6.6)
- **6.0 Codesign Loader**: Enable/disable code signing of the payload loader
  - Boolean flag (True/False)
  - If enabled, signs with certificate specified in following options
- **6.1 Codesign Type**: Certificate source for code signing
  - SelfSign: Generate self-signed certificate
  - Spoof URL: Clone certificate details from a URL
  - Provide Certificate: Upload an existing PFX/P12 certificate file
  - Only visible when Codesign Loader = True
- **6.2 Codesign CN**: Common Name (CN) for self-signed certificate
  - Default: "Microsoft Corporation"
  - Only visible when Codesign Type = SelfSign
  - Used in certificate subject name
- **6.3 Codesign Orgname**: Organization Name for self-signed certificate
  - Default: "Microsoft Corporation"
  - Only visible when Codesign Type = SelfSign
  - Used in certificate issuer name
- **6.4 Codesign Spoof URL**: URL to clone certificate details from
  - Default: "www.google.com"
  - Only visible when Codesign Type = Spoof URL
  - Fetches certificate from URL and clones its properties
- **6.5 Codesign Cert**: Upload PFX/P12 certificate file
  - Only visible when Codesign Type = Provide Certificate
  - File format: PFX or P12 (binary certificate format)
- **6.6 Codesign Cert Password**: Password for the certificate file
  - Only visible when Codesign Type = Provide Certificate
  - Leave empty if certificate has no password



## Build Steps Reference

The Erebus builder executes the following build steps in sequence. Each step is reported to Mythic during the build process:

### 1. Gathering Files
- **Description**: Copy files to temporary build location
- **Purpose**: Staging all necessary files for compilation
- **Visibility**: Always executed

### 2. Header Check
- **Description**: Check input file for PE (MZ) header
- **Purpose**: Validate that supplied file is raw shellcode, not a PE binary
- **Triggers**: Only when shellcode payload is processed
- **Error Condition**: If MZ header is detected, build fails

### 3. Shellcode Obfuscation
- **Description**: Obfuscate shellcode using Shellcrypt
- **Process**: Applies compression, encryption, and encoding in sequence
  - Compression: LZNT1, RLE, or NONE
  - Encryption: RC4 or XOR with configured key (AES support pending loader implementation)
  - Encoding: BASE64, ASCII85, ALPHA32, WORDS256, or NONE
- **Output**: Formatted shellcode (C, CSharp, or Raw)
- **Visibility**: Always executed (unless build fails)

### 4. Gathering DLL Exports for Hijacking
- **Description**: Extract exports from uploaded DLL for proxy table
- **Triggers**: Only when Main Payload Type = Hijack
- **Process**: Analyzes DLL to generate export table
- **Error Condition**: If no exports found or file too small

### 5. Compiling DLL Payload
- **Description**: Compile DLL with hijacked export proxying
- **Triggers**: Only when Main Payload Type = Hijack
- **Process**: Uses C++ compiler to build proxy DLL with shellcode
- **Configuration**: Includes injected shellcode and target process info

### 6. Compiling Shellcode Loader
- **Description**: Compile C++ Shellcode Loader with obfuscated shellcode
- **Triggers**: Only when Loader Type = Shellcode Loader
- **Configuration Applied**:
  - Injection type (NtQueueApcThread, NtMapViewOfSection, CreateFiber, etc.)
  - Target process for injection
  - Compression/Encoding type
  - Encryption type and key
- **Output Format**: EXE or DLL based on "0.1 Loader Type" parameter

### 7. Compiling ClickOnce Loader
- **Description**: Compile .NET ClickOnce loader with obfuscated shellcode
- **Triggers**: Only when Loader Type = ClickOnce
- **Configuration Applied**:
  - Injection method (createfiber, earlycascade, poolparty, classic, enumdesktops, appdomain)
  - Target process for injection
  - Compression/Encoding type
  - Encryption type and key
  - Runtime Identifier (RID) for .NET publishing

### 8. Sign Shellcode Loader
- **Description**: Sign compiled payload with code signing certificate
- **Triggers**: Only when Codesign Loader = True
- **Options**:
  - SelfSign: Generate and use self-signed certificate
  - Spoof URL: Download and clone certificate from specified URL
  - Provide Certificate: Use uploaded PFX/P12 certificate file
- **Verification**: Validates signature was applied successfully

### 9. Backdooring MSI
- **Description**: Inject payload into existing MSI installer
- **Triggers**: Only when Container Type = MSI and MSI Backdoor File is provided
- **Process**: Modifies MSI tables to include custom action for payload execution
- **Attack Types**:
  - execute: CustomAction with direct command execution
  - run-exe: Extract and execute EXE from Binary table
  - load-dll: DLL loading via entry point
  - dotnet: .NET assembly loading
  - script: VBScript/JScript execution

### 10. Adding Trigger
- **Description**: Create trigger mechanism for payload execution
- **Triggers**: Only when Output Extension Source = Trigger and Main Payload Type = Loader
- **Supported Triggers**:
  - LNK: Windows shortcut with execution chain
  - BAT: Batch script runner
  - MSI: Windows Installer with custom action
  - ClickOnce: ClickOnce application manifest
- **Functionality**: Sets up execution of loader with optional decoy display

### 11. Creating Decoy
- **Description**: Generate or include decoy file
- **Triggers**: Only when Decoy File Inclusion = True
- **Process**:
  - If file uploaded: Stages provided decoy file
  - If not uploaded: Generates generic example decoy file
- **Purpose**: Social engineering to obscure malicious execution

### 12. Creating MalDoc
- **Description**: Create or backdoor Excel document with VBA payload
- **Triggers**: Only when Output Extension Source = MalDoc and Create MalDoc != None
- **Modes**:
  - Create New: Generates fresh XLSM with embedded VBA
  - Backdoor Existing: Injects VBA into uploaded Excel file
  - VBA Module Only: Exports standalone .bas module file
- **VBA Configuration**:
  - Execution trigger: AutoOpen, OnClose, or OnSave
  - Injection type: Command Execution or Shellcode Injection
  - Loader technique: VirtualAlloc, EnumLocales, QueueUserAPC, or ProcessHollowing
  - Obfuscation: Optional VBA code obfuscation

### 13. Containerising
- **Description**: Package payload into final delivery container
- **Triggers**: Always executed (unless previous step failed)
- **Container Types**:
  - ISO: Bootable media with optional AutoRun.inf
  - 7z: 7-Zip compressed archive with configurable compression
  - ZIP: Standard ZIP archive with optional password
  - MSI: Windows Installer package
- **Final Output**: Compressed and packaged payload ready for deployment

#### Build Step Status Reporting

Each build step is reported to Mythic C2 with:
- **StepName**: Name of the build step
- **StepStdout**: Status message and diagnostic information
- **StepSuccess**: Boolean indicating pass/fail

If any step fails, the entire build is terminated and an error is reported to the operator.

## Build Workflow

### 1. Payload Type Selection
- **Loader**: Uses Shellcode Loader or ClickOnce
- **Hijack**: Uses DLL proxy hijacking

### 2. Shellcode Obfuscation
- **Input**: Raw shellcode binary from Mythic
- **Compression**: LZNT1, RLE, or NONE
- **Encryption**: RC4 or XOR
  - Currently supported: RC4 (stream cipher), XOR (simple XOR encryption)
  - Available but not yet supported by loaders (TODO): AES128_CBC, AES256_CBC, AES256_ECB, CHACHA20, SALSA20, XOR_COMPLEX
- **Encoding**: ALPHA32, ASCII85, BASE64, WORDS256, or NONE
- **Output Format**: C, CSharp, or Raw
  - Additional formats available for custom loaders: Nim, Go, Python, PowerShell, VBA, VBScript, Rust, JavaScript, Zig

### 3. Loader Compilation
- **Shellcode Loader**: C++ executable/DLL with configurable injection
- **ClickOnce**: .NET application with manifests
- Configuration applied based on user parameters

### 4. Optional Code Signing
- Sign with selected certificate (self-signed, spoofed, or provided)
- Build step name: `Sign Shellcode Loader`

### 5. Optional Trigger or MalDoc
- **Trigger Option**: Create LNK, BAT, MSI, or ClickOnce trigger with decoy execution
  - Build step name: `Adding Trigger`
- **MalDoc Option**: Create or backdoor Excel document with VBA payload
  - Build step name: `Creating MalDoc`
  - Supports AutoOpen, OnClose, or OnSave triggers
  - VBA loader techniques: VirtualAlloc, EnumLocales, QueueUserAPC, or ProcessHollowing

### 6. Containerization
- Package in ISO, 7z, ZIP, or MSI
- Build step name: `Containerising`

### 7. Delivery
- Output final packaged payload

## Build Parameters Reference

### Main Payload Selection (Section 0.0-0.2)
- **0.0 Main Payload Type**: Choose "Loader" or "Hijack"
  - **Loader**: Uses Shellcode Loader (C++) or ClickOnce (.NET) - requires Raw shellcode format for Loader
  - **Hijack**: Uses DLL proxy hijacking - requires C format shellcode
- **0.1 Loader Type**: Select "Shellcode Loader" or "ClickOnce" (visible when Main Payload Type = Loader)
- **0.1 Loader Type** (alternate): Select "EXE" or "DLL" (visible when Main Payload Type = Shellcode Loader)

### Shellcode Loader Configuration (Section 0.3-0.5)
- **0.3 Loader Build Configuration**: Debug or Release build
- **0.4 Shellcode Loader - Injection Type**:
  - 1 = NtQueueApcThread (APC injection to suspended thread - Remote)
  - 2 = NtMapViewOfSection (Section mapping injection - Remote)
  - 3 = CreateFiber (Fiber-based execution - Self)
  - 4 = EarlyCascade (Early Bird APC injection - Remote)
  - 5 = PoolParty (Worker Factory thread pool injection - Remote)
- **0.5 Shellcode Loader - Target Process**: Process name for remote injection

### ClickOnce Configuration (Section 0.3-0.7)
- **0.3 ClickOnce Build Configuration**: Debug or Release build
- **0.4 ClickOnce RID**: Runtime Identifier (default: win-x64) for .NET publishing
- **0.6 ClickOnce - Injection Method**:
  - createfiber: Fiber-based self-injection
  - earlycascade: Early Bird APC injection (remote)
  - poolparty: Worker Factory thread pool injection (remote)
  - classic: Classic CreateRemoteThread injection (remote)
  - enumdesktops: EnumDesktops callback injection (self)
  - appdomain: AppDomain injection for .NET assemblies (self)
- **0.7 ClickOnce - Target Process**: Target process for remote injection (default: explorer.exe)
  - Only visible for remote injection methods

#### VBA Module Import Instructions

**Recommended Workflow: VBA Module Only Export**

When you select "VBA Module Only", the builder generates:
1. `{document_name}_payload.bas` - Importable VBA module
2. `{document_name}_payload.txt` - Plain text reference

**To use the exported VBA module:**

1. Open Excel and create or open a workbook
2. Press **Alt+F11** to open the VBA Editor (or Tools → Macros → Visual Basic Editor)
3. File → Import File
4. Select the `.bas` file generated by Erebus
5. The VBA module will be imported into your workbook
6. The payload is now ready to execute on document open

**To use with Full XLSM mode:**

The XLSM file comes pre-populated with the VBA payload and will execute automatically when the macro security settings allow.

#### VBA Loader Techniques

When using **Shellcode Injection** mode, you can select from four loader techniques:

1. **VirtualAlloc + CreateThread** (Default)
   - Classic and most reliable technique
   - Allocates RWX memory → copies shellcode → creates execution thread
   - Best compatibility across all Office versions
   - Moderate detection rate

2. **EnumSystemLocalesA Callback**
   - Executes shellcode via API callback mechanism
   - Bypasses static analysis tools that only look for CreateThread
   - Lower detection rate than direct CreateThread
   - Compatible with modern Office versions

3. **QueueUserAPC Injection**
   - Uses Asynchronous Procedure Calls for execution
   - Executes in current thread context (no new thread creation)
   - Stealthier than CreateThread approach
   - Requires alertable wait state (handled automatically)

4. **Process Hollowing**
   - Creates suspended notepad.exe process
   - Injects shellcode into remote process memory
   - Resumes thread to execute payload
   - Highest evasion potential but more complex
   - Best for advanced evasion scenarios

**Recommendation:** Start with VirtualAlloc for reliability, upgrade to EnumLocales or QueueUserAPC for better evasion, use ProcessHollowing for maximum stealth.

## Adding Features

### Plugin System

Erebus uses an extensible plugin architecture for adding new functionality. For comprehensive plugin development documentation, see [Plugin Development]({{< relref "plugin-development.md" >}}).

**Quick Start:**
1. Copy `modules/plugin_example.py.template` to `modules/plugin_your_feature.py`
2. Implement the three required methods: `get_metadata()`, `register()`, `validate()`
3. Test your plugin: `python plugin_your_feature.py`
4. The plugin system will automatically discover and validate your plugin

**Key Features:**
- ✅ Automatic plugin discovery
- ✅ Built-in validation framework
- ✅ Standardized test blocks for all plugins
- ✅ Mythic RPC integration for operational reporting
- ✅ Easy registration of plugin functions

**Current Plugins:**

The Erebus payload wrapper includes the following production plugins:

1. **plugin_archive_container.py** - Archive container base class and utilities
   - Handles compression level specifications for archives
   - Manages password-protected archive creation
   
2. **plugin_base.py** - Base plugin class and framework
   - Provides PluginBase abstract class for all plugins
   - Implements plugin lifecycle management
   - Handles validation framework and reporting

3. **plugin_codesigner.py** - Code signing functionality
   - Self-signed certificate generation (OpenSSL)
   - Certificate spoofing from remote URLs
   - Provided certificate signing support
   - Integrates with Windows signing tools (signtool.exe)

4. **plugin_container_clickonce.py** - ClickOnce container building
   - Builds .NET ClickOnce manifests
   - Handles deployment and application manifests
   - SHA256 hash generation for file integrity
   - Manages ClickOnce deployment configuration

5. **plugin_container_iso.py** - ISO container creation
   - Creates bootable ISO media from payload
   - Optional AutoRun.inf generation for auto-execution
   - Supports backdooring existing ISO files
   - Uses mkisofs/genisoimage for ISO generation

6. **plugin_container_msi.py** - MSI container and backdooring
   - MSI package creation from scratch
   - Backdooring existing MSI installers
   - Multiple attack vectors:
     - `execute`: CustomAction with command execution
     - `run-exe`: Binary extraction and execution
     - `load-dll`: DLL loading via entry point
     - `dotnet`: .NET assembly loading
     - `script`: VBScript/JScript execution
   - Supports multiple file injection into MSI database
   - Includes ErebusActionTypes and ErebusInstallerToolkit utilities

7. **plugin_loader.py** - Plugin loader and discovery system
   - Automatic plugin discovery from modules directory
   - Dynamic function registration
   - Fallback mechanism for missing functions
   - Error handling and reporting

8. **plugin_payload_dll_proxy.py** - DLL proxy generation for hijacking
   - Extracts exports from target DLLs
   - Generates proxy DEF files for export forwarding
   - Integrates with loader compilation pipeline
   - Supports multiple export types

9. **plugin_payload_maldocs.py** - Excel document creation and VBA payload injection
   - Creates new XLSM documents with payload
   - Backdoors existing Excel files (.xlsm, .xls, .xlam)
   - VBA macro obfuscation
   - Multiple VBA loader techniques:
     - VirtualAlloc + CreateThread
     - EnumSystemLocalesA callback
     - QueueUserAPC injection
     - Process hollowing
   - Execution triggers: AutoOpen, OnClose, OnSave

10. **plugin_trigger_bat.py** - BAT script trigger generation
    - Generates batch scripts for payload execution
    - Executes trigger binary and command chain
    - Displays decoy file after execution
    - Supports obfuscated command execution

11. **plugin_trigger_clickonce.py** - ClickOnce trigger and manifest generation
    - Creates ClickOnce deployment manifests
    - Builds application and deployment manifests
    - Supports trusted execution model
    - References: https://specterops.io/blog/2023/06/07/less-smartscreen-more-caffeine-abusing-clickonce-for-trusted-code-execution/

12. **plugin_trigger_lnk.py** - LNK shortcut trigger creation
    - Creates .lnk (Windows shortcut) files
    - Configurable command execution chains
    - Decoy file display integration
    - Icon and description customization

13. **plugin_trigger_msi.py** - MSI trigger generation
    - Creates MSI packages as execution triggers
    - Embeds payloads in custom actions
    - Configurable execution conditions
    - Supports immediate and deferred actions

**Plugin Architecture Overview:**

Each plugin follows a standardized structure:

```python
from erebus_wrapper.erebus.modules.plugin_base import PluginBase

class CustomPlugin(PluginBase):
    def get_metadata(self):
        """Return plugin information"""
        return {
            "name": "Plugin Name",
            "version": "1.0.0",
            "author": "Your Name",
            "description": "Plugin description",
            "dependencies": []  # List of required packages
        }
    
    def register(self):
        """Register functions that will be available to builder.py"""
        return {
            "function_name": self.your_function,
            "another_function": self.another_function
        }
    
    def validate(self):
        """Verify all dependencies are available"""
        checks = {
            "dependency_check": self.check_dependencies(),
            "functionality_check": self.test_basic_functionality()
        }
        return {
            "status": "ok" if all(checks.values()) else "error",
            "message": "All checks passed",
            "details": checks
        }
    
    def check_dependencies(self):
        """Verify required packages/tools are installed"""
        try:
            import required_package
            return True
        except ImportError:
            return False
```

**Testing Your Plugin:**
```bash
# Test individual plugin
cd erebus_wrapper/Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules
python plugin_your_feature.py

# Test entire plugin system
python __init__.py

# View comprehensive validation report
python test_validation.py
```

**Integration with Builder:**

Plugins are automatically imported and their functions registered at build time. The builder accesses plugin functions through the plugin loader:

```python
from erebus_wrapper.erebus.modules.plugin_loader import get_plugin_loader

plugin_loader = get_plugin_loader()
my_function = plugin_loader.get_function("function_name")
result = my_function(param1, param2)
```

This fallback mechanism ensures compatibility when plugins are loaded as modules or through the plugin system.

### Modules

Modern Erebus modules are implemented as plugins. See [Plugin Development]({{< relref "plugin-development.md" >}}) for detailed information.

#### Loader Configuration Templates

Folder Location: `erebus_wrapper/agent_code/templates`

Templates use Jinja2 templating syntax for dynamic configuration. These are rendered at build time with user-supplied parameters and obfuscation values.

**config.hpp** - C++ Shellcode Loader Configuration
```cpp
// Defines for build-time configuration
#define CONFIG_TARGET_PROCESS L"{{ TARGET_PROCESS }}\0"
#define CONFIG_INJECTION_TYPE {{ INJECTION_TYPE }}
#define CONFIG_COMPRESSION_TYPE {{ COMPRESSION_TYPE }}
#define CONFIG_ENCODING_TYPE {{ ENCODING_TYPE }}
#define CONFIG_ENCRYPTION_TYPE {{ ENCRYPTION_TYPE }}

// Encryption key and IV arrays (injected from shellcrypt output)
unsigned char key[] = { {{ ENCRYPTION_KEY }} };
unsigned char iv[] = { {{ ENCRYPTION_IV }} };
```

**Available Template Variables:**
- `TARGET_PROCESS`: Target process path for injection (default: "C:\Windows\System32\notepad.exe")
- `INJECTION_TYPE`: Numeric injection type ID (1-5)
  - 1: NtQueueApcThread
  - 2: NtMapViewOfSection
  - 3: CreateFiber
  - 4: EarlyCascade
  - 5: PoolParty
- `COMPRESSION_TYPE`: Numeric compression ID (0-2)
  - 0: NONE
  - 1: LZNT1
  - 2: RLE
- `ENCODING_TYPE`: Numeric encoding ID (0-4)
  - 0: NONE
  - 1: BASE64
  - 2: ASCII85
  - 3: ALPHA32
  - 4: WORDS256
- `ENCRYPTION_TYPE`: Numeric encryption ID
  - 0: NONE
  - 1: XOR
  - 2: RC4
- `ENCRYPTION_KEY`: Comma-separated hex values for encryption key
- `ENCRYPTION_IV`: Comma-separated hex values for IV (if applicable)

**InjectionConfig.cs** - C# ClickOnce Loader Configuration
```csharp
public static class InjectionConfig 
{
    // Configuration values
    public static string TargetProcess = "{{ TARGET_PROCESS }}";
    public static string InjectionMethod = "{{ INJECTION_METHOD }}";
    public static int CompressionType = {{ COMPRESSION_TYPE }};
    public static int EncodingType = {{ ENCODING_TYPE }};
    public static int EncryptionType = {{ ENCRYPTION_TYPE }};
    
    // Encryption key and IV arrays
    public static byte[] EncryptionKey = new byte[] { {{ ENCRYPTION_KEY }} };
    public static byte[] IV = new byte[] { {{ ENCRYPTION_IV }} };
}
```

**Available Template Variables (ClickOnce):**
- `TARGET_PROCESS`: Target process for injection (default: "explorer.exe")
- `INJECTION_METHOD`: String method name
  - createfiber, earlycascade, poolparty, classic, enumdesktops, appdomain
- `COMPRESSION_TYPE`, `ENCODING_TYPE`, `ENCRYPTION_TYPE`: Same numeric mappings as C++
- `ENCRYPTION_KEY`, `ENCRYPTION_IV`: Same comma-separated hex format

**Template Rendering Process:**
1. User selects compression, encryption, and encoding options
2. Shellcrypt obfuscates the shellcode and outputs key/IV
3. Key/IV values are parsed and formatted as hex arrays
4. Template variables are populated with:
   - User parameters (injection type, target process, etc.)
   - Obfuscation type IDs (compression, encryption, encoding)
   - Extracted key and IV from shellcrypt output
5. Jinja2 renders templates with populated variables
6. Rendered config files are written to loader source directories
7. Loaders are compiled with config included as build-time constants

#### Template Usage in Builder

From `builder.py`, templates are rendered as follows:

```python
from jinja2 import Environment, FileSystemLoader

# Load Jinja2 environment
environment = Environment(loader=FileSystemLoader(templates_path))

# Get template
config_template = environment.get_template("config.hpp")

# Prepare template data
config_data = {
    "TARGET_PROCESS": "C:\\Windows\\System32\\notepad.exe",
    "INJECTION_TYPE": 1,
    "COMPRESSION_TYPE": 1,    # LZNT1
    "ENCODING_TYPE": 0,       # NONE
    "ENCRYPTION_TYPE": 1,     # XOR
}

# Render template
rendered_config = config_template.render(**config_data)

# Write to destination
with open(config_destination, "w") as f:
    f.write(rendered_config)
```

**DLL Hijacking Templates**

**proxy.def** - DLL Export Forwarding Definition
```
EXPORTS
{{ EXPORTS }}
```

Populated with extracted exports from target DLL in format:
```
FunctionName @1 NONAME
AnotherFunction @2 NONAME
```

#### Agent Code Structure

Folder Location: `erebus_wrapper/agent_code`

**Directory Layout:**
```
agent_code/
├── templates/              # Jinja2 templates for loaders
│   ├── config.hpp         # C++ loader config
│   ├── InjectionConfig.cs # C# loader config
│   └── proxy.def          # DLL proxy exports
├── shellcrypt/            # Shellcode obfuscation utility
│   ├── shellcrypt.py      # Main obfuscation script
│   ├── utils/             # Utility modules
│   └── assets/            # Obfuscation assets
├── container/             # Container specifications
│   ├── spec.json          # Container metadata
│   ├── 7z/                # 7-Zip templates
│   ├── iso/               # ISO templates
│   ├── msi/               # MSI templates
│   └── clickonce/         # ClickOnce templates
├── Erebus.Loaders/        # C++ and C# loaders
│   ├── Erebus.Loader/     # C++ Shellcode Loader
│   │   ├── Makefile       # Build configuration
│   │   ├── include/       # Header files
│   │   └── src/           # Source code
│   ├── Erebus.ClickOnce/  # .NET ClickOnce Loader
│   │   ├── Makefile       # Build configuration
│   │   ├── Properties/    # Project properties
│   │   └── *.cs           # C# source files
│   └── Erebus.Loaders.sln # Visual Studio solution
├── hijack/                # DLL Hijacking (C++)
│   ├── Makefile           # Build configuration
│   ├── main.cpp           # Main hijack logic
│   └── shellcode.hpp      # Obfuscated shellcode
├── shellcode/             # Shellcode workspace
│   ├── payload.bin        # Input shellcode from Mythic
│   └── obfuscated.bin     # Obfuscated output
├── decoys/                # Decoy files
└── Erebus.Loaders/        # Loader implementations
    └── ...
```

### Adding New Build Parameters

1. Define the parameter in the `build_parameters` list in `builder.py`
2. Ensure proper naming: `"section.number description"`
3. Add hide conditions if parameter is conditional using `HideCondition`
4. Reference parameter in build logic with `self.get_parameter("Parameter Name")`
5. Update documentation with parameter description and visibility rules

**Example:**
```python
BuildParameter(
    name = "0.9 Example Parameter",
    parameter_type = BuildParameterType.String,
    description = "Example parameter description",
    default_value = "default",
    required = True,
    hide_conditions = [
        HideCondition(name="0.0 Main Payload Type", operand=HideConditionOperand.EQ, value="Hijack"),
    ]
)
```

### Adding New Container Types

To add a new container type:

1. **Create Plugin Module**: `plugin_container_<type>.py` in `erebus_wrapper/erebus/modules/`
2. **Implement Async Function**:
   ```python
   async def build_<type>(build_path: Path, **kwargs) -> str:
       """Build container of type <type>
       
       Args:
           build_path: Path to build directory with payload files
           **kwargs: Container-specific parameters
       
       Returns:
           str: Path to created container file
       """
       # Implementation
       return output_path
   ```
3. **Register Plugin**: Implement `get_metadata()`, `register()`, and `validate()` methods
4. **Import in builder.py**:
   ```python
   try:
       from erebus_wrapper.erebus.modules.archive.container_<type> import build_<type>
   except ImportError:
       build_<type> = _plugin_loader.get_function("build_<type>")
   ```
5. **Add to containerise_payload()**: Add case statement for new container type
6. **Add Build Parameter**: Add option to "3.0 Container Type" in `build_parameters`
7. **Update Documentation**: Document container-specific parameters and behavior

**Example Container Function:**
```python
async def build_custom_container(build_path: Path, compression: int = 5, **kwargs) -> str:
    """Create custom container from payload
    
    Args:
        build_path: Path to payload directory
        compression: Compression level (0-9)
    
    Returns:
        str: Path to created container
    """
    payload_dir = build_path / "payload"
    container_path = build_path / "payload.custom"
    
    # Implementation logic
    if not container_path.exists():
        raise RuntimeError("Failed to create container")
    
    return str(container_path)
```

### Adding New Injection Methods

**For Shellcode Loader (C++ - Erebus.Loader)**:

1. **Implement Injection Technique**:
   - Add header file: `Erebus.Loader/include/injections/NewInjectionMethod.hpp`
   - Implement injection logic:
     ```cpp
     #ifndef NEW_INJECTION_METHOD_H
     #define NEW_INJECTION_METHOD_H
     
     class NewInjectionMethod : public InjectionMethod {
     public:
         bool Execute(HANDLE hProcess, void* pShellcode, SIZE_T shellcodeSize) override;
     };
     
     #endif
     ```

2. **Update config.hpp Template**:
   - Add template variable handling:
     ```cpp
     #if CONFIG_INJECTION_TYPE == 6
     #define USE_NEW_INJECTION_METHOD
     #endif
     ```

3. **Update InjectionFactory**:
   - Add case statement to create new injection type:
     ```cpp
     case 6:
         return std::make_unique<NewInjectionMethod>();
     ```

4. **Add Build Parameter**:
   ```python
   BuildParameter(
       name = "0.4 Shellcode Loader - Injection Type",
       choices = ["1", "2", "3", "4", "5", "6"],  # Add "6"
       description = "..."
   )
   ```

5. **Update Documentation**: Document the new injection type and its behavior

**For ClickOnce (.NET - Erebus.ClickOnce)**:

1. **Implement Injection Technique**:
   - Add C# class: `Erebus.ClickOnce/Injections/NewInjectionMethod.cs`
   - Implement injection logic:
     ```csharp
     public class NewInjectionMethod : IInjectionMethod {
         public bool Execute(Process targetProcess, byte[] shellcode) {
             // Implementation
             return true;
         }
     }
     ```

2. **Update InjectionConfig.cs Template**:
   - Add case statement in InjectionFactory:
     ```csharp
     case "newmethod":
         return new NewInjectionMethod();
     ```

3. **Add Build Parameter**:
   ```python
   BuildParameter(
       name = "0.6 ClickOnce - Injection Method",
       choices = ["createfiber", "earlycascade", "poolparty", "classic", "enumdesktops", "appdomain", "newmethod"],
       description = "..."
   )
   ```

4. **Update Documentation**: Document the new injection method

### Adding New Trigger Types

To add a new trigger type:

1. **Create Plugin Module**: `plugin_trigger_<type>.py` in `erebus_wrapper/erebus/modules/`
2. **Implement Async Function**:
   ```python
   async def create_<type>_payload_trigger(
       build_path: Path,
       payload_name: str,
       trigger_binary: str = None,
       trigger_command: str = None,
       **kwargs
   ) -> str:
       """Create trigger of type <type>
       
       Args:
           build_path: Path to build directory
           payload_name: Name of payload to execute
           trigger_binary: Binary to execute when triggered
           trigger_command: Command arguments
       
       Returns:
           str: Path to created trigger file
       """
       # Implementation
       return trigger_path
   ```

3. **Register Plugin**: Implement plugin base class methods

4. **Import in builder.py**:
   ```python
   try:
       from erebus_wrapper.erebus.modules.archive.trigger_<type> import create_<type>_payload_trigger
   except ImportError:
       create_<type>_payload_trigger = _plugin_loader.get_function("create_<type>_payload_trigger")
   ```

5. **Add to Trigger Logic in build()**: Add condition branch in trigger section:
   ```python
   elif self.get_parameter("0.9 Trigger Type") == "NewType":
       await create_newtype_payload_trigger(
           build_path=Path(agent_build_path),
           payload_name="payload_file",
           trigger_binary=self.get_parameter("0.9a Trigger Binary"),
           trigger_command=self.get_parameter("0.9b Trigger Command")
       )
   ```

6. **Add Build Parameter**:
   ```python
   BuildParameter(
       name = "0.9 Trigger Type",
       choices = ["LNK", "BAT", "MSI", "ClickOnce", "NewType"],
       description = "..."
   )
   ```

7. **Update Documentation**: Document trigger type and behavior

**Example Trigger Function:**
```python
async def create_custom_payload_trigger(
    build_path: Path,
    payload_name: str,
    **kwargs
) -> str:
    """Create custom trigger file"""
    payload_dir = build_path / "payload"
    trigger_path = payload_dir / f"trigger.custom"
    
    # Build trigger content
    trigger_content = f"""
    # Custom trigger for {payload_name}
    # Implementation
    """
    
    # Write trigger file
    trigger_path.write_text(trigger_content)
    
    return str(trigger_path)
```

### Adding New Obfuscation Methods

To add new compression, encryption, or encoding methods:

1. **Update Shellcrypt**: Add support in `agent_code/shellcrypt/shellcrypt.py`
2. **Update builder.py Mappings**:
   ```python
   COMPRESSION_METHODS = {
       "LZNT1": "lznt",
       "RLE": "rle",
       "DEFLATE": "deflate",  # New method
       "NONE": ""
   }
   
   COMPRESSION_TYPE_MAP = {
       "NONE": 0,
       "LZNT1": 1,
       "RLE": 2,
       "DEFLATE": 3,  # New mapping
   }
   ```
3. **Update Loaders**: Implement decompression/decryption/decoding logic
4. **Update Templates**: Add conditional sections for new obfuscation type
5. **Add Build Parameter**: Add option to obfuscation parameter
6. **Update Documentation**: Document the new method

## Configuration Workflow

During the build process:

1. **Shellcode Obfuscation**: Raw shellcode is processed through shellcrypt with user options
2. **Loader Configuration**:
   - **Shellcode Loader (C++)**:
     - `config.hpp` template is rendered with injection type and target process
     - Written to `Erebus.Loader/include/config.hpp`
     - Compiled using CMake with specified build configuration
   - **ClickOnce (.NET)**:
     - `InjectionConfig.cs` template is rendered with injection method and target process
     - Encryption key extracted from obfuscation and included as byte array
     - Written to `Erebus.ClickOnce/InjectionConfig.cs`
     - Compiled using Makefile with CONFIG and RID parameters
     - Makefile targets:
       - `publish`: Builds release binary and runs cleanup script
       - `release`: Publishes with PublishSingleFile, SelfContained, and PublishTrimmed
       - `cleanup`: Removes debug symbols and unnecessary runtime files
3. **Compilation**: Loaders are compiled with their respective configurations
   - Output directory for ClickOnce: `bin/{CONFIG}/{TFM}/{RID}/publish`
   - All debug symbols (.pdb files) removed by cleanup script
4. **Trigger Setup** (if Output Extension Source = Trigger):
   - **LNK Trigger**: Creates .lnk shortcut that executes trigger binary with command arguments and displays decoy
   - **BAT Trigger**: Generates batch script that executes payload and shows decoy file
   - **MSI Trigger**: Embeds trigger into MSI package with execution conditions
   - **ClickOnce Trigger**: Creates ClickOnce deployment manifests for trusted code execution
     - Generates .application deployment manifest (entry point)
     - Generates .exe.manifest application manifest (assembly identity)
     - Calculates SHA256 hashes and file sizes for integrity verification
     - Reference: https://specterops.io/blog/2023/06/07/less-smartscreen-more-caffeine-abusing-clickonce-for-trusted-code-execution/
5. **MalDoc Creation** (if Output Extension Source = MalDoc):
   - Creates new XLSM document or backdoors existing Excel file
   - Embeds VBA payload with selected execution trigger (AutoOpen/OnClose/OnSave)
   - Applies VBA obfuscation if enabled
   - Supports Command Execution or Shellcode Injection modes
6. **Containerization**: Final payload is packaged into selected container format
7. **Code Signing**: (Optional) Payload is signed with certificate

## Trigger System Details

### LNK Trigger
- Creates a `.lnk` (Windows shortcut) file
- Executes specified trigger binary with command arguments
- Displays decoy file when activated
- Files: `trigger_lnk.py`

### BAT Trigger
- Generates a batch script (`.bat` file)
- Executes trigger binary and command arguments in sequence
- Can display decoy file
- Files: `trigger_bat.py`

### MSI Trigger
- Embeds execution trigger within MSI custom actions
- Respects MSI execution conditions (install, repair, uninstall)
- Supports command execution or binary launch
- Files: `trigger_msi.py`

## Build Step Tracking

The builder reports progress through build steps:
- Gathering Files
- Header Check
- Shellcode Obfuscation
- Gathering DLL Exports for Hijacking (DLL hijack only)
- Compiling DLL Payload (DLL hijack only)
- Compiling Shellcode Loader (Shellcode Loader)
- Compiling ClickOnce Loader (ClickOnce)
- Sign Shellcode Loader (optional)
- Backdooring MSI (MSI container with backdoor file)
- Adding Trigger (LNK, BAT, or MSI trigger)
- Creating Decoy (LNK trigger with decoy file)
- Containerising

Each step includes stdout/stderr output and success/failure status for debugging.

### ClickOnce Trigger
- Creates ClickOnce deployment manifests (.application file)
- Leverages trusted ClickOnce execution model for code delivery
- Can bypass SmartScreen warnings through trusted publisher model
- Creates proper XML manifests for deployment:
    - Application manifest (.exe.manifest) - Describes assembly and file dependencies
    - Deployment manifest (.application) - Entry point for ClickOnce deployment
- Supports auto-installation and execution
- Files: `trigger_clickonce.py`
- Reference: https://specterops.io/blog/2023/06/07/less-smartscreen-more-caffeine-abusing-clickonce-for-trusted-code-execution/
