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
         │  │ Encryption: AES*/CHACHA20   │ │
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
- **Encryption**: AES128_CBC, AES256_CBC, AES256_ECB, RC4, or XOR
  - Additional options (TODO): CHACHA20, SALSA20, XOR_COMPLEX
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
  - **Requirements**: Shellcode Format must be set to C
  - **Note**: v0.0.1 only supports XOR encryption - does not currently support encoded or compressed payloads

### Output Extension Source (Section 0.8)
- **0.8 Output Extension Source**: Choose whether the visible file extension comes from Trigger or MalDoc
  - Trigger: Use LNK/BAT/MSI/ClickOnce trigger files
  - MalDoc: Use Excel document with VBA payload

### Trigger Configuration (Section 0.9-0.9b)
- **0.9 Trigger Type**: Select trigger mechanism - LNK, BAT, MSI, or ClickOnce
  - Only visible when Output Extension Source = Trigger
- **0.9a Trigger Binary**: Executable to run when trigger is activated (default: C:\Windows\System32\conhost.exe)
  - Hidden for MSI and ClickOnce triggers
- **0.9b Trigger Command**: Command arguments to pass (default: --headless cmd.exe /Q /c erebus.exe | decoy.pdf)
  - Hidden for MSI and ClickOnce triggers

### MalDoc Configuration (Section 0.9-0.9g)
- **0.9 Create MalDoc**: None, Create/Backdoor Excel, or VBA Module Only
  - Only visible when Output Extension Source = MalDoc
- **0.9a MalDoc Type**: Create New or Backdoor Existing
- **0.9b Excel Source File**: Upload existing Excel file to backdoor (XLSM/XLS/XLAM)
  - Only visible when MalDoc Type = Backdoor Existing
- **0.9c VBA Execution Trigger**: AutoOpen, OnClose, or OnSave (default: AutoOpen)
- **0.9d Excel Document Name**: Name/title for Excel document (default: Invoice)
- **0.9e Obfuscate VBA**: Boolean - obfuscate VBA code for evasion (default: True)
- **0.9f MalDoc Injection Type**: Command Execution or Shellcode Injection
- **0.9g VBA Loader Technique**: VirtualAlloc + CreateThread, EnumSystemLocalesA Callback, QueueUserAPC Injection, or Process Hollowing
  - Only visible when MalDoc Injection Type = Shellcode Injection

### Decoy File (Section 0.13)
- **0.13 Decoy File Inclusion**: Boolean - include decoy file in final payload (default: False)
- **0.13 Decoy File**: Upload decoy file (PDF/XLSX/etc.) - if none uploaded, example file is used

### Shellcrypt Options (Section 2.0-2.4)
- **2.0 Compression Type**: LZNT1, RLE, or NONE
- **2.1 Encryption Type**: AES128_CBC, AES256_CBC, AES256_ECB, RC4, or XOR
  - Note: CHACHA20, SALSA20, and XOR_COMPLEX are currently disabled (TODO: Add decryption support to loaders)
- **2.2 Encryption Key**: Custom key or "NONE" for auto-generate
- **2.3 Encoding Type**: ALPHA32, ASCII85, BASE64, WORDS256, or NONE
- **2.4 Shellcode Format**: C, CSharp, or Raw
  - Note: Nim, Go, Python, PowerShell, VBA, VBScript, Rust, JavaScript, and Zig formats commented out (uncomment for custom loaders)

### Container Options (Section 3.0-3.2)
- **3.0 Container Type**: ISO, 7z, ZIP, or MSI
- **3.1 Compression Level**: 0-9 (9 = max)
- **3.2 Archive Password**: Optional archive password

### ISO-Specific Options (Section 4.0-4.2)
- **4.0 ISO Volume ID**: Volume name in Explorer
- **4.1 ISO Enable Autorun**: Enable AutoRun.inf
- **4.2 ISO Backdoor File**: Existing ISO to modify

### MSI-Specific Options (Section 5.0-5.8)
- **5.0 MSI Product Name**: Application name shown in MSI/UI
- **5.1 MSI Manufacturer**: Company name shown in MSI metadata
- **5.2 MSI Install Scope**: User (AppData) or Machine (Program Files)
- **5.3 MSI Backdoor File**: Existing MSI to modify and inject payload
- **5.4 MSI Attack Type**: Attack vector for backdoor injection
  - execute: Run command via CustomAction (stealthiest)
  - run-exe: Extract and execute EXE from Binary table
  - load-dll: Load native DLL via DllEntry
  - dotnet: Load .NET assembly (auto-detected)
  - script: Execute VBScript/JScript
- **5.5 MSI Entry Point**: DLL export or script function name (for load-dll/dotnet/script attacks)
- **5.6 MSI Command Arguments**: Command line arguments for execute/run-exe attacks
- **5.7 MSI Execution Condition**: MSI condition for payload execution (default: NOT REMOVE = install only)
- **5.8 MSI Custom Action Name**: Custom action identifier (auto-generated if empty)

### Code Signing (Section 6.0-6.6)
- **6.0 Codesign Loader**: Enable/disable code signing
- **6.1 Codesign Type**: SelfSign, Spoof URL, or Provide Certificate
- **6.2 Codesign CN**: Common Name for self-signed cert
- **6.3 Codesign Orgname**: Organization name
- **6.4 Codesign Spoof URL**: URL to clone cert from
- **6.5 Codesign Cert**: PFX/P12 certificate file
- **6.6 Codesign Cert Password**: Certificate password



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

### Modules
#### Module Template (Legacy)
Folder Location: `erebus_wrapper/erebus/modules`

**Note:** Modern modules are implemented as plugins. See [Plugin Development]({{< relref "plugin-development.md" >}}) for the current approach.

```python
import pefile, asyncio
#↬ Use async/await as done in the Mythic class
async def module_name(param1: str, param2: int, **param3: any) -> str:
    """Do something

    Args:
        param1 (str): Do something
        param2 (int): Do something
    
    Raises:
        Exception: Value Error
    
    Returns:
        str: Returns some string
    """
    try:
        addition = param1 + param2
    except ValueError:
        raise Exception("Incorrect Value")

    return addition    

if __name__ == "__main__": # <-- Test functionality by running the module alone before importing it
    addition = asyncio.run(module_name("number", 1))
    print(addition)
```

**Best Practices:**
- Always use `async/await` pattern for consistency with Mythic
- Test modules independently before importing
- Include comprehensive docstrings
- Handle exceptions gracefully
- Return appropriate types

#### Agent Templates
Folder Location: `erebus_wrapper/agent_code/templates`

Templates use Jinja2 templating syntax for dynamic configuration:

**config.hpp** - C++ Loader Configuration
```cpp
#define CONFIG_TARGET_PROCESS L"{{ TARGET_PROCESS }}\0"
#define CONFIG_INJECTION_TYPE {{ INJECTION_TYPE }}
```

**InjectionConfig.cs** - C# ClickOnce Configuration
```csharp
public static string InjectionMethod = "{{ INJECTION_METHOD }}";
public static string TargetProcess = "{{ TARGET_PROCESS }}";
public static byte[] EncryptionKey = new byte[] { {{ ENCRYPTION_KEY }} };
```

Templates are rendered at build time with user-supplied parameters.

### Adding New Build Parameters

1. Define the parameter in the `build_parameters` list in `builder.py`
2. Ensure proper naming: `"section.number description"`
3. Add hide conditions if parameter is conditional
4. Reference parameter in build logic with `self.get_parameter("Parameter Name")`

### Adding New Container Types

1. Create a new module `container_<type>.py` in `erebus_wrapper/erebus/modules/`
2. Implement async function matching signature: `async def build_<type>(**kwargs) -> str`
3. Import and add to builder's containerise_payload method
4. Add build parameter for container selection

### Adding New Injection Methods

For **Shellcode Loader (C++)**:
1. Implement injection function in Erebus.Loaders C++ codebase
2. Add case statement in `config.hpp` template
3. Add option to "0.4 Shellcode Loader - Injection Type" parameter

For **ClickOnce (.NET)**:
1. Implement injection method in Erebus.Loaders C# codebase
2. Add option to "0.6 ClickOnce - Injection Method" parameter
3. Update `InjectionConfig.cs` template to handle new method

### Adding New Trigger Types

1. Create a new module `trigger_<type>.py` in `erebus_wrapper/erebus/modules/`
2. Implement async function matching signature: `async def create_<type>_payload_trigger(**kwargs) -> str`
3. Import the function in `builder.py`
4. Add condition to builder's trigger logic to handle the new type
5. Add option to "7.0 Trigger Type" parameter in `build_parameters`

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
