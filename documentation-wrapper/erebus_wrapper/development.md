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
- **Trigger Mechanisms**: LNK-based triggers with decoy files
- **DLL Hijacking**: Proxy-based DLL hijacking capability

## High Level Flow Chart

![High Level Flow Chart of Erebus' Workflow](/wrappers/erebus_wrapper/flow.png)

## Build Workflow

### 1. Payload Type Selection
- **Loader**: Uses Shellcode Loader or ClickOnce
- **Hijack**: Uses DLL proxy hijacking

### 2. Shellcode Obfuscation (Shellcrypt Phase)
- **Input**: Raw shellcode binary from Mythic
- **Compression**: LZNT1, RLE, or NONE
- **Encryption**: AES128_CBC, AES256_CBC, AES256_ECB, CHACHA20, SALSA20, XOR, XOR_COMPLEX
- **Encoding**: ALPHA32, ASCII85, BASE64, WORDS256, or NONE
- **Output Format**: C, CSharp, Nim, Go, Python, PowerShell, VBA, VBScript, Rust, JavaScript, Zig, or Raw

### 3. Loader Compilation
- **Shellcode Loader**: C++ executable/DLL with configurable injection
- **ClickOnce**: .NET application with manifests
- Configuration applied based on user parameters

### 4. Optional Container & Trigger
- Package in ISO, 7z, ZIP, or MSI
- Create LNK trigger with decoy execution
- Sign with selected certificate

### 5. Delivery
- Output final packaged payload

## Build Parameters Reference

### Main Payload Selection (Section 0.0)
- **0.0 Main Payload Type**: Choose "Loader" or "Hijack"
- **0.1 Loader Type**: Select "Shellcode Loader" or "ClickOnce" (Loader only)

### Shellcode Loader Configuration (Section 0.3-0.5)
- **0.3 Loader Build Configuration**: Debug or Release build
- **0.4 Shellcode Loader - Injection Type**:
  - 1 = NtQueueApcThread (APC injection to suspended thread - Remote)
  - 2 = NtMapViewOfSection (Section mapping injection - Remote)
  - 3 = CreateFiber (Fiber-based execution - Self)
  - 4 = EarlyCascade (Early Bird APC injection - Remote)
  - 5 = PoolParty (Worker Factory thread pool injection - Remote)
- **0.5 Shellcode Loader - Target Process**: Process name for remote injection

### ClickOnce Configuration (Section 0.3 & 0.6-0.7)
- **0.3 ClickOnce Build Configuration**: Debug or Release build
- **0.6 ClickOnce - Injection Method**:
  - createfiber: Fiber-based self-injection
  - earlycascade: Early Bird APC injection (remote)
  - poolparty: Worker Factory thread pool injection (remote)
  - classic: Classic CreateRemoteThread injection (remote)
  - enumdesktops: EnumDesktops callback injection (self)
- **0.7 ClickOnce - Target Process**: Target process for remote injection

### DLL Hijacking (Section 1.0)
- **1.0 DLL Hijacking**: Upload DLL for proxy-based hijacking (requires C format shellcode)

### Trigger Configuration (Section 0.8-0.10)
- **0.8 Trigger Binary**: Executable to run when trigger is activated
- **0.9 Trigger Command**: Command arguments to pass
- **0.10 Decoy File**: Optional decoy file (PDF/XLSX/etc.)

### Shellcrypt Options (Section 2.0-2.5)
- **2.0 Compression Type**: LZNT1, RLE, or NONE
- **2.1 Encryption Type**: Select encryption algorithm
- **2.2 Encryption Key**: Custom key or auto-generate
- **2.3 Encoding Type**: ALPHA32, ASCII85, BASE64, WORDS256, or NONE
- **2.4 Shellcode Format**: Output format for obfuscated shellcode
- **2.5 Shellcode Array Name**: Variable name for shellcode array (non-raw formats)

### Container Options (Section 3.0-3.2)
- **3.0 Container Type**: ISO, 7z, ZIP, or MSI
- **3.1 Compression Level**: 0-9 (9 = max)
- **3.2 Archive Password**: Optional archive password

### ISO-Specific Options (Section 4.0-4.2)
- **4.0 ISO Volume ID**: Volume name in Explorer
- **4.1 ISO Enable Autorun**: Enable AutoRun.inf
- **4.2 ISO Backdoor File**: Existing ISO to modify

### MSI-Specific Options (Section 5.0-5.3)
- **5.0 MSI Product Name**: Application name in MSI
- **5.1 MSI Manufacturer**: Company name
- **5.2 MSI Install Scope**: User (AppData) or Machine (Program Files)

### Code Signing (Section 6.0-6.6)
- **6.0 Codesign Loader**: Enable/disable code signing
- **6.1 Codesign Type**: SelfSign, Spoof URL, or Provide Certificate
- **6.2 Codesign CN**: Common Name for self-signed cert
- **6.3 Codesign Orgname**: Organization name
- **6.4 Codesign Spoof URL**: URL to clone cert from
- **6.5 Codesign Cert**: PFX/P12 certificate file
- **6.6 Codesign Cert Password**: Certificate password

## Adding Features

### Modules
#### Module Template
Folder Location: `erebus_wrapper/erebus/modules`

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

## Configuration Workflow

During the build process:

1. **Shellcode Obfuscation**: Raw shellcode is processed through shellcrypt with user options
2. **Loader Configuration**:
   - `config.hpp` template is rendered with injection type and target process
   - Written to `Erebus.Loader/include/config.hpp`
   - `InjectionConfig.cs` template is rendered with injection method and target process
   - Encryption key is extracted from obfuscation and included
   - Written to `Erebus.ClickOnce/InjectionConfig.cs`
3. **Compilation**: Loaders are compiled with their respective configurations
4. **Containerization**: Final payload is packaged
5. **Code Signing**: (Optional) Payload is signed with certificate

## Build Step Tracking

The builder reports progress through build steps:
- Gathering Files
- Header Check
- Shellcode Obfuscation
- Configuring Shellcode Loader / ClickOnce Loader
- Compiling Shellcode Loader / DLL / ClickOnce
- Sign Shellcode Loader (optional)
- Adding Trigger
- Creating Decoy
- Containerising

Each step includes stdout/stderr output and success/failure status for debugging.
