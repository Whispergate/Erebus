+++
title = "OPSEC"
chapter = false
weight = 4
pre = "<b>4. </b>"
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

**RC4**
- Stream cipher with variable-length key
- Fast encryption/decryption
- Per-session key generated
- Moderate security level
- **Supported** ✓

**XOR**
- Multi-byte XOR encryption
- Minimal performance overhead
- Key applied cyclically across shellcode
- **Supported** ✓

**AES-ECB**
- AES in Electronic Codebook mode
- 128/192/256-bit key support via BCrypt
- Stateless block cipher (no IV required)
- **Supported** ✓

**AES-CBC**
- AES in Cipher Block Chaining mode
- 128/192/256-bit key with per-build IV
- Stronger than ECB (chained blocks prevent pattern leakage)
- IV/nonce embedded in shellcode.hpp alongside key
- **Supported** ✓

**Current Recommendation**: Use **RC4** for most scenarios (good balance of performance and security). Use **AES-CBC** for high-security environments. Use **XOR** only for testing or basic obfuscation.

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
2. **Encryption**: AES-CBC (strong cryptography with IV)
3. **Encoding**: ALPHA32 (alphanumeric obfuscation)
4. **Custom Key**: User-supplied or generated (not default)

**Result**: Shellcode is compressed, encrypted with AES-CBC, then encoded to alphanumeric characters. Extremely difficult to detect or analyze without decryption key.

**Performance-Optimized Configuration:**
1. **Compression**: NONE
2. **Encryption**: RC4 (fast stream cipher)
3. **Encoding**: NONE
4. **Custom Key**: Generated

**Result**: Minimal overhead while maintaining encryption.

---

## Custom Shellcode (External C2)

Erebus can use raw shellcode from any external C2 instead of (or in addition to) the Mythic-wrapped payload. Enable via the `0.0a Enable Custom Shellcode` parameter and upload the raw binary via `0.0b Custom Shellcode File`.

**How It Works**
- When enabled, the uploaded file is written to `shellcode/payload.bin` in the build tree, overriding the Mythic-generated shellcode entirely.
- The rest of the pipeline (MZ-header check, shellcrypt obfuscation, loader compilation) runs unchanged against the custom blob.
- The Mythic-wrapped payload selection is ignored but still required by the Mythic UI.

**Supported Sources**
- Cobalt Strike - export a raw shellcode payload (stageless, `.bin`)
- Havoc - export a raw shellcode blob
- Sliver - use `generate --format shellcode`
- msfvenom - `msfvenom -f raw -o payload.bin ...`
- Any other C2 that exports position-independent shellcode as a raw binary

**Constraints**
- The file **must** be raw shellcode - PE files (MZ header `\x4d\x5a`) are rejected and the build will fail with a clear error.
- Architecture must match the selected loader architecture (x64 vs x86).
- All obfuscation parameters (encryption, compression, encoding) apply normally to the custom shellcode.

**OPSEC Notes**
- Custom shellcode is not wrapped in the Mythic callback infrastructure, so Mythic will not receive a callback - this is expected when targeting an external C2.
- Ensure the shellcode format matches the loader expectations (raw, not base64 or hex-encoded).

---

## MalDocs (Excel VBA) OPSEC Considerations

**Build Pipeline**
- The builder compiles the Excel document (XLSM/XLSX/XLAM) directly on Linux using the template files from `agent_code/templates/`. The VBA payload is injected via ZIP-level manipulation with a compiled `vbaProject.bin` produced by the built-in VBA compiler (`agent_code/vba_compiler/`).
- A `.bas` file and `build_maldoc.bat` are also included in the payload directory for optional Windows-side COM re-injection via `erebus_helper.py` when higher-fidelity output is needed.
- When "Backdoor Existing" is selected without uploading an Excel file, the builder falls back to the appropriate template automatically.

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

**Dynamic Payload Discovery**

When using Command Execution mode, the generated VBA resolves the payload location at runtime rather than using a hardcoded path. The `FindPayload` VBA function searches the following locations in order:

1. `CurDir$` - current working directory of the Excel process
2. `ThisWorkbook.Path` - same directory as the document
3. `%TEMP%` / `%TMP%`
4. `%APPDATA%` / `%LOCALAPPDATA%`
5. `%USERPROFILE%\Desktop`, `\Downloads`, `\Documents`
6. `%USERPROFILE%` root
7. OneDrive-synced Desktop, Downloads, Documents (`%OneDrive%`)

Both a direct existence check (`fso.FileExists`) and a recursive subfolder search are performed per candidate. This covers OneDrive-redirected shell folders (common on modern Windows where Desktop/Downloads live under `%OneDrive%` rather than `%USERPROFILE%`).

If the payload is found, its full path is quoted with `Chr(34)` and substituted back into the shell command. The macro exits silently if the file cannot be found, avoiding a RegSvr32 / process-launch error dialog that could alert the user.

**OPSEC Note**: `Scripting.FileSystemObject` is a common macro dependency and is not inherently suspicious, but recursive filesystem enumeration from EXCEL.EXE may trigger behavioral heuristics in advanced EDR products. Consider pairing with a short `Application.Wait` delay before the search.

**VBA Loader Techniques**

Erebus provides four VBA shellcode loader techniques with different detection profiles:

1. **VirtualAlloc + CreateThread** (Classic)
   - **Detection**: High - well-known pattern, heavily monitored
   - **Stealth**: Low - CreateThread is suspicious from Office process
   - **Reliability**: Very High - works on all Office versions
   - **OPSEC**: 
     - Commonly flagged by EDR/AV
     - VirtualAlloc with RWX protection is suspicious
     - Thread creation from EXCEL.EXE raises alerts
   - **Use When**: Testing or targeting environments without EDR
   - **Mitigation**: Combine with VBA obfuscation and staged delivery

2. **EnumSystemLocalesA Callback**
   - **Detection**: Medium - less common, bypasses basic static analysis
   - **Stealth**: Medium - legitimate API with callback mechanism
   - **Reliability**: High on modern systems
   - **OPSEC**:
     - EnumSystemLocalesA is legitimate Windows API
     - Callback mechanism avoids explicit CreateThread
     - May bypass signature-based detection
     - Behavioral analysis may still catch execution
   - **Use When**: Need better evasion than CreateThread
   - **Mitigation**: Monitor for abnormal EnumSystemLocalesA behavior

3. **QueueUserAPC Injection**
   - **Detection**: Medium-Low - APC-based execution less monitored in VBA context
   - **Stealth**: Medium-High - no new thread creation
   - **Reliability**: High (requires alertable wait state)
   - **OPSEC**:
     - Executes in current thread context
     - No suspicious thread creation from Office
     - APC queuing to self is less suspicious than remote APC
     - Sleep(1) triggers APC execution automatically
   - **Use When**: Targeting environments with thread creation monitoring
   - **Mitigation**: Watch for APC queue operations from EXCEL.EXE

4. **Process Hollowing** (notepad.exe)
   - **Detection**: Medium-High - creates external process
   - **Stealth**: High - payload runs in separate process
   - **Reliability**: High
   - **OPSEC**:
     - Spawns notepad.exe from EXCEL.EXE (suspicious parent-child)
     - VirtualAllocEx and WriteProcessMemory are monitored APIs
     - Suspended process creation is red flag
     - Payload isolation reduces direct attribution to Excel
   - **Use When**: Need process isolation and advanced evasion
   - **Mitigation**: Parent process monitoring, memory write detection
   - **Alternative Hosts**: Consider svchost.exe, RuntimeBroker.exe

**Loader Selection Guidance:**
- **Unmonitored Environment**: VirtualAlloc (simple, reliable)
- **Basic AV/Signature Detection**: EnumLocales (bypasses simple patterns)
- **EDR with Thread Monitoring**: QueueUserAPC (no thread creation)
- **Advanced EDR/Behavioral Analysis**: Process Hollowing (process isolation)
- **Maximum Stealth**: Combine Process Hollowing + VBA Obfuscation + Delayed Execution

**General VBA OPSEC:**
- Always enable VBA obfuscation (parameter 7.5)
- Test loader selection against target environment
- Consider staged execution (download-then-execute vs. embedded shellcode)
- Monitor for Office process anomalies during testing

**Operational Risk**
- Macro-based delivery is high-visibility in monitored environments.
- Use only when tradecraft and campaign constraints allow.

---

## Injection Methods & OPSEC

### Shellcode Loader Injection Types (C++)

**Type 1: NtMapViewOfSection**
- **Method**: Section mapping injection
- **Scope**: Remote process injection
- **Detection**: Advanced - checks for mapped sections
- **OPSEC**: Monitor kernel calls, section object activity
- **Stealth**: High - legitimate Windows API usage
- **Reliability**: High on modern Windows
- **Recommended Targets**: explorer.exe, winlogon.exe

**Type 2: CreateFiber**
- **Method**: Fiber-based self-injection
- **Scope**: Self-injection (same process)
- **Detection**: Low - fibers are uncommon
- **OPSEC**: Less suspicious than remote injection
- **Stealth**: Very High - legitimate Windows mechanism
- **Reliability**: High
- **Recommended Targets**: Self-injection only (DLL hijack context)

**Type 3: EarlyCascade (Early Bird APC)**
- **Method**: NtQueueApcThread injection before process initialization
- **Scope**: Remote process injection
- **Detection**: Advanced - before execution monitoring may miss it
- **OPSEC**: Injects before main thread begins, APC queued to suspended thread
- **Stealth**: Very High - injection happens before typical monitoring
- **Reliability**: High on unprepared systems
- **Recommended Targets**: notepad.exe, cmd.exe, rundll32.exe

**Type 4: PoolParty**
- **Method**: Worker Factory thread pool injection via IoCompletion port
- **Scope**: Remote process injection (existing process with thread pool)
- **Detection**: Very Advanced - thread pool monitoring required
- **OPSEC**: Uses worker factory mechanism, no new thread creation
- **Stealth**: Very High - uncommon detection
- **Reliability**: High on modern Windows versions
- **Target Requirements**: Process must have an active thread pool (IoCompletion handle)
- **Recommended Targets**: RuntimeBroker.exe, fontdrvhost.exe, dllhost.exe, sihost.exe

**Recommendation**: Use EarlyCascade or PoolParty for maximum stealth, CreateFiber for self-injection scenarios (DLL hijacking).

### Loader Memory Handling

The shellcode loader implements several OPSEC-hardened memory practices:

- **VirtualAlloc staging**: Shellcode staging buffer uses `VirtualAlloc` instead of `malloc` to avoid CRT heap metadata that leaks allocation sizes to forensic tools.
- **Key material scrubbing**: Decryption keys are copied to a stack buffer and zeroed with `SecureZeroMemory` immediately after use.
- **Post-injection cleanup**: The staging buffer is zeroed with `SecureZeroMemory` and freed after injection completes, preventing shellcode recovery from the loader's address space.
- **RC4 S-box scrubbing**: The RC4 key schedule (S-box) is zeroed after decryption to prevent key recovery from memory dumps.
- **Remote allocation cleanup**: Failed write or protection-change operations free the remote allocation via `NtFreeVirtualMemory`, preventing forensic artifacts in the target process.
- **Jittered delays**: All post-injection sleep intervals use jittered timing (`base + GetTickCount() % jitter`) to avoid fixed-interval detection signatures.

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

### MSC (GrimReaper) Triggers

**Mechanism:**
- Microsoft Management Console snap-in file
- Leverages MMC for payload execution
- Appears as legitimate system administration tool

**OPSEC Considerations:**
- MSC files are trusted by default on Windows
- Execution through MMC provides legitimate process tree
- Less commonly monitored than LNK or BAT triggers

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
