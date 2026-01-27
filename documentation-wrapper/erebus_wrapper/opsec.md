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
