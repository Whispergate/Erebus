+++
title = "OPSEC"
chapter = false
weight = 4
pre = "<b>4. </b>"
+++

## How to read this document

Every component in the Erebus pipeline has two audiences:

- **Operators** - pentesters and red teamers *using* the feature on an engagement.
- **Developers** - contributors hardening the feature inside the Erebus codebase.

Each section below is structured uniformly so both audiences can scan it:

- A one-line mechanism summary
- **OPSEC Considerations** - the artefacts, telemetry, and failure modes that will actually get the operator caught. This is *not* a ranking of how "stealthy" the technique is; it is a list of the concrete defender signals the technique produces.
- **Improvements - For Operators** - tradecraft decisions the operator makes when *using* the feature.
- **Improvements - For Erebus Developers** - code-level hardening work that would reduce the component's OPSEC surface inside the repo.

There is no ranking of "stealth levels" anywhere below. If a component is riskier than another, that emerges from the length and severity of its Considerations list - not from marketing adjectives.

---

## Shellcode Obfuscation (Shellcrypt)

Shellcrypt is the Python-based obfuscation pipeline that transforms raw shellcode through a configurable chain of compression → encryption → encoding → output formatting stages before the loader embeds it.

### Compression: LZNT1

*LZNT1 is the compression format used by `RtlCompressBuffer`; a Python port at `agent_code/shellcrypt/` runs it pre-build, and the loader decompresses at runtime.*

**OPSEC Considerations**
- Compressed shellcode no longer matches raw-byte YARA rules, but its entropy profile is still distinguishable from natural data - entropy-based heuristics on packed `.text` sections can flag it.
- Runtime decompression materialises the plaintext shellcode in memory at a predictable point in loader execution, which is a reliable hook target for memory scanners.
- The loader needs to link the LZNT1 decompressor, which shows up as recognisable function shape in static analysis.

**Improvements - For Operators**
- Pair LZNT1 with an encryption stage so the compressed bytes are not exposed inside the loader image; compression alone is not a security layer.
- If the payload is already small (< 4 KB typical shellcode), the compression win is marginal and the extra decompressor code is more attack surface than it's worth - pick `NONE`.

**Improvements - For Erebus Developers**
- Add a second compressor option that's less common than LZNT1 (APLib / LZNT2 / Brotli) so the decompressor routine isn't identical across every Erebus build.
- Scrub the compressed buffer with `SecureZeroMemory` after decompression (currently only the plaintext post-decrypt is scrubbed).

### Compression: RLE

*Simple run-length encoding implemented in-line in the loader.*

**OPSEC Considerations**
- RLE's output is highly recognisable - its byte-pair structure is obvious to anyone glancing at it with a hex editor.
- Size reduction is negligible for non-repetitive shellcode, so the defender gains more than the operator.

**Improvements - For Operators**
- Avoid for production; use `LZNT1` or `NONE`. RLE's only real use is as a debug stage to verify the decompressor pipeline works.

**Improvements - For Erebus Developers**
- Consider deprecating the `RLE` option, or restrict it to test-builds behind a flag so it doesn't leak into operational payloads.

### Compression: NONE

*No compression - the encryption stage operates on the raw shellcode directly.*

**OPSEC Considerations**
- The shellcode's own structural fingerprints (`\xfc\x48\x83\xe4\xf0`, etc. for MSF-family) are preserved through encryption; if the encryption layer is weak the original shellcode can still be recovered.

**Improvements - For Operators**
- Always enable a strong encryption stage when `COMPRESSION_TYPE = NONE` so the loader image doesn't leak recognisable byte patterns.

**Improvements - For Erebus Developers**
- No action needed; `NONE` is the correct default when compression buys nothing.

### Encryption: RC4

*RC4 stream cipher with a per-build random key (default in Shellcrypt). The loader scrubs the S-box after use (see [Loader Memory Handling](#loader-memory-handling)).*

**OPSEC Considerations**
- The key and S-box exist in loader memory during decryption; any scanner that dumps the loader's heap between shellcrypt decode and injection will recover both.
- RC4 is cryptographically broken for long-term confidentiality but more than enough for loader-lifetime obfuscation - the real risk is the key being embedded in `.rdata`.

**Improvements - For Operators**
- Use a custom key via `2.2 Encryption Key` rather than the auto-generated one, and reuse keys across a campaign only if you're confident the loaders won't be mass-sampled together.
- Rotate the key per build if the engagement has repeated deliveries to the same victim environment.

**Improvements - For Erebus Developers**
- The S-box is already scrubbed after use - good. Next step: make the key material live on the stack (`alloca`) rather than a global array so it doesn't appear in `.rdata` strings.
- Add compile-time key derivation (XOR the literal key with a per-build nonce baked into the loader) so two loaders built from the same source don't share a static key signature.

### Encryption: XOR

*Multi-byte XOR with a cyclically applied key.*

**OPSEC Considerations**
- XOR with a short key is trivial to recover via known-plaintext attack once the defender has a single loader + its shellcode (e.g. from a sandbox run).
- The key pattern is visible in the `.rdata` section as-is.

**Improvements - For Operators**
- Use for testing only; prefer RC4 or AES for anything that will be delivered.
- If forced to use XOR (e.g. size constraints on a minimal loader), combine it with `LZNT1` so at least the pre-XOR bytes aren't recognisable.

**Improvements - For Erebus Developers**
- Consider adding an XOR variant that uses a per-byte position-dependent derived key (LCG-style) rather than a flat repeating key; the loader code delta is tiny and it breaks trivial single-byte XOR scanners.

### Encryption: AES-ECB

*AES in Electronic Codebook mode via BCrypt. No IV required.*

**OPSEC Considerations**
- ECB leaks block-level repetition patterns - any 16-byte block that repeats in the plaintext shellcode produces an identical ciphertext block. For short shellcodes this rarely matters, but for larger staged loaders it's a visible pattern.
- The loader needs to link `bcrypt.dll` which is a strong indicator of cryptographic work on an otherwise simple process.

**Improvements - For Operators**
- Prefer AES-CBC - there is no upside to ECB for shellcode obfuscation.

**Improvements - For Erebus Developers**
- Document AES-ECB as deprecated in-code; keep it available for parity but warn in `builder.py` when selected.
- Move `bcrypt.dll` loading to dynamic resolution via PEB walk so it doesn't appear in the import table.

### Encryption: AES-CBC

*AES in CBC mode via BCrypt. Per-build random IV baked into `shellcode.hpp` alongside the key.*

**OPSEC Considerations**
- Same `bcrypt.dll` import surface as AES-ECB.
- The IV + key are both present in the loader image at static offsets - a defender who extracts them can decrypt the embedded shellcode offline.

**Improvements - For Operators**
- This is the strongest shellcrypt option; use it when the payload is sensitive enough that offline ciphertext recovery matters (e.g. the loader may sit in a sandbox or forensic archive long after the campaign).
- Pair with `LZNT1` to hide the shellcode structure before encryption.

**Improvements - For Erebus Developers**
- Derive the AES key from a password + embedded salt so the key itself isn't a static literal in the binary; the derivation cost is trivial.
- Load `bcrypt.dll` dynamically (see AES-ECB entry above).

### Encoding: BASE64

*Standard Base64 wrapping applied after encryption.*

**OPSEC Considerations**
- Base64 is trivially detectable as a sliding-window character-set match; YARA rules for `[A-Za-z0-9+/=]{100,}` are routine.
- Expands payload size ~33 %, inflating the loader binary.

**Improvements - For Operators**
- Use when the final container (ISO, HTML smuggling page, etc.) needs ASCII-safe embedding. For plain binary loaders, prefer `NONE`.

**Improvements - For Erebus Developers**
- Nothing structural; Base64 is what it is.

### Encoding: ASCII85

*Base85 / Ascii85 encoding. Denser than Base64.*

**OPSEC Considerations**
- Produces character sequences rarely found in benign loader binaries, so static analysts notice long ASCII85 blocks quickly.
- Decoder code is small but distinctive.

**Improvements - For Operators**
- Only worth picking when the delivery channel benefits from density (e.g. a character-limited paste lure).

**Improvements - For Erebus Developers**
- Same as Base64 - no structural work needed.

### Encoding: ALPHA32 / WORDS256

*ALPHA32 maps each byte to one of 32 alphanumeric characters; WORDS256 maps each byte to a NATO-alphabet word.*

**OPSEC Considerations**
- Both encodings defeat byte-level signature scanning on the encoded form, but the decoder shape is extremely recognisable in the loader.
- WORDS256's space-separated English word stream is easy for text filters (DLP, gateway content filters) to flag as anomalous.
- ALPHA32 output looks like random base32 and shares YARA-rule fate with any other base32-like blob.

**Improvements - For Operators**
- Skip WORDS256 unless the lure specifically calls for text-looking content (e.g. embedding in a fake document body).
- ALPHA32 is fine for ASCII-safe channels but doesn't add much over Base64 for binary loaders.

**Improvements - For Erebus Developers**
- The ALPHA32/WORDS256 decoders in the loader contain literal lookup tables in `.rdata`. Move these to stack-resident buffers built from compact initialisers at runtime.

### Encoding: NONE

*No encoding applied - the encrypted bytes are embedded directly as a `unsigned char` array.*

**OPSEC Considerations**
- Raw encrypted bytes in the loader image are the smallest surface - no decoder shape to match.
- If the encryption layer is weak or absent, the raw shellcode bytes become trivially recoverable.

**Improvements - For Operators**
- Default choice when the loader is the delivery artefact. Pair with AES-CBC for best results.

**Improvements - For Erebus Developers**
- No action needed.

### Output Formats: C / CSharp / Raw

*Shellcrypt emits the obfuscated bytes in the chosen output language. Only `C`, `CSharp`, and `Raw` are wired into the loaders shipped with Erebus today; the other formats (Nim, Go, Python, VBA, etc.) are library features not integrated into the build pipeline.*

**OPSEC Considerations**
- The output format is a static indicator of which loader consumed it; a defender who recovers both the shellcrypt artefact and the loader can confirm they come from the same toolchain.
- `Raw` format preserves the byte alignment of the shellcode; `C` and `CSharp` introduce fixed structural wrapping (`unsigned char shellcode[] = { ... }` / `byte[] shellcode = new byte[] { ... }`) that is easy to grep for.

**Improvements - For Operators**
- Match the format to the loader (`C` for Shellcode Loader, `CSharp` for ClickOnce); mismatching won't compile.
- `Raw` is the right pick when the shellcode is embedded into a non-loader container (e.g. the Electron wizard's `payload/` tree - the shellcode is wrapped in another PE, not a source file).

**Improvements - For Erebus Developers**
- Rename the generated array identifier to something non-obvious (the current `shellcode` / `sh3llc0d3` pattern is widely signatured). The Electron container already uses `iconBuffer` - apply the same approach to the C/CSharp loaders.

### Chaining Strategy

Ops stack in the order `compress → encrypt → encode` on the outbound side; the loader reverses them. Each layer costs the defender a specific type of analysis:

- **Compression** costs the defender the ability to byte-scan for raw shellcode fingerprints.
- **Encryption** costs the defender the ability to recover the shellcode without also extracting the key + decryption routine from the loader.
- **Encoding** costs the defender the ability to apply binary-only YARA rules to the final loader image.

A defender with memory-scanning capability inside the target process defeats all three layers at the moment the loader is about to inject. Obfuscation is a delay tactic against static analysis, not a runtime defense. Treat it as one half of the picture - the other half is the [Loader Memory Handling](#loader-memory-handling) section below.

**Improvements - For Operators**
- Default recipe: `LZNT1` + `AES-CBC` + `NONE`. Add an encoding stage only when the delivery channel is text-safe (HTML smuggling, email body paste, etc.).
- Change at least one layer per campaign - reusing all three is what makes multiple samples attributable.

**Improvements - For Erebus Developers**
- Add a `shellcrypt --verify` round-trip harness to the CI that catches loader/shellcrypt desynchronisation before it ships.

---

## Custom Shellcode (External C2)

*`0.0a Enable Custom Shellcode` + `0.0b Custom Shellcode File` lets the operator override the Mythic-generated shellcode with a raw binary from any C2 (Cobalt Strike, Havoc, Sliver, msfvenom).*

**OPSEC Considerations**
- Custom shellcode is not wrapped in Mythic's callback infrastructure - Mythic will *never* see a callback. An operator debugging their chain can't use Mythic's "did the payload fire" signal as ground truth.
- Architecture mismatches (uploading an x64 blob into an x86 loader, or vice versa) fail silently at runtime - there is no compile-time check.
- The uploaded file replaces `shellcode/payload.bin` in the build tree and goes through the same shellcrypt pipeline; all obfuscation/encryption considerations above apply unchanged.
- MZ header check at `0.1 Loader Type` rejects PE files, but does *not* validate that the bytes are executable shellcode - uploading a random blob will produce a loader that crashes its target process.

**Improvements - For Operators**
- Always run a throwaway test on a clean VM before delivery to verify the shellcode actually fires; don't rely on compile success.
- Upload stageless shellcode whenever possible - stagers add a second C2 connection before the real implant, doubling the network indicators.
- Keep the external C2's infrastructure hygiene (domain age, TLS certs, hosting AS) independent from the Erebus build-host infrastructure. Don't correlate.
- Verify the bitness matches `0.1 Loader Type` (x64/x86) *manually* - there is no UI enforcement.

**Improvements - For Erebus Developers**
- Add architecture detection (heuristic on the first few shellcode bytes or a new BuildParameter) and fail the build with a clear error on mismatch.
- Add an optional "sanity execute in QEMU user-mode" preflight step that confirms the shellcode at least reaches its first syscall before it ships.

---

## MalDocs (Excel VBA)

Erebus generates macro-enabled Excel documents (XLSM/XLAM) or exports a standalone `.bas` module. The build pipeline compiles the `vbaProject.bin` on Linux via `agent_code/vba_compiler/`, injects it into a base template from `agent_code/templates/` via ZIP-level manipulation, and optionally emits a `build_maldoc.bat` runbook for Windows-side COM re-injection via `erebus_helper.py`.

### Build Pipeline Footprint

*Linux-side compile produces a valid MS-OVBA-compliant `.xlsm` / `.xlam` without touching Office, plus side artefacts in `payload/`.*

**OPSEC Considerations**
- The Linux-compiled `vbaProject.bin` is technically valid but is byte-for-byte different from one Office would emit; sophisticated EDR tooling that compares the stream structure can flag it.
- Build artefacts left in `payload/` include the plain `.bas` file and `build_maldoc.bat` runbook alongside the compiled Excel document - if the operator ships the whole `payload/` tree (e.g. zipped for Mythic delivery) those side artefacts go to the victim.
- Optional Windows-side COM re-injection via `erebus_helper.py` leaves a ~5–10 s window where the Excel host process has COM automation hooks active.

**Improvements - For Operators**
- Before delivery, strip the `.bas` and `build_maldoc.bat` from the payload tree; they're operator convenience artefacts, not target files.
- Use the Windows-side `erebus_helper.py` re-injection for any high-effort delivery - the re-injected `vbaProject.bin` is byte-identical to a real Office-authored one.
- Match the document template (`template.xlsm` vs `template.xlsx`) to the lure pretext; the cell content in the template shows in the victim's document.

**Improvements - For Erebus Developers**
- Strip the `.bas` / `.bat` runbook files from the copy that gets bundled by the Mythic payload delivery (keep them in `payload/` during build, remove them in the containerisation stage).
- Add a template catalog (invoice, HR form, meeting notes) rather than the single generic `template.xlsm` so per-campaign documents don't share identical cell layouts.

### Dynamic Payload Discovery (`FindPayload`)

*In Command Execution mode, the generated VBA runs `Scripting.FileSystemObject` against a list of candidate directories (`%TEMP%`, `%APPDATA%`, `ThisWorkbook.Path`, OneDrive-synced folders, etc.) to resolve the payload file at runtime.*

**OPSEC Considerations**
- Recursive filesystem enumeration from `EXCEL.EXE` is an unusual behaviour - Defender for Endpoint, CrowdStrike, and SentinelOne all have behavioural rules that flag `EXCEL.EXE` walking `%TEMP%` or `%USERPROFILE%` subtrees.
- The candidate list is hard-coded into the generated VBA and appears in clear text (after obfuscation) inside `vbaProject.bin` - an analyst who unpacks the document sees exactly which directories were probed.
- If the payload is found via a recursive search (`RecursiveSearch` / `StackSearch`) rather than a direct path match, the API call volume alone is enough to trigger AMSI or ETW-based detection.

**Improvements - For Operators**
- When possible, drop the payload into `ThisWorkbook.Path` (the same directory as the document) so `FindPayload` hits on the first direct check and skips the recursive search entirely - this is the first candidate the function tries.
- Add an explicit `Application.Wait (Now + TimeValue("0:00:02"))` sleep before the search so the detection window doesn't overlap with Excel's startup-telemetry burst.
- Avoid delivering the payload and the document in separate channels (email + cloud storage) that split them across directories; this is the scenario where `FindPayload` goes recursive.

**Improvements - For Erebus Developers**
- Add a BuildParameter for "limit `FindPayload` to the document's own directory" that compiles out the recursive subtree walker, eliminating the behavioural trigger entirely.
- Encrypt the candidate-directory string list inside the VBA so analysts can't pull them out via ZIP extraction + plain-text grep.

### VBA Loader Technique: VirtualAlloc + CreateThread

*Classic VBA shellcode injection - allocate RWX, copy, CreateThread. The default in Erebus.*

**OPSEC Considerations**
- `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` from `EXCEL.EXE` is the single most reliable EDR trigger on Office macros - it has been heuristically flagged for close to a decade.
- `CreateThread` from an Office process is a fixed AMSI+ETW signature.
- The technique works on every Office version, so it's the first thing new operators reach for and the first thing every EDR vendor models.

**Improvements - For Operators**
- Avoid on any monitored target; use this only for labs or environments that are explicitly known not to have EDR.
- If forced to use it, pair with heavy VBA obfuscation to push the decoder past signature scanners - accepting that the runtime behaviour is still caught by behavioural rules.

**Improvements - For Erebus Developers**
- Replace the direct `VirtualAlloc` call with `NtAllocateVirtualMemory` via direct syscall stub (VBA can't do this cleanly; this is a technique change, not a one-line patch).

### VBA Loader Technique: EnumSystemLocalesA Callback

*Shellcode is executed via the callback argument of `EnumSystemLocalesA` - no `CreateThread`.*

**OPSEC Considerations**
- Eliminates the `CreateThread` signature but not the preceding `VirtualAlloc`; the RWX page is still allocated.
- Callback-as-entry-point is itself a weak signature but less mature than `CreateThread` detection.
- Works on modern Office, fails on very old Excel versions (Office 2010 and earlier may not have the required VBA interop).

**Improvements - For Operators**
- Pick this over VirtualAlloc+CreateThread when the target is monitored by signature-first tooling (traditional AV, older EDR).
- Still not sufficient on behavioural-detection stacks - those flag the preceding RWX allocation.

**Improvements - For Erebus Developers**
- Add a variant using `EnumUILanguagesW` or `EnumResourceLanguagesW` as the callback hook so Erebus doesn't use only one well-known callback API.

### VBA Loader Technique: QueueUserAPC Injection

*APC queued against the current thread, triggered by a subsequent alertable wait (`Sleep(1)` with the `bAlertable` flag).*

**OPSEC Considerations**
- No new thread is created, which defeats a class of parent-process-thread-creation rules.
- The APC queue operation is still visible via ETW (`Microsoft-Windows-Threat-Intelligence` provider's APC callbacks).
- The alertable wait is a weak signal on its own but a strong one in combination with the preceding RWX allocation.

**Improvements - For Operators**
- Best of the four on environments with thread-creation monitoring but without full ETW-TI instrumentation.
- Not an improvement on systems running Defender for Endpoint with kernel-mode ETW-TI.

**Improvements - For Erebus Developers**
- Queue the APC to a background COM pump thread instead of the main VBA thread so the alertable wait isn't tied to Excel's foreground loop.

### VBA Loader Technique: AddressOfEntryPoint Injection (notepad.exe host)

*VBA spawns `notepad.exe` suspended, resolves the child's AddressOfEntryPoint via `NtQueryInformationProcess` → PEB → PE header parsing, flips the page to RW with `VirtualProtectEx`, overwrites the entry point bytes with shellcode via `WriteProcessMemory`, restores the original page protection, then calls `ResumeThread`.*

**No `VirtualAllocEx`. No RWX region. Shellcode runs in existing mapped memory.**

**OPSEC Considerations**
- `notepad.exe` as a child of `EXCEL.EXE` is still a process-lineage anomaly - parent–child relationship is logged by most EDRs regardless of injection method.
- `VirtualProtectEx` (RW) + `WriteProcessMemory` against a suspended child followed immediately by `VirtualProtectEx` (restore) is a known entry-point overwrite pattern; Defender for Endpoint and CrowdStrike both have signatures for this sequence.
- No RWX allocation avoids a major static heuristic, but the PEB-parse + PE-header-read sequence via `ReadProcessMemory` is a behavioural indicator used by kernel-mode ETW-TI sensors.
- Entry-point shellcode has no return path once the original code is overwritten - ensure your shellcode either restores the original bytes before execution or runs `ExitProcess` to avoid crashing the host process in a way that generates noise.

**Improvements - For Operators**
- Swap the host process to something that more plausibly launches from Office (e.g. `splwow64.exe`, `RuntimeBroker.exe`) - the spawn itself is the most durable signal regardless of injection method.
- On well-monitored environments, favour the QueueUserAPC (self-APC) loader instead; it never crosses a process boundary.

**Improvements - For Erebus Developers**
- Add a BuildParameter for the target process name; hard-coding `notepad.exe` is the single biggest limitation of this technique in Erebus today.
- Add a variant that targets a process that is *already running* (PID lookup + `OpenProcess`) rather than spawning a new one - eliminates the parent–child creation event entirely.
- Restore the original entry-point bytes from a pre-write backup buffer before `ResumeThread` so the host process can tear down cleanly after shellcode exits.

### VBA HTTP Shellcode Stager

*When `0.9v HTTP Stager URL` is set and `0.9f = Shellcode Injection`, the builder uploads a per-build RC4-encrypted shellcode blob to the Mythic file store and embeds a compact `GetBuf()` downloader in the VBA instead of any inline shellcode. The staging URL is constructed as `<base>/direct/download/<agentFileId>`. Both the shellcode and the URL are stored as RC4-encrypted byte arrays in VBA source.*

**OPSEC Considerations**
- The `GetBuf()` VBA function issues an outbound HTTP GET from `EXCEL.EXE` (or `WINWORD.EXE`) at macro execution time. Proxy-aware EDRs and network security tools log this as an Office process making an external connection, which is an anomaly signal independent of the payload content.
- `WinHttp.WinHttpRequest.5.1` (and the `MSXML2.ServerXMLHTTP` fallback) are legitimate COM objects used by Office add-ins, but invocation from a VBA macro context is flagged by products that track COM-object-creation call chains.
- The Mythic `/direct/download/<uuid>` endpoint does not require authentication. Any actor who learns the UUID can retrieve the encrypted blob. The RC4 key is embedded in the macro and never transmitted; recovering the plaintext shellcode requires both the blob and the key.
- A sandbox that replays the document offline without network access will silently fail at `GetBuf` - `http.Status <> 200` → `Exit Sub` - and the macro will appear inert. This is an intentional behaviour but also means analyst sandboxes that block egress will never observe execution.
- The staged blob on the Mythic server remains accessible until manually deleted. After the engagement, remove it from the Mythic file store to avoid leaving a retrievable artefact.

**Improvements - For Operators**
- Host the encrypted blob behind a redirector with a Referer or User-Agent whitelist so mass-scan retrieval attempts are silently 404'd while the target (which sends the embedded User-Agent string) receives a 200.
- Set `DeleteAfterFetch = True` in the Mythic RPC call if single-use delivery is acceptable - the blob is removed from the file store after the first successful download, limiting the exposure window.
- Rotate the Mythic team server port away from the default `7443` if the team server IP is visible in network logs; many detection rules specifically match on that port from Office processes.
- Ensure the team server certificate CN matches the SNI sent by `WinHttp` (or use a valid CA-signed cert); the `&H3300` flag suppresses certificate errors client-side but some network inspection proxies will still flag the mismatch.

**Improvements - For Erebus Developers**
- Add a `DeleteAfterFetch` BuildParameter toggle for operators who want single-use staging (currently hardcoded `False`).
- Add domain-fronting support: allow the operator to supply a separate `Host:` header value so the GET resolves via a CDN front-domain while the `Host:` header routes to the team server back-end.
- Consider splitting the blob across multiple HTTP requests (chunked download) to defeat byte-pattern matching on the response body - the per-build RC4 encryption already prevents static matching, but chunking breaks length-based heuristics.

---

### VBA Obfuscation

*Optional obfuscation pass applied to the generated VBA source (variable renaming, string splitting, dead code insertion).*

**OPSEC Considerations**
- Obfuscation defeats most *signature* scanners but raises the document's Shannon entropy, which is itself a signal used by anomaly-based detection (`oletools::olevba` with `--decalc`, Proofpoint, Defender's cloud-side scoring).
- Over-obfuscation (too many dead-code blocks, too much string splitting) has a known characteristic entropy profile that is easier to pick out than mild obfuscation.

**Improvements - For Operators**
- Enable obfuscation by default on any environment where you suspect signature-first detection.
- Disable obfuscation when targeting environments where the anomaly-scoring stack is known (large enterprises with Defender for Office 365 tune to entropy); a clean-looking macro scores lower.
- Never hand-author additional obfuscation on top of Erebus's output - the combined entropy profile is worse than either alone.

**Improvements - For Erebus Developers**
- Add a "low entropy" obfuscation mode that only renames identifiers and leaves string literals plain - this targets the anomaly-scoring case without defeating it.

### Macro Security / MOTW

*Office's default macro security blocks macros from files with the Mark of the Web (MOTW), requiring the user to explicitly enable content.*

**OPSEC Considerations**
- MOTW is applied by the browser / email client to files downloaded from the internet; it is **not** applied to files extracted from an ISO container (this is an intentional Windows design choice, though it has been partially addressed in recent Windows 11 updates).
- When MOTW is present, the victim sees a yellow warning bar and must click "Enable Content" - this is the single biggest delivery-phase friction point for maldocs.
- Office macros delivered via Outlook's newest policies are blocked by default (no user click-to-enable) even on MOTW-less documents.

**Improvements - For Operators**
- Deliver the maldoc inside an ISO container so MOTW is not applied on extraction (see [ISO](#iso-optical-media) section).
- For email delivery, accept that click-to-enable is required; design the lure pretext to match (e.g. "This document is from a trusted partner - click Enable Content to view the signed invoice").
- Avoid delivering via Outlook directly to organisations with strict macro policies; use Teams / OneDrive share links that bypass Outlook's Outlook-specific block.

**Improvements - For Erebus Developers**
- Add an explicit warning in `builder.py` when MalDoc + direct email delivery are both selected, pointing to the ISO container option.

---

## Shellcode Loader (C++) Injection Methods

The C++ `Erebus.Loader` supports four injection techniques, selected via `0.4 Shellcode Loader - Injection Type`. All four are implemented as indirect-syscall-free C++ using MinGW on Linux - see [Loader Memory Handling](#loader-memory-handling) for the hardening baseline that applies to every method.

### Type 1: NtMapViewOfSection

*Section mapping injection - create a `NtCreateSection` → `NtMapViewOfSection` pair in both the loader and the target, use the shared view as the staging buffer.*

**OPSEC Considerations**
- `NtCreateSection` / `NtMapViewOfSection` from a non-kernel process is visible to kernel-mode ETW-TI; modern EDR hooks on these syscalls directly.
- The target process is embedded as a wide-string literal in `config.hpp` and ends up in the loader's `.rdata` - a static analyst can see which process Erebus was targeting.
- The created section object has a name by default (`Local\<random>`) which appears in `handle.exe` output and in ETW `ObjectHandle` events.

**Improvements - For Operators**
- Set `0.5 Shellcode Loader - Target Process` to a process that is plausibly running on the target (prefer `explorer.exe`, `dllhost.exe`, or `RuntimeBroker.exe` depending on the user's session state).
- Verify the target is actually running before execution; injection into a missing process fails noisily.

**Improvements - For Erebus Developers**
- Encrypt the target process name literal in `config.hpp` and decrypt at runtime so it doesn't appear in `.rdata` strings.
- Use an unnamed section (`NULL` object name) to suppress the ETW ObjectHandle trail.

### Type 2: CreateFiber

*Self-injection via fiber creation. Shellcode runs in the loader's own process, no remote operation.*

**OPSEC Considerations**
- No remote-injection APIs are called, which defeats the entire class of cross-process injection detection.
- The loader process becomes the host for the shellcode's subsequent behaviour - any suspicious activity (network connections, credential access) is attributed to whatever binary Erebus was compiled into. For DLL hijacking chains this is by design; for a standalone exe it's often a giveaway.
- Fiber-based execution is unusual enough that some behavioural models (e.g. Elastic's `process_injection_via_fibers`) explicitly flag it.

**Improvements - For Operators**
- Only use when the loader is a DLL hijack and the host process is plausibly a C2 client (e.g. Teams, Outlook, OneDrive) - the host process's legitimate network surface is cover for the C2.
- Never use with a standalone `erebus.exe` loader - the fiber creation + network activity from a single-file exe is its own fingerprint.

**Improvements - For Erebus Developers**
- Add a variant that uses `UMS scheduling` / `User-Mode Scheduling` threads rather than fibers - same in-process execution model, different API surface.

### Type 3: EarlyCascade (NtQueueApcThread)

*Early Bird APC injection - spawn a target process suspended, queue an APC to its main thread, resume.*

**OPSEC Considerations**
- Spawning a process suspended is by itself a weak signal; combined with `NtQueueApcThread` it is a strong one. EDRs that hook `NtQueueApcThread` catch this reliably.
- The `CreateProcessW` call has to go somewhere - the suspended target process name is visible in Sysmon Event ID 1 (process creation) and in its parent-child relationship to the Erebus loader.
- Early APC injection fires before any ETW providers the target process would register, which is the technique's real advantage - but kernel-mode ETW (including ETW-TI) is not affected.

**Improvements - For Operators**
- Pick a target process that is plausibly spawned by the loader's parent (e.g. spawning `notepad.exe` from a Word document exploit chain is fine; spawning it from a standalone exe is suspicious).
- Target `rundll32.exe` or `regsvr32.exe` only if the surrounding chain justifies them - random LOLBIN spawning is a detection pattern.

**Improvements - For Erebus Developers**
- Replace `NtQueueApcThread` with the newer `NtQueueApcThreadEx2` variant which takes an APC reserve object and has less mature detection coverage.

### Type 4: PoolParty

*Worker Factory thread pool injection via `IoCompletion` port - no new threads, reuse an existing pool.*

**OPSEC Considerations**
- Requires the target process to have an active thread pool (`RuntimeBroker.exe`, `dllhost.exe`, `fontdrvhost.exe`, `sihost.exe` are reliable choices). Injection into a pool-less process fails.
- Worker factory manipulation is detected by very few EDR products today but is a known technique - coverage is expanding.
- `NtAlpcConnectPort` usage for the completion notification is visible in ETW.

**Improvements - For Operators**
- Use for environments where injection into shell processes is specifically detected - PoolParty bypasses most process-tree detections because the payload runs inside an existing, legitimately-running pool thread.
- Verify the target process has a pool (check with `!thread` in WinDbg or Process Hacker) before deployment.

**Improvements - For Erebus Developers**
- Add automatic fallback to EarlyCascade when the chosen target process has no thread pool, rather than failing the injection.
- Expose more target process options than the current hard-coded list in the documentation.

---

## Loader Memory Handling

*The C++ loader implements several baseline OPSEC-hardening practices on memory, key material, and staging buffers.*

**Current hardening baseline (already in place):**
- Staging buffer allocation via `VirtualAlloc` rather than `malloc` to avoid CRT heap metadata leakage.
- Decryption key material copied to stack, zeroed with `SecureZeroMemory` immediately after use.
- Post-injection cleanup: staging buffer zeroed and freed after injection completes.
- RC4 S-box zeroed after key schedule use.
- Remote allocation cleanup via `NtFreeVirtualMemory` on failed write / protection change.
- Jittered sleep timing: `base + GetTickCount() % jitter` rather than fixed intervals.

**OPSEC Considerations (what still leaks despite the hardening)**
- PEB walking to resolve API addresses is visible when a debugger attaches - the walking loop is a recognisable shape in disassembly.
- String literals marking injection-type branches (e.g. `"NtMapViewOfSection"`, `"CreateFiber"`) exist in `.rdata` as compile-time debug markers in some build configurations; `strings erebus.exe` lists them.
- Jitter base values and modulus are hard-coded constants, so the "jitter" has a known distribution (`base` + `[0, jitter)`) that's statistically distinguishable from uniform random sleeping.
- `SecureZeroMemory` is implemented as a `RtlSecureZeroMemory` call at the API level - modern compilers optimise the underlying `memset` back into a simple loop, and the call itself appears in the import table unless resolved via PEB walk.
- The loader's `.text` section contains the full injection routine code which is not encrypted; a memory scanner can match it after the loader has been mapped.

**Improvements - For Operators**
- Use the `Release` build configuration, not `Debug` - Debug builds retain string markers and symbol data that Release strips.
- Pair memory hardening with a strong shellcrypt chain so the sensitive window between "decrypt shellcode" and "scrub staging buffer" is as short as possible.

**Improvements - For Erebus Developers**
- Move to **indirect syscalls** via a SysWhispers-style lookup table - all `Nt*` calls should go through direct syscall stubs resolved at runtime, not via the `ntdll.dll` import table.
- Add a **per-build randomised jitter seed** mixed with `RDTSC` so the jitter distribution is non-reproducible.
- Strip injection-type string literals from Release builds entirely; replace with numeric constants.
- **Encrypt the `.text` section of the injection routine** with a short XOR key that's resolved at load-time, decrypted into a fresh page, and executed from the new page - this defeats post-load memory scanners.
- Add padding / dummy-code generation to the injection routines so two builds don't have byte-identical `.text` sections.
- Replace `SecureZeroMemory` with a volatile-pointer inline loop so the compiler can't optimise it out and no import is needed.

---

## Evasion Patches (Shellcode Loader / DLL Hijack)

*Runtime hardening applied by `RunEvasionPatches()` before shellcode decryption and injection. Controlled by `0.5m` / `0.5n` / `0.5o`. Does not apply to ClickOnce.*

### Syscall Backend (`0.5m`)

Two choices, both bypass user-mode hooks on `Nt*` calls:

- **TartarusGate** (default) - runtime-generated indirect syscall shim page. Each stub is `mov r10, rcx; mov eax, <ssn>; jmp <gadget_in_ntdll>`; the actual `syscall` instruction executes from inside ntdll's `.text`, which is where kernel telemetry expects it.
- **SysWhispers3** - compile-time generated `Sw3Nt*` stubs. Requires the `include/evasion/sw3/` tree and the `Syscalls-asm.x{64,86}.asm` sources linked in the loader Makefile.

**OPSEC Considerations**
- SSN resolution walks ntdll's export table; on a process that has already lost ntdll to a deep user-mode hooking engine, the SSN table may be shifted and resolution fails silently.
- Indirect syscalls bypass user-mode hooks but *not* kernel-mode ETW-TI (`Microsoft-Windows-Threat-Intelligence`). Protected-process EDR still sees the call.
- `InitIndirectSyscalls()` runs after `UnhookNtdll()` - if unhook fails, the SSN table read is from the hooked ntdll and the generated stubs may carry poisoned SSNs.

### Callstack Spoofing (`0.5n` + `0.5o`)

*When enabled, `Nt*` calls at injection sites dispatch through `SpoofCall()` instead of calling the function directly. The target sees `[rsp+0] = Gadget` as its return address; the gadget's `add rsp, 0x68; ret` returns to the real caller. A walker (`RtlVirtualUnwind`, EDR stackwalk, `StackWalk64`) sees the gadget module as the immediate caller of the Nt* - not the loader's `.text`.*

**How the module list is used**
- `InitCallstackSpoof()` iterates `CONFIG_CALLSTACK_SPOOF_MODULES` in order and scans each module's `.text` for the byte sequence `48 83 C4 68 C3` (`add rsp, 0x68; ret`).
- First match wins. Resolution is PEB-walk only (`GetModuleHandleC`) - no `LoadLibrary` fallback, so operator-chosen modules must already be mapped in the host process.
- Displacement is fixed at `0x68` because it is coupled to `sub rsp, 112` in `callstack_spoof_gas.S`. Changing it requires matching ASM edits and is not exposed to the operator.

**OPSEC Considerations**
- The spoofed frame above every `Nt*` call is whichever module hosts the gadget. Defaults (`ntdll` / `kernel32` / `kernelbase`) blend into every Win32 process. A mismatched host (e.g. an ntdll gadget inside a process that normally never calls into ntdll for the spoofed API path) is still a tell.
- Only volatile registers are touched by the trampoline (`rax`, `rcx`, `rdx`, `r8`, `r9`, `r10`, `r11`). Non-volatile state is preserved across the spoofed call, so downstream code that relies on `rbx` / `rbp` / `rsi` / `rdi` / `r12`–`r15` is unaffected.
- If no gadget is found, `SpoofCall` still forwards the call but without spoofing - the loader continues to function, no telemetry about the fallback is emitted, and the operator loses the spoof silently.
- The `add rsp, 0x68; ret` byte pattern is common in ntdll's epilogues but scarcer in application DLLs. Picking a small / stripped module may yield zero matches.
- A kernel-mode stackwalk (ETW-TI on NtCreateThreadEx, for example) sees the full call chain, including the return back into the loader's `.text` after the gadget's `ret`. Callstack spoofing is a user-mode stackwalk defence only.

**Improvements - For Operators**
- Pick modules that blend with the target host's legitimate telemetry. Examples:
  - GUI-heavy processes (`explorer.exe`, `RuntimeBroker.exe`): add `user32.dll`, `gdi32.dll`.
  - Network tooling / browsers: add `winhttp.dll`, `wininet.dll`.
  - Office: add `mso.dll`, `vbe7.dll` (already mapped when a macro runs).
- Confirm the chosen module is actually mapped in the target host before shipping - `listdlls.exe <pid>` or Process Hacker. A missing module means the gadget search silently skips it and falls through to the next entry.
- Leave the defaults in place unless you have a specific reason - they cover every Win32 process and the gadget density in ntdll alone is ~100+ candidates.

**Improvements - For Erebus Developers**
- Surface a gadget-search telemetry knob so the operator sees which module / offset was selected per build (ship it in the IOC report).
- Extend the ASM to accept the displacement as a parameter (currently hardcoded), which would let the search accept any `add rsp, N; ret` found rather than requiring `N == 0x68`.
- Add a second spoof tier that swaps the gadget host mid-campaign (rebuild with a different `0.5o` list) so two builds from the same operator don't share the exact same first-frame module.

---

## ClickOnce Injection Methods (C# / .NET)

The `Erebus.ClickOnce` loader is a .NET 7 single-file publish with six selectable injection methods via `0.6 ClickOnce - Injection Method`. All .NET-specific considerations (CLR ETW, AMSI for .NET, JIT logging) apply across every method in addition to the per-technique notes below.

### General .NET Telemetry Surface

**OPSEC Considerations**

*The following apply to every ClickOnce injection method below, in addition to per-technique notes.*

- `Microsoft-Windows-DotNETRuntime` ETW provider emits events on module load, JIT compile, assembly load - a defender with `PerfView` or SilkETW on the host sees every method JITted inside the ClickOnce loader.
- **AMSI for .NET** (enabled by default on Windows 10 1803+) scans `Assembly.Load` buffers - if the loader loads any follow-on .NET assembly dynamically, AMSI sees it.
- ClickOnce's single-file publish preserves PDB file names and namespace markers unless explicitly stripped; `Erebus.ClickOnce` in the namespace string is the single biggest fingerprint.
- The `bin/Release/net7.0-windows/win-x64/publish/` directory tree contains numerous satellite DLLs beyond `Erebus.ClickOnce.exe` - all are shipped to the victim as part of the payload.

**Improvements - For Operators**
- Disable symbols via `DebugType=none DebugSymbols=false` in the publish command (Erebus already does this in `Erebus.ClickOnce/Makefile`).
- Rename the project namespace before building for high-value engagements - a one-time source change removes the `Erebus.ClickOnce` fingerprint.
- Strip the `publish/` satellite DLLs of anything not strictly needed (Erebus's build pipeline already filters out the main exe/dll but leaves supporting DLLs - review the list in `payload/` before delivery).

**Improvements - For Erebus Developers**
- Add a BuildParameter for a custom namespace/assembly name so operators can rebrand per-campaign without editing source.
- Add an AMSI patch to the loader entry point (fix `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`) before any `Assembly.Load` calls.
- Consider ahead-of-time compilation (NativeAOT) to eliminate JIT events entirely - large refactor, significant payoff.

### createfiber

*Fiber-based self-injection (same as C++ CreateFiber).*

**OPSEC Considerations**
- Same concerns as the C++ CreateFiber entry above; additionally the .NET runtime's fiber interop is unusual and may itself be an indicator.

**Improvements - For Operators**
- Same as C++ CreateFiber: DLL hijack chains only, not standalone delivery.

**Improvements - For Erebus Developers**
- See C++ CreateFiber entry.

### earlycascade

*Early Bird APC injection implemented in managed code.*

**OPSEC Considerations**
- .NET P/Invoke for `NtQueueApcThread` goes through `DllImport` which is visible in the assembly's metadata tables - a `dnSpy` analyst can list every P/Invoke in seconds.
- Otherwise identical to C++ EarlyCascade.

**Improvements - For Operators**
- Same as the C++ method.

**Improvements - For Erebus Developers**
- Resolve `NtQueueApcThread` via reflection + `Marshal.GetDelegateForFunctionPointer` at runtime rather than `DllImport` so it doesn't appear in the metadata tables.

### poolparty

*PoolParty implemented via .NET P/Invoke against the worker factory APIs.*

**OPSEC Considerations**
- Same PoolParty target-process requirements as the C++ method.
- P/Invoke metadata leaks every API name (`NtAlpcConnectPort`, `NtCreateWorkerFactory`, etc.) unless resolved at runtime.

**Improvements - For Operators**
- Same as the C++ method.

**Improvements - For Erebus Developers**
- Resolve all worker-factory APIs via reflection at runtime.

### classic (CreateRemoteThread)

*`CreateRemoteThread` against a remote process.*

**OPSEC Considerations**
- `CreateRemoteThread` is the most monitored injection API on Windows, with detection going back ~15 years.
- `OpenProcess` with `PROCESS_CREATE_THREAD` access is itself a strong signal.

**Improvements - For Operators**
- Use only when the target environment is explicitly known not to have EDR; prefer earlycascade or poolparty otherwise.

**Improvements - For Erebus Developers**
- Document this method as legacy in the UI and surface a warning when it's selected.

### enumdesktops

*Self-injection via `EnumDesktops` callback - shellcode runs as the enumeration callback.*

**OPSEC Considerations**
- Self-injection avoids remote-process APIs entirely - the RWX page lives in the ClickOnce loader's own address space.
- `EnumDesktops` from a .NET process is unusual enough to be a weak signal on its own; it's rarely called outside of UI framework code.
- Desktop enumeration can fail in non-interactive sessions (Services, Task Scheduler tasks) - reliability depends on execution context.

**Improvements - For Operators**
- Use in ClickOnce-launched-from-browser scenarios where the loader is guaranteed to be in an interactive session.
- Not reliable for scheduled-task execution chains.

**Improvements - For Erebus Developers**
- Add a variant that falls back to fiber execution if `EnumDesktops` fails rather than hard-erroring.

### appdomain

*AppDomain injection - load a secondary managed assembly into a new AppDomain and invoke it.*

**OPSEC Considerations**
- AppDomain creation events are emitted to `Microsoft-Windows-DotNETRuntime` ETW; a defender watching for managed-managed injection catches this.
- `Assembly.Load(byte[])` feeds directly into AMSI for .NET on Windows 10 1803+.
- The loaded assembly is hosted in the same process but in an isolated AppDomain - useful for IL-level payload staging, less useful for shellcode.

**Improvements - For Operators**
- Only meaningful when the follow-on payload is itself a .NET assembly. For shellcode injection, prefer poolparty or earlycascade.

**Improvements - For Erebus Developers**
- Bypass AMSI before `Assembly.Load` via the standard `AmsiScanBuffer` patch (see general .NET telemetry notes above).

---

## VM Loader (Erebus.VMLoader)

The VM Loader wraps the shellcode execution chain inside an embedded vmkit RISC VM. A native host binary (`vmloader_builder`) encodes an 8-op IR program and XOR-encrypts both the bytecode and the raw shellcode at build time. At runtime the target-side loader decrypts the bytecode, walks the IR, and dispatches each opcode - `EvasionPatch → ObfuscatedSleep → AllocRegion → WritePayload → DecryptPayload → ProtectRX → ExecPayload → FreeRegion` - to its C++ handler. The `ExecPayload` opcode dispatches to the configured self-injection method at compile time via `CONFIG_INJECTION_TYPE`.

### vmkit VM Obfuscation Layers

*Three layers sit on top of the underlying injection: opcode byte randomization (256-entry reverse map), per-build XOR of the bytecode at rest (`g_vm_ir_blob`), and per-op context XOR (the `VMLoaderContext` is XOR-scrambled between each opcode dispatch).*

**OPSEC Considerations**
- The vmkit reverse map is per-build (it is a static constexpr array compiled into the loader), but it does not change between builds unless `EREBUS_HASH_SEED` differs. If two builds share the same seed, the opcode mapping is identical. The Mythic builder generates a new random `EREBUS_HASH_SEED` per build, so operationally this is fine.
- The XOR key (`derive_key(VM_IR_SEED)`) is derived from a fixed seed (`VM_IR_SEED = 0xC0DE1337U` default) mixed with a base string. A static analyst who extracts the key derivation logic from the loader image can decrypt `g_vm_ir_blob` offline and reconstruct the IR program.
- The IR program reveals the full execution plan - evasion, sleep timing, region size, injection type - to a static analyst who decrypts it.
- Context XOR between ops is keyed to the same `VM_IR_SEED`; it is an anti-memory-scan measure, not a cryptographic one.
- The `g_vm_ir_blob` is `inline constexpr` read-only data in `.rodata`. The stack copy in `entry()` is mutable and is decrypted in-place; a debugger breakpointing after the first `vm.execute()` step sees plaintext opcodes in the stack frame.

**Improvements - For Operators**
- Prefer `BUILD=release` always - debug builds retain stack frame metadata and do not apply dead-code strip flags.
- Vary the loader format per delivery chain (`dll` for sideloading, `exe` for standalone, `xll` for maldoc-adjacent chains) to avoid every VM Loader build sharing the same PE structure.

**Improvements - For Erebus Developers**
- Expose `VM_IR_SEED` as a per-build random value (`EREBUS_HASH_SEED` already provides this hook) so the key derivation output differs per build.
- Encrypt the stack blob copy before storing it so a memory dump mid-execution reveals only XOR'd opcodes.
- Consider a larger IR dispatch table (beyond 8 ops) with no-op padding ops to frustrate IR recovery via size analysis.

### Shellcrypt Bypass

*The VM Loader writes raw shellcode bytes directly to `shellcode.hpp`; the Shellcrypt pipeline (`2.0`–`2.3`) does not run. The `vmloader_builder` tool applies its own XOR via `derive_key(VM_IR_SEED)` when generating `embedded.h`.*

**OPSEC Considerations**
- The XOR layer applied by `vmloader_builder` is simpler than the Shellcrypt AES-CBC pipeline - a defender who extracts `VM_IR_SEED` and understands `derive_key()` can recover the raw shellcode from `g_vm_payload[]` offline.
- There is no compression stage. The shellcode's raw size is embedded as `g_vm_payload_size` (plaintext `std::size_t` constant in `embedded.h`), leaking the exact unobfuscated payload size.
- Shellcode structural fingerprints (`\xfc\x48\x83\xe4\xf0`, Cobalt Strike `\x90\x90\x90\x90` NOP sleds, Meterpreter headers) survive the XOR unless `CONFIG_ENCRYPTION_TYPE` is non-zero at the vmkit layer - which it is not today (`CONFIG_ENCRYPTION_TYPE=0` is forced).

**Improvements - For Operators**
- Pre-process the shellcode with an external tool before uploading to Mythic (e.g. apply a second XOR or RC4 layer to the raw blob) to obscure shellcode fingerprints from the `g_vm_payload[]` static array.
- If using Cobalt Strike or Meterpreter payloads, enable artifact kit transforms so the shellcode doesn't start with the canonical `\xfc\x48` header.

**Improvements - For Erebus Developers**
- Add a `DecryptPayload` key rotation option so the vmloader_builder can use a different seed for payload XOR vs. IR XOR - currently both use `derive_key(VM_IR_SEED)`, meaning one key recovers both.
- Consider linking a second encryption pass (AES-ECB or ChaCha20) into the `DecryptPayload` opcode handler, enabled by a new `CONFIG_PAYLOAD_ENCRYPTION_TYPE` define, to provide a stronger layer than single-cycle XOR.

### Self-Injection Types (VM Loader)

*The VM Loader supports only self-injection methods (types 2, 6, 7). No remote-process context is available inside the VM. The injection type is a compile-time constant (`CONFIG_INJECTION_TYPE`); changing it requires a full rebuild.*

**OPSEC Considerations**
- Self-injection means the shellcode runs inside the VM Loader's own process image. All post-injection activity (network connections, LSASS access, etc.) is attributed to whatever binary the VM Loader was compiled into (`erebus_vm.exe`, a sideloaded DLL, an XLL add-in, etc.).
- For `exe` delivery the parent process is `erebus_vm.exe` - an unknown, unsigned process spawning network connections is a high-signal event on any monitored host. Pair with code signing and a convincing PE metadata chain.
- `ModuleStomp` (type 6) overwrites a legitimate DLL's `.text` section with shellcode. The VAD entry remains file-backed, which bypasses VAD-walk memory scanners. The on-disk DLL is unmodified; only the in-memory mapping changes.
- `KernelCallbackTable` (type 7) overwrites a `PEB.KernelCallbackTable` function pointer and triggers it via `SendMessage(WM_COPYDATA)` - no new thread is created. ETW-TI does not see a `NtCreateThreadEx` call for this path, but the `SendMessage` dispatch from an unusual process is visible in user32 ETW events.
- Type 2 (`CreateFiber`) is the same as the Shellcode Loader's fiber path; see [Shellcode Loader (C++) Type 2: CreateFiber](#type-2-createfiber) above.

**Improvements - For Operators**
- For `dll`/`xll` delivery: prefer `ModuleStomp` (type 6) - the file-backed VAD blends with the host process's existing loaded DLLs and provides the cleanest memory forensics profile.
- For `exe` delivery: `KernelCallbackTable` (type 7) avoids a `NtCreateThreadEx` call, making the execution appear as a message dispatch rather than a thread launch. Pair with heavy PE metadata spoofing.
- Use `dll` format for sideloading chains (same benefit as Shellcode Loader DLL): the host process's legitimate reputation covers the loader's activity.

**Improvements - For Erebus Developers**
- Add a type 8 - `TxfHollow`-style phantom section mapping - so the VM Loader has parity with the Shellcode Loader's full injection roster.
- The `ExecPayload` handler currently reads `sc_size` from the IR operand `op.u64[0]`, which must match the payload size exactly. Add a bounds check against the region's allocated size to harden against future IR-craft attacks.

### Two-Step Build and embedded.h

*The VM Loader build is split: `make embedded` runs a native Linux binary (`vmloader_builder`) that emits `include/embedded.h`; `make all` cross-compiles the Windows PE. `builder.py` runs both steps sequentially.*

**OPSEC Considerations**
- `embedded.h` is a generated header containing `g_vm_ir_blob[]` and `g_vm_payload[]` as `inline constexpr` arrays. It is written to disk inside the Mythic Docker container during the build. If the container is shared across operators or the build path is inspectable, a co-tenant can extract the raw encrypted payload and seed.
- The `vmloader_builder` binary is a native Linux executable compiled from source during `make embedded`. It is stateless and discarded after use; it does not persist between builds.
- Build logs from `make embedded` (stdout/stderr) are captured into `builder.py`'s `output` buffer and surfaced in the Mythic build step. These logs include compiler output that may reveal the Docker container's MinGW version and include paths.

**Improvements - For Operators**
- No operator-visible actions; this is a pipeline detail.

**Improvements - For Erebus Developers**
- Run `make clean` after a successful build inside the Mythic container so `embedded.h` (which contains the full encrypted payload) does not persist on disk between builds.
- Add a build-step separator for the embedded step in the Mythic UI so operators can distinguish `vmloader_builder` compilation failures from loader cross-compilation failures.

---

## Containers

### ISO (Optical Media)

*ISO9660/Joliet disk image that Explorer mounts as a drive when double-clicked.*

**OPSEC Considerations**
- Windows 11 22H2 introduced MOTW propagation to files extracted from ISO mounts - this closed the long-standing "ISO bypasses SmartScreen" gap. Pre-22H2 Windows still has the bypass.
- The ISO's volume label is visible in Explorer and is a *static* indicator that an analyst can extract from the ISO header via `file` or `isoinfo`.
- Mounting an ISO triggers `Sysmon Event ID 12` (registry) and `Event ID 1` (process creation for `explorer.exe`'s mount handler) on instrumented hosts.
- The `autorun.inf` mechanism is **ignored on hard-disk-class volumes** by default since Windows 7 - it only works on explicitly-whitelisted removable media. Erebus still writes it but operators should not rely on it triggering execution.

**Improvements - For Operators**
- Choose a volume label that matches the lure pretext: `WINDOWS_UPDATE`, `DRIVER_PKG`, `Q4_INVOICES`, `HR_ONBOARDING`.
- Target Windows 10 / pre-22H2 Windows 11 explicitly if MOTW-bypass is critical to the chain.
- Don't enable `AutoRun.inf` - it provides no execution benefit and adds a filesystem artefact the defender will see.
- Hide every file in the ISO except the single trigger (LNK / BAT / MSC) so the victim sees only the clickable target.

**Improvements - For Erebus Developers**
- Add a BuildParameter for a custom volume label randomisation pattern (e.g. `INVOICE_{random}`) so operators don't have to manually vary it across builds.
- Surface a warning in the UI when ISO + Windows 11 22H2 are both expected - the bypass no longer works.

### 7z Archive

*7-Zip archive with optional header encryption and AES-256 for file content.*

**OPSEC Considerations**
- 7z archive format is less common than ZIP; some email gateways and secure file-transfer systems strip or block it by default.
- Password protection (without header encryption) still leaks the file list to any scanner.
- 7z's compressed-signature heuristics are well-known to gateway AV; large 7z attachments trigger size-based filters.

**Improvements - For Operators**
- Always enable header encryption (`-mhe=on` in 7z CLI terms - Erebus does this by default when a password is set).
- Use passwords that are short enough for the victim to type from the lure email (8–10 chars), not randomly generated ones.
- Pre-test delivery via the intended channel (Gmail, O365, Proofpoint) - 7z block rates vary dramatically by provider.

**Improvements - For Erebus Developers**
- Expose `mhe=on/off` as an explicit parameter rather than inferring from password presence, so operators can turn it off intentionally for environments that block header-encrypted 7z.

### ZIP Archive

*Standard ZIP with optional ZipCrypto or AES password protection.*

**OPSEC Considerations**
- ZIP is universally accepted and is the lowest-friction archive format for email delivery.
- The file list is always visible, even in password-protected archives (this is a ZIP spec limitation - only file contents are encrypted).
- ZipCrypto (the default password format for older ZIP writers) is cryptographically broken; modern ZIP tools warn about it.
- Windows' built-in ZIP viewer does not support AES-encrypted ZIPs - victims need 7-Zip or WinRAR installed.

**Improvements - For Operators**
- Match the ZIP encryption format to the target environment's available decompression tools. Default Windows = ZipCrypto; enterprise environments with 7-Zip/WinRAR = AES.
- Choose innocuous file names for every file in the archive so the visible file list looks benign; rely on the trigger file extension filter to hide the decoys.

**Improvements - For Erebus Developers**
- Expose an explicit encryption choice (ZipCrypto vs AES-256) rather than picking one implicitly.

### MSI (Windows Installer)

*Windows Installer database built via `wixl` (msitools) on Linux. Can optionally backdoor an existing MSI via `5.3 Enable MSI Backdoor`.*

**OPSEC Considerations**
- MSI installation writes to `%SystemRoot%\Installer\` (per-machine) or `%LocalAppData%\Temp\MSI*.LOG` (verbose logging) - both are forensic-friendly artefact locations.
- MSI rollback is expected to work by the Windows Installer service; if an MSI fails to install "cleanly" (e.g. because the payload crashes the installer), rollback leaves the payload paths still registered in the Installer database.
- Machine-scope installation requires a UAC prompt unless the MSI is launched via a Group Policy elevated context.
- A backdoored MSI's original checksum is visible to integrity scanners that baseline common software; backdooring a signed MSI breaks its signature.
- MSIs register in Add/Remove Programs by default, which is visible to any user.

**Improvements - For Operators**
- Prefer User-scope installation for email delivery (no UAC).
- For Machine-scope, pair with a plausible `5.0 MSI Product Name` and `5.1 MSI Manufacturer` that match a software category the organisation would install (e.g. a CAD plugin for an engineering firm).
- If backdooring an existing MSI, strip the original signature via `osslsigncode remove-signature` before re-delivery - a broken signature is worse than no signature.
- Disable verbose MSI logging via registry (`HKLM\Software\Policies\Microsoft\Windows\Installer\Logging`) in the payload's execution chain to suppress the `%TEMP%\MSI*.LOG` trail on the victim.

**Improvements - For Erebus Developers**
- Add an "uninstall entry suppression" option that omits the Add/Remove Programs registration.
- Add a signature-strip step to the backdoor flow so operators don't have to do it manually.

### Electron Fake-Installer

*Single portable Windows `.exe` built with `electron-builder` under wine. Wraps the compiled loader as an `extraResources` tree and presents a Next / Install / Finish wizard that extracts to `%TEMP%\inst-<uuid>` and spawns the loader hidden + detached on "Install" click. A two-stage interaction gate plus a configurable set of environment guardrails defers the copy-to-temp step until after real user interaction has been observed and every enabled check has passed.*

**OPSEC Considerations**
- At install-time the Electron runtime extracts the entire app (app.asar + native modules + resources) to `%USER%\AppData\Local\Temp\<portable-uuid>\` **before** the wizard even opens - this is ~75–90 MB of filesystem activity visible to any file-write-monitoring EDR. **The guardrails do not prevent this initial extraction**; they only prevent the *loader tree* being copied from `resources/payload/` to a second `%TEMP%\inst-<uuid>` tempdir until the user interacts.
- When guardrails are disabled, a sandbox auto-clicker that tabs through the wizard's Next button reaches the `installer:run` IPC handler in < 50 ms and the loader copy fires immediately.
- When guardrails are enabled (default), the `installer:run` handler is two-gate protected:
  1. **Interaction token gate** - the renderer must acquire a one-shot random token via `installer:ready`, which the main process only issues after the configured dwell time has elapsed AND a real `mousemove` with non-zero movementX/Y deltas has been observed inside the window. A sandbox that invokes `installer:run` directly (without going through the UI) is rejected because the token was never issued.
  2. **Environment guardrail gate** - `runGuardrails()` re-checks for debugger attachment, sandbox env vars, default bad usernames/hostnames, operator-supplied username/hostname white/blocklists, minimum screen resolution, minimum CPU count and RAM, maximum system idle time, and an optional pre-spawn sleep. If any enabled check fails, the handler returns before touching the filesystem.
- Guardrail check results are **not logged** anywhere visible - failure is silent, and the wizard looks like it succeeded (fake progress bar runs to completion, then Finish is shown). This is intentional: a defender running the sample in a sandbox sees a successful-looking installer and no loader execution.
- Even with guardrails enabled, the portable-app extraction in `%USER%\AppData\Local\Temp\<portable-uuid>\` contains `resources/payload/` with the loader tree on disk before the wizard opens - the guardrails protect the *second* copy, not the first. An analyst who dumps the portable-app tempdir before any interaction still recovers the loader.
- The staged `resources/payload/` tree is **allowlisted** at build time by `_stage_payload` in [container_electron.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/archive/container_electron.py) to contain exactly one file: the single `erebus.{exe,dll,xll}` loader binary that matches the configured `3.E4 Electron Entry Format`. Every other top-level file in `payload/` is dropped; every subdirectory is dropped. This means ClickOnce satellite DLLs, trigger sidecars (`clickonce_trigger/`), decoy files, operator bookkeeping (`IOCs.txt`, `erebus_helper.py`, `build_*.bat`, …), and MalDoc artefacts never land in `%TEMP%\inst-<uuid>` when the wizard fires `cpSync`. ClickOnce loaders that depend on satellite DLLs are therefore not compatible with the Electron container - use the Shellcode Loader (which publishes as a self-contained single file) for Electron-wrapped payloads, or wrap the unmodified ClickOnce tree in an ISO/7z container instead.
- **Post-run cleanup is not performed.** The Electron main process exits after the fake wizard advances to Finish; the `%TEMP%\inst-<uuid>\` directory containing the staged loader copy persists until the victim manually clears `%TEMP%`. No batch watcher, no `MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT` fallback. An analyst with access to `%TEMP%` post-run recovers the staged loader tree intact.
- The portable exe is built via wine on Linux, which means `wine` build provenance (specific wine version, PE timestamps generated by `mingw-w64` + `electron-builder`) is baked into the final binary. Samples from the same Erebus Docker image share these static indicators.
- PE resource metadata (File Description, Product Name, Product Version, File Version, Copyright, Company) is fully operator-controlled via BuildParameters `3.E0` / `3.E1` / `3.E2` / `3.E7` / `3.E8`. **If these are left as defaults** (`Acme Installer`, `Acme Corporation`, empty copyright) the loader is trivially attributable to Erebus.
- Custom icons are baked via `rcedit` (called by `electron-builder` under wine); an analyst who extracts the ICO from the PE can compare icon hashes across samples.
- The wizard UI's HTML/CSS/JS lives in `app.asar` which is a plain concatenated archive - any analyst with `asar extract` can read the source of `src/main.js`, `src/renderer/wizard.js`, `src/guardrails.js`, etc. directly. **The guardrail check list is visible to static analysis.**
- The spawned child process has the portable-exe as its grandparent, which is an unusual lineage shape (`ErebusInstaller.exe` → `<electron-wizard-child>` → `cmd.exe/erebus.exe`).
- **Persistence (`3.P0 – 3.P3`)** - when enabled, `reg.exe` or `schtasks.exe` is invoked via `execFileSync` inside the wizard's `installer:run` handler. Both are signed Windows binaries, but spawning `reg.exe` from an Electron process is an unusual parent lineage and will be flagged by process-tree-aware EDRs. The registry key/task name is set to `3.P2 Persistence Name` (defaults to product name) - use a plausible application-maintenance name rather than anything that matches known Erebus defaults. The loader copy at `%APPDATA%\<name>\<loader>` or `%LOCALAPPDATA%\<name>\<loader>` remains on disk permanently - ensure the loader's own PE metadata matches the persistence name for consistency.

**Improvements - For Operators**
- **Keep guardrails enabled** (`3.E9 Enable Electron Guardrails = True`, default). The default dwell time of 2500 ms + required mouse movement defeats the most common auto-click sandbox detonators without affecting real victims.
- **Fill in every PE resource field** (`3.E0`, `3.E1`, `3.E2`, `3.E7`, `3.E8`) with values matching a plausible enterprise vendor. Review the Details tab on the final exe *before* shipping.
- Upload a custom icon via `3.E6a Electron Custom Icon` that matches the spoofed vendor - the default Erebus icon is a straight giveaway.
- Pair with `6.0 Codesign Loader` enabled (SelfSign + Spoof URL at minimum) so the signature certificate's CN matches the PE metadata's CompanyName.
- Avoid `entry_format = dll` (rundll32 parent) unless the surrounding chain explicitly justifies it - `rundll32.exe` spawned from an installer is unusual.
- For targeted engagements, populate `3.E9i Username Whitelist` and/or `3.E9g Hostname Whitelist` with the specific victim identity - the installer then refuses to run on every host except the intended one. This is the single highest-value guardrail for spear-phishing scenarios.
- Use `3.E9p Pre-Spawn Delay (ms)` to add a 5–15 second sleep before the file copy and spawn when targeting sandboxes with short detonation timeouts (1–3 minutes typical).
- Verify the staged `resources/payload/` tree inside the NSIS contains only victim-facing files. The `_stage_payload` filter drops operator bookkeeping at build time, but if you add new files to `payload/` in the future, confirm they're either victim-facing or covered by the exclude list before shipping.
- When `3.P0 Enable Persistence = True`, the loader is copied to `%APPDATA%\<name>\` or `%LOCALAPPDATA%\<name>\` before spawn. The copy is visible on disk permanently. For targeted engagements, populate `3.P2 Persistence Name` with a plausible application name matching the spoofed vendor rather than leaving it as the product name default.

**Improvements - For Erebus Developers**
- Add a `builder.py` preflight that refuses to build if any PE resource BuildParameter is left at its default value (warning only, not error, so operators can override).
- Add per-build asset-level salting to `src/main.js`, `src/guardrails.js`, and `src/renderer/wizard.js` (randomised identifiers, string shuffling) so two builds don't share byte-for-byte asar contents and the guardrail check names aren't a static fingerprint.
- Scrub the wine build timestamps from the PE headers via a post-build `osslsigncode`-style rewrite.
- Add a post-run cleanup mechanism - options include a `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` registration for the inst-tree (requires shelling to a native PE helper), a compiled cleanup helper spawned detached after loader exit, or `FILE_FLAG_DELETE_ON_CLOSE` on the extracted files before spawn.
- Add persistence OPSEC improvements: when `3.P0 Enable Persistence` is enabled, the registry key or scheduled task name is currently the raw product name, which is operator-controlled but not obfuscated. Consider per-build random name generation as a default with the operator-supplied name as an override.
- Add a guardrail for detecting mouse-click automation via timing distribution analysis (real human clicks arrive with distinctive inter-event timing; automation is too regular or too fast).
- Add a guardrail that checks `%USERPROFILE%\Recent` or `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` for a non-empty history - real users have recent files, fresh sandbox VMs don't.
- Encrypt the entire `resources/payload/` tree on disk inside the asar/extraResources so the initial portable-app extraction doesn't expose the loader tree plaintext. Decrypt after guardrails pass.
- Add a BuildParameter for alternative host process names for the rundll32 case (or replace rundll32 with `regsvr32` / `.NET rundll` for less signatured parents).

---

## Code Signing

### Self-Signed Certificates

*Erebus generates an X.509 cert via OpenSSL and signs the payload with `osslsigncode`.*

**OPSEC Considerations**
- A self-signed certificate's CN appears on the victim's **Digital Signatures** tab, so the CN choice is a user-visible lure element.
- Self-signed certs have **no SmartScreen reputation** - the victim sees a "Windows protected your PC" warning even if the binary is technically signed.
- Chain validation fails; any AV or allow-list (WDAC, AppLocker) that requires a trusted publisher rejects the binary.
- The private key never leaves the Erebus Docker container, but the cert itself is fingerprintable - multiple payloads signed with the same Erebus build share a CA public key signature.

**Improvements - For Operators**
- Set `6.2 Codesign CN` to match the PE ProductName / CompanyName fields exactly - inconsistency between signature CN and shell properties is a fast-scan signal.
- Rotate the self-signed cert per campaign by rebuilding the Docker container (current Erebus generates one per build, but confirm this in your environment).
- Treat self-signed as a *visual* signal only - it does not help with SmartScreen or allow-list bypass.

**Improvements - For Erebus Developers**
- Cache self-signed certs on disk with a configurable rotation policy so operators can explicitly choose "same cert across campaign" vs "per-build rotation".

### Spoof URL (Certificate Cloning)

*Fetch the SSL certificate details from a remote URL (`6.4 Codesign Spoof URL`) and apply those details to a self-signed cert.*

**OPSEC Considerations**
- Same chain-validation failure as plain self-signing - this is cosmetic spoofing only.
- Deep inspection (e.g. a defender clicking through to Certificate Details → Certification Path) still shows the self-signed root.
- The spoofed target URL is a clue: cloning `microsoft.com`'s certificate is higher-profile than cloning a legitimate small-business cert.

**Improvements - For Operators**
- Choose a small/medium business URL with a lot of lookalike candidates on the target's supply chain rather than a flagship tech company - `microsoft.com` and `google.com` are the most-cloned certs in detection tooling.
- Pair the spoofed CN with matching PE metadata across the entire build.

**Improvements - For Erebus Developers**
- Add caching of fetched cert details so a campaign can reuse the same spoofed identity without re-fetching.

### Provided Certificate

*Operator supplies a PFX/P12 via `6.5 Codesign Cert`.*

**OPSEC Considerations**
- A genuine EV / OV code-signing cert gives real SmartScreen reputation and WDAC/AppLocker compliance, but exposes the cert to revocation.
- If the cert is used across multiple campaigns or multiple samples are collected by a vendor, the revocation race becomes inevitable.
- Provided certs baked into Mythic's payload database can be extracted by anyone with access to the Mythic instance - treat the Mythic server as cert-sensitive.

**Improvements - For Operators**
- Use provided certs only for the specific sample(s) that need them; don't batch-sign an entire campaign with one.
- Revoke the cert proactively at the end of the engagement rather than waiting for the CA to revoke it - this is better PR when the sample surfaces in VirusTotal.
- Store the cert PFX password separately from the cert itself in the Mythic upload (Erebus supports this via `6.6 Codesign Cert Password`).

**Improvements - For Erebus Developers**
- Add a "single-use" flag that deletes the cert from Mythic after one successful build so it can't be reused accidentally.

### What Signing Buys You vs. What It Doesn't

*Summary of the tradeoffs across the three signing modes so operators and developers share the same mental model.*

**OPSEC Considerations**

*Signing always gives you:*
- A CN / ProductName pair on the Digital Signatures properties tab (user-visible).
- PE header `IMAGE_DIRECTORY_ENTRY_SECURITY` data which some static scanners treat as a "likely legitimate" signal.

*Signing only gives you with a trusted cert:*
- SmartScreen pass (reputation-based, takes time to accrue).
- WDAC / AppLocker publisher-rule compliance.
- Absence of the "Windows protected your PC" SmartScreen warning.

*Signing never gives you:*
- Bypass of AV behavioural detection.
- Bypass of AMSI / script-based scanners.
- Legitimate chain validation against self-signed or spoofed certs.

**Improvements - For Operators**
- Always sign (even self-signed) - an unsigned binary is worse than a self-signed one because modern scanners treat unsigned as "suspicious".
- Match the signature's CN to the rest of the payload's lure pretext (PE ProductName, Electron wizard Product, filename).

**Improvements - For Erebus Developers**
- Add a post-build signing verification step that confirms `osslsigncode verify` at least parses the signature correctly before the payload ships.

---

## Trigger Mechanisms

### LNK (Shortcut)

*A Windows `.lnk` file that executes a target binary with command-line arguments, plus optional icon + decoy.*

**OPSEC Considerations**
- The target path and arguments are stored in cleartext in the `.lnk` file - any analyst with `lnkparser` or `pylnk3` can read them.
- LNK files with command-line arguments pointing to `cmd.exe`, `powershell.exe`, or `conhost.exe` are a known phishing pattern and are flagged by Sentinel / Defender rules.
- Windows Event ID 4688 logs process creation with the full command line for elevated sessions and for any session with command-line auditing enabled - this captures the LNK's entire command as the parent process spawns the target.
- The LNK icon resolution (e.g. `%SystemRoot%\system32\shell32.dll,0`) is stored in the LNK and is visible as a string.

**Improvements - For Operators**
- Keep the command line as short as possible; chain complex logic into a BAT file that the LNK launches rather than embedding everything in the LNK args.
- Choose an icon that matches the lure pretext (PDF icon for a fake invoice, Office icon for a fake document).
- Avoid the default `conhost.exe` trigger binary - it's specifically fingerprinted in phishing-LNK YARA rules. Prefer `cmd.exe` or a specific system binary matching the pretext.
- Hide the LNK inside an ISO container so the target path doesn't appear in a file's extended attributes.

**Improvements - For Erebus Developers**
- Add a BuildParameter for the LNK description string so operators don't all ship the default "Invoice" value.
- Add an option to omit the icon resolution string entirely (use the default system icon) to reduce static content.

### BAT (Batch Script)

*Plain-text batch file that executes the trigger binary with arguments and optionally launches the decoy.*

**OPSEC Considerations**
- Batch files are the most-inspectable trigger format - every command is cleartext and any `findstr` pass reveals the payload chain.
- Command-line auditing + PowerShell script-block logging capture every command the BAT executes.
- AMSI does *not* scan BAT files directly, but every `powershell` / `cscript` / `mshta` invocation inside the BAT is scanned.
- `cmd.exe /c` with complex argument strings is a known phishing pattern (Defender rule `T1059_001`).

**Improvements - For Operators**
- Keep the BAT minimal: `start "" erebus.exe & start "" decoy.pdf` or equivalent. Don't use environment-variable tricks or `%~dp0` resolution that looks clever - those are specifically signatured.
- Use a BAT only when the lure pretext plausibly uses one (legacy software install script, SCCM deployment runner, etc.). For modern lures, prefer LNK or MSC.
- If the BAT must invoke PowerShell, pre-encode the PowerShell payload as base64 to defeat `findstr`-based static scanning but accept that AMSI will still see it.

**Improvements - For Erebus Developers**
- Default to a minimal two-line BAT template; make verbose/multi-command templates opt-in.
- Add an option to emit the BAT in UTF-16LE with a BOM - some older defender rules only scan ASCII BATs.

### MSI (Trigger Mode)

*The same MSI container format, but used as a direct trigger (victim double-clicks an MSI that contains the payload as a custom action) rather than wrapping the payload in a standalone MSI.*

**OPSEC Considerations**
- Same event-log and Installer-directory considerations as the MSI container section above.
- Trigger-mode MSIs often run with different execution sequences than standalone MSIs, which an analyst comparing to a normal installer database can spot.

**Improvements - For Operators**
- Same guidance as the MSI container entry - prefer User-scope, match product name + manufacturer to a plausible vendor.

**Improvements - For Erebus Developers**
- See MSI container entry.

### MSC (Management Console Snap-in)

*XML-based `.msc` file opened by `mmc.exe` that chains execution of the trigger binary via a `TaskpadView` or `Link` element.*

**OPSEC Considerations**
- `.msc` files are text XML - an analyst with any text editor can read the embedded command chain immediately.
- Process lineage: the payload spawns as a child of `mmc.exe`, which is *unusual* for most payloads (real MSC snap-ins rarely spawn anything). Process-tree detections that baseline `mmc.exe`'s children catch this.
- MOTW is applied to MSC files downloaded directly from the web, which triggers Defender's SmartScreen dialog on double-click.
- MSC files extracted from an ISO container pre-Windows 11 22H2 bypass MOTW, but this is the same MOTW bypass every other ISO'd file gets.
- Some Windows SKUs (Home) do not ship the full MMC console; MSC triggers fail silently on those hosts.

**Improvements - For Operators**
- Always deliver MSC inside an ISO container; direct download triggers MOTW + SmartScreen.
- Target business SKUs only (Pro / Enterprise / Education); verify Windows Home is not in scope.
- Minimise the embedded command - prefer a single `cmd.exe /c erebus.exe` over any longer chain.

**Improvements - For Erebus Developers**
- Add a BuildParameter for the MSC snap-in's display name / description so each build doesn't have an identical XML fingerprint.
- Consider emitting the MSC with a `Link` element (less common) rather than `TaskpadView` (more common) based on the target environment.

### ClickOnce (Trigger)

*A `.application` manifest hosted via HTTP/HTTPS that triggers ClickOnce deployment when the victim clicks the link.*

**OPSEC Considerations**
- Cached application files end up in `%LocalAppData%\Apps\2.0\` - a forensic-friendly location that defenders routinely parse.
- The deployment manifest URL is embedded in the `.application` and is reachable via a simple HTTP GET; any analyst clicking the link downloads the same payload the victim does.
- SmartScreen learns URL reputation over time, so fresh deployment URLs start at zero reputation and progressively warm up.
- Signed deployment manifests improve the SmartScreen score but require an actual code-signing cert (same cert considerations as the signing section above).
- ClickOnce runs the application in the user's context only - no privilege escalation, no SYSTEM.

**Improvements - For Operators**
- Host the deployment manifest on infrastructure that has been warmed up for at least 48–72 hours before the campaign.
- Sign the `.application` manifest with the same cert used for the payload binary for signal consistency.
- Expire the hosting URL immediately after the engagement ends to limit forensic recovery windows.

**Improvements - For Erebus Developers**
- Add a BuildParameter for the deployment manifest expiration date so operators can encode a hard cutoff.

### HTML Smuggling

*Self-contained HTML page with the loader XOR-encoded (per-build 16-byte random key) and base64-embedded; JavaScript reverses both layers and reconstructs a `Blob` for download.*

**OPSEC Considerations**
- The reconstructed file is MOTW-tagged by the browser on save - the victim still sees "File from the internet" on first launch.
- Gateway content inspection that runs headless browsers can execute the JavaScript and recover the reconstructed file server-side; some modern SEGs (Mimecast, Proofpoint) do this.
- `navigator.msSaveOrOpenBlob` and `URL.createObjectURL` + `a.click()` patterns are specifically scanned by endpoint DLP and some EDRs.
- Base64 + XOR is sufficient to defeat static gateway YARA rules, but a live browser rendering the page sees the decoded bytes in JavaScript memory.
- The HTML page's visible content (page title, heading, download button text) is a lure element the analyst inspects.

**Improvements - For Operators**
- Match `page_title`, `heading`, `message`, `button_text`, and `download_name` to the lure pretext. Default text ("Loading document...") is a giveaway.
- Use a realistic `download_name` matching a plausible document/installer for the target (`Invoice-Q4.exe`, not `update.exe`).
- Host on a short-lived low-reputation domain; HTML smuggling pages are often detected post-hoc via URL reputation rather than content scanning.
- Set `delay_ms` to something longer than the default (3000–5000 ms) so the download doesn't fire during the page's load telemetry burst.

**Improvements - For Erebus Developers**
- Replace XOR with a per-build AES key derived from a simple password - the XOR layer is the weakest part of the current chain.
- Split the base64 payload into multiple chunks concatenated at runtime so the string length doesn't match "big base64 blob" YARA rules.
- Randomise the JavaScript variable identifiers per build (already done for the payload variable; extend to every function in the script).
- Add an optional browser-fingerprint gate that only decodes the payload if a specific UA / language / referer matches, so gateway browsers (which sandbox with odd UAs) can't extract the file.

### ClickFix (Clipboard Lure)

*A fake CAPTCHA HTML page that copies a configured command to the victim's clipboard via `navigator.clipboard.writeText` and walks the victim through Win+R → Ctrl+V → Enter.*

**OPSEC Considerations**
- `navigator.clipboard.writeText` requires user activation (a click event), which is satisfied by the verify button - this is not a detection signal, it's a browser spec requirement.
- Some EDR products (CrowdStrike, SentinelOne recent builds) hook `navigator.clipboard.writeText` at the browser level and log the clipboard content. A defender with this capability sees the PowerShell cradle immediately.
- The pasted command runs via `powershell.exe` launched from `explorer.exe` (the Run dialog's parent), which is a known phishing pattern and is flagged by Defender for Endpoint's `T1059.001 PowerShell` rule.
- The Run dialog's history is persisted to `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` - forensic analysts routinely parse this registry key and it contains the exact command the victim ran.
- AMSI scans the PowerShell command before execution; any `iwr` / `Invoke-WebRequest` / `DownloadString` pattern is high-signal.
- The HTML page itself contains zero executable content - it's a lure page, not a payload. This is both a feature (no AV signature on the HTML) and a limit (all detection happens at the downstream `powershell.exe` process).

**Improvements - For Operators**
- Minimise the PowerShell command length - anything over ~150 characters doesn't fit cleanly in a single Run-dialog paste and the victim notices.
- Avoid `iwr` / `Invoke-WebRequest` verbs when possible; prefer `curl` (on Windows 10+ aliased to `Invoke-WebRequest` but invoked via the alias doesn't trigger some pattern scanners).
- Use an AES-encoded PowerShell stager (via `-EncodedCommand`) to hide the exact URLs from AMSI's initial scan - accept that AMSI will still see the decoded command once the stager runs.
- Match the lure brand (`brand_name`, `brand_color`, `verification_heading`) to a service the target environment actually uses. Cloudflare and Google reCAPTCHA are the most-used ClickFix lure brands in detection rules - pick something less signatured.
- Warn operators in campaign planning that the `RunMRU` registry key retains the command for forensic analysis.

**Improvements - For Erebus Developers**
- Add a BuildParameter for a pre-encoded PowerShell stager so operators don't have to encode their own.
- Consider adding a post-execution "clear RunMRU" sub-command that runs as part of the pasted command (e.g. `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /f`), though this is itself a detection pattern.
- Add `curl` / `Invoke-RestMethod` as command alternatives in the default template so operators rotate through stager verbs.
- Add a per-build randomised function/variable name pass to the generated HTML/JS so two builds don't share JS fingerprints.

---

## Linux / macOS Trigger Mechanisms

### Bash Script (.sh)

*Bash script that backgrounds the payload via `nohup` with optional base64 eval obfuscation. Used for both Linux and macOS targets.*

**OPSEC Considerations**
- `nohup` itself is not suspicious, but the child process it spawns is attributed to the script's parent shell - visible as a process whose `ppid` points to `bash`.
- `auditd` on hardened Linux hosts logs `execve` for every process including nohup child launches; the payload binary path appears in the audit log.
- Base64 eval (`eval "$(echo <b64> | base64 -d)"`) defeats simple string scanning but is itself a well-known obfuscation pattern detected by YARA rules for `eval.*base64`.
- On macOS, `EndpointSecurity`-based EDR (CrowdStrike Falcon for Mac, SentinelOne) subscribes to `ES_EVENT_TYPE_NOTIFY_EXEC` and sees every process launch regardless of whether a terminal window appears.
- The script must have `+x` set before the victim can run it; an operator delivering via ZIP should `chmod +x` in the build note or use a `.command` wrapper on macOS (which Terminal.app marks executable before running).

**Improvements - For Operators**
- Deliver inside a ZIP - on macOS the ZIP's `+x` bit is preserved on extraction (unlike a direct download, which loses it in some browser decompressors).
- Use a short-lived payload path inside `/tmp` or the user's `~/.cache/` to match legitimate background tooling patterns; avoid `/Users/<victim>/Desktop/payload`.
- On Linux, check if `auditd` is running before execution - if it is, the `execve` event is logged; there is no operator-side mitigation short of abusing an existing allowed binary.

**Improvements - For Erebus Developers**
- Add a `setsid` variant as an alternative to `nohup` - `setsid` creates a new session and is slightly less signatured than `nohup` on modern Linux.
- Add an optional sleep jitter at the top of the script so execution doesn't happen during the first-launch telemetry burst.

### Desktop File (Linux)

*XDG `.desktop` application launcher that executes via file manager double-click.*

**OPSEC Considerations**
- GNOME 42+ marks `.desktop` files downloaded via browser with an untrusted xattr and shows a dialog; this is bypassed by delivering inside a ZIP archive.
- KDE Plasma shows a "Do you want to run this?" prompt on first execution regardless of download source - there is no bypass; the victim must click Run.
- The `Exec=` field is cleartext - any analyst with a text editor or `grep` sees the exact command.
- File managers log recent-document open events to `~/.local/share/recently-used.xbel`, which is a forensic artefact visible after incident response.
- XFCE (Thunar) executes `.desktop` files silently on double-click with no prompt - highest friction-free delivery success rate.

**Improvements - For Operators**
- Deliver inside a ZIP or TAR to bypass GNOME's quarantine marking.
- Target XFCE or LXDE desktops for lowest victim friction; warn the operator if targeting a GNOME environment that the Run prompt will appear.
- Match `Name=` and `Icon=` to a plausible document type for the lure (e.g. `application-pdf` icon + `Name=Invoice Q4 2024`).

**Improvements - For Erebus Developers**
- Add a BuildParameter for `Name=` and `Icon=` so operators don't have to rely on the "PDF Document" default.
- Obfuscate the `Exec=` line by splitting the command across a wrapper script dropped alongside the `.desktop` file, so the `.desktop` itself only references a benign-looking script name.

### macOS .command File

*Bash script with `.command` extension; Terminal.app opens and runs it on Finder double-click.*

**OPSEC Considerations**
- Terminal.app's launch is itself visible in the Unified Log (`com.apple.terminal`) and to `EndpointSecurity` subscribers.
- The `osascript` call to close Terminal generates additional ES events (`ES_EVENT_TYPE_NOTIFY_EXEC` for `osascript`) - two unusual processes fire instead of one.
- Gatekeeper quarantines `.command` files downloaded directly via browser (xattr `com.apple.quarantine`); files extracted from a ZIP archive on macOS ≤ 12 do not inherit the quarantine xattr.
- On macOS 13+ (Ventura) Gatekeeper's xattr propagation from archives is more aggressive; test the delivery chain against the target macOS version before the engagement.
- `nohup.out` is suppressed by redirecting to `/dev/null` - the script must do this explicitly or nohup writes output to `nohup.out` in the user's working directory.

**Improvements - For Operators**
- Deliver inside a ZIP and instruct the victim to extract before running (standard social-engineering instruction).
- Sign the `.command` file or the wrapping ZIP with an Apple Developer ID if available - this passes Gatekeeper and removes the quarantine dialog.
- Keep the terminal window closed via the `osascript` block; a lingering Terminal window is the most obvious tell to a victim.

**Improvements - For Erebus Developers**
- Add a `close_terminal=False` option for environments where `osascript` is blocked or logged (e.g. enterprise MDM that restricts `osascript`).
- Add a delay before the `osascript` close call so the terminal doesn't visibly flash before disappearing - 500 ms is usually sufficient.

### macOS AppleScript (.scpt)

*AppleScript source file executed via `osascript`. Runs the payload via `do shell script` with no window.*

**OPSEC Considerations**
- `osascript` is a signed macOS binary - its child processes are attributed to it, not to the original lure. Process lineage: `Finder → osascript → sh → payload`.
- `do shell script` runs commands via `/bin/sh`; this is logged by `EndpointSecurity` (`ES_EVENT_TYPE_NOTIFY_EXEC` on `/bin/sh`).
- Double-clicking a `.scpt` file in Finder opens Script Editor (not `osascript`), which shows the source code to the victim before they click Run - always combine with a `.command` wrapper that runs `osascript update.scpt` in the background.
- TCC (Transparency, Consent, and Control) may prompt if `do shell script` touches protected directories (`~/Desktop`, `~/Documents`, `~/Downloads`, APFS volumes).
- The char-code obfuscation (`character id N`) is effective against static string scanners but any analyst who runs the script sees the reassembled command in plain text.

**Improvements - For Operators**
- Never hand a bare `.scpt` directly to the victim via Finder - they will see Script Editor open with the source code. Always wrap in a `.command` that runs `osascript` non-interactively.
- Keep the command path inside `/tmp` or `~/.cache/` to avoid TCC prompts from protected user directories.
- Sign the `.command` wrapper with a Developer ID so Gatekeeper doesn't flag the chain.

**Improvements - For Erebus Developers**
- Add a `.command` wrapper that calls `osascript` to the AppleScript trigger output so the operator gets both files together and doesn't have to create the wrapper manually.
- Add a `with administrator privileges` option as an opt-in parameter (off by default - it prompts the victim for a password, which is appropriate for some social-engineering scenarios).

### macOS PKG Installer

*macOS PKG installer with a `postinstall` bash script that executes the payload. Installer.app runs the script as root.*

**OPSEC Considerations**
- `postinstall` running as root is visible in the Unified Log under `com.apple.Installer` and in `system_profiler SPInstallHistoryDataType` - the package identifier (`bundle_id`) and installation time are permanently recorded.
- Gatekeeper quarantines unsigned PKGs downloaded from the internet; Installer.app shows "Apple cannot check this for malicious software" on macOS 12+ for unsigned packages and on macOS 15+ unsigned PKGs are rejected outright for most distribution paths.
- `nohup` inside `postinstall` detaches the payload from Installer.app's process group; the payload's parent PID in `ps` will be 1 (launchd) once Installer exits.
- The payload binary written to `install_location` (default `/tmp`) persists on disk until manually cleaned up.
- On the Mythic Docker build host (Linux), `pkgbuild` is unavailable; the plugin emits a raw `pkg_project/` directory. Operators must assemble the final `.pkg` on a macOS host - and sign it there - before delivery.

**Improvements - For Operators**
- Sign the PKG with an Apple Developer ID Installer certificate and notarise it via `xcrun notarytool submit` to pass Gatekeeper on macOS 12+. Without notarisation the victim sees a warning dialog on macOS 14+.
- Set `bundle_id` to a plausible reverse-DNS identifier (e.g. `com.adobe.acrobatupdate`) matching the lure pretext rather than the default `com.apple.systemupdate`.
- Set `install_location` to a user-writable path so `postinstall` doesn't require root elevation - but note that on many macOS versions, Installer always runs `postinstall` as root regardless of install scope.
- After the engagement, clean up the installation history: `pkgutil --forget <bundle_id>` removes the entry from `system_profiler` but leaves the files on disk.

**Improvements - For Erebus Developers**
- Add a BuildParameter for `bundle_id`, `pkg_name`, and `install_location` so operators don't edit the default values manually.
- Detect when `pkgbuild` is available and surface a build-step message confirming whether a real `.pkg` or a raw project directory was produced.
- Add a cleanup line to `postinstall` that runs `pkgutil --forget <bundle_id>` after the payload fires so the installation record is removed automatically.

---

## Decoy Files

*Optional non-malicious file shown to the victim alongside the payload (e.g. a legitimate PDF opened after the loader fires) to reduce suspicion and maintain the lure.*

**OPSEC Considerations**
- The decoy file inherits MOTW from whatever channel it was delivered via (ISO/ZIP/email attachment). Opening it triggers Defender SmartScreen on downloaded files.
- If the decoy's content doesn't match the lure pretext (e.g. a generic `decoy.pdf` for an "invoice" pretext), the victim's suspicion spikes rather than drops.
- Decoys are shown to the victim *after* the payload has already fired in most Erebus chains, so they serve as cover for the initial execution noise - but a delayed decoy display (> 2–3 seconds) means the victim sees a blank screen during the gap.
- Timing: the payload and decoy are usually launched from the same BAT/LNK, so their process start times are nearly simultaneous - any behavioural rule that correlates child processes sees both.

**Improvements - For Operators**
- Upload a lure-appropriate decoy via `0.13 Decoy File` rather than relying on the built-in default - the default is a generic stub that no real pretext would include.
- Match the decoy file type to the pretext: PDF for invoices, XLSX for reports, DOCX for contracts.
- Review the decoy for sensitive information: operators sometimes reuse decoys across engagements and accidentally leak customer names / internal paths.

**Improvements - For Erebus Developers**
- Ship an empty-decoy-is-not-okay warning when the operator builds with `Decoy File Inclusion = True` but no file is uploaded.
- Add a small catalogue of lure-appropriate decoy templates (blank invoice, blank HR form, blank meeting notes) so the default path isn't a generic stub.

---

## Erebus.Helper Deferred Builds

*When a feature requires Windows-side compilation (XLL, legacy MalDoc COM re-injection, deferred Electron builds), Erebus stages the source files + a `build_*.bat` runbook in `payload/` and the operator runs it on a Windows host via `erebus_helper.py`.*

**OPSEC Considerations**
- The staged source tree (`electron_src/`, `.cpp` files, `.bas` files) and the `build_*.bat` runbook are shipped **inside the same `payload/` directory** that gets delivered to the victim unless the operator removes them manually. If forgotten, the victim receives the build source + runbook alongside the actual payload.
- `erebus_helper.py` is a merged single-file export of the entire Erebus.Helper suite; it contains every Windows-side build function in the project. Leaking it to a target environment is a full tradecraft disclosure.
- Running the deferred build on an attributable Windows host (the operator's daily-driver VM) writes build-host fingerprints into the produced binary: PE timestamps, compiler version strings, path fragments from `npm` / `MSVC` / `dotnet` caches.
- `npm install` in the deferred Electron path pulls from the public npm registry, which logs the user-agent and build-host IP unless tunneled.

**Improvements - For Operators**
- **Strip every build artefact** (`electron_src/`, `build_*.bat`, `erebus_helper.py`, `.bas` files) from `payload/` before Mythic ships the final archive. Review the archive's file list manually.
- Run deferred builds on a dedicated throwaway Windows VM, not your daily driver. Clear `%TEMP%`, `%APPDATA%\npm-cache`, and the build output after each engagement.
- Route `npm install` traffic through a VPN or a dedicated egress so the build-host IP isn't correlated with your operational infrastructure.
- Verify the produced binary doesn't contain full paths from the build host (e.g. `C:\Users\operator\Desktop\build\...`) - run `strings | grep -i users` before shipping.

**Improvements - For Erebus Developers**
- Auto-strip build artefacts from `payload/` in the containerisation stage (exclude `electron_src/`, `build_*.bat`, `*.bas`, `erebus_helper.py` from the final archive by default).
- Add a warning when the final container includes `erebus_helper.py` - this should never be shipped to a target.
- Cache `npm install` output in the Erebus Docker image so deferred builds don't need the public npm registry (enables fully-offline deferred builds).
- Scrub PE timestamps via `osslsigncode` in the Electron build pipeline so build-host time isn't a forensic marker.

---

## Docker Container / Wine Build Footprint

*The Erebus Docker image provides the build environment: Python 3, MinGW-w64, wine, Node.js 20, electron-builder, Pillow, cairosvg, msitools, osslsigncode. Every produced payload inherits some fingerprints from this environment.*

**OPSEC Considerations**
- PE timestamps in the final binary reflect the build time inside the Docker container, which reveals a rough build-infrastructure uptime window if multiple samples are collected.
- MinGW-w64's runtime library shape is distinctive - every Erebus C++ loader shares the same runtime fingerprint. Samples can be clustered on this alone.
- Wine's version number is visible in the PE headers of electron-builder output (via the `rcedit` step); rapid fingerprinting tools like DIE (Detect It Easy) surface it.
- `node_modules/` contents in the Electron project contain the exact versions of every npm package used in the build; the `package-lock.json` fingerprint is identical across builds from the same Erebus version.
- The Docker image's layer hashes are reproducible from the `Dockerfile` - defenders who obtain a sample and reverse-engineer the build can recreate the exact image.

**Improvements - For Operators**
- Rebuild the Docker image before each high-value engagement so the `apt install` timestamps and package versions rotate.
- Run the Docker container with `--rm` and don't reuse build contexts across engagements.
- Don't build from a host whose public IP is attributable to your operational infrastructure; egress the Docker image's package installs through a scrubbed network.
- Review the final binary's PE header timestamps and runtime strings before delivery (`pefile` / `die` / `strings`).

**Improvements - For Erebus Developers**
- Add a reproducible-build mode that normalises PE timestamps to a fixed value (common pattern: `SOURCE_DATE_EPOCH` environment variable).
- Pin `node_modules/` versions so two operators with different Erebus install dates don't produce different Electron payloads.
- Strip wine / MinGW-w64 version strings from the built PE via a post-build rewrite step.
- Consider shipping an `apt-get clean` + layer-flattening Dockerfile so the public image doesn't contain every intermediate package cache.
- Document the exact fingerprints that are shared across all Erebus builds so operators know what to scrub before delivery.
