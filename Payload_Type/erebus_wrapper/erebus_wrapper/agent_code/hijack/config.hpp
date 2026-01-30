#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

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
