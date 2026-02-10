#ifndef EREBUS_XLL_CONFIG_H
#define EREBUS_XLL_CONFIG_H
#pragma once

#include <windows.h>

// Encryption: 0 = NONE, 1 = XOR, 2 = RC4
#define XLL_ENCRYPTION_TYPE {{XLL_ENCRYPTION_TYPE}}

// Injection: 0 = CreateThread (self), 1 = ProcessInject (remote)
#define XLL_INJECTION_METHOD {{XLL_INJECTION_METHOD}}

#define XLL_TARGET_PROCESS L"{{XLL_TARGET_PROCESS}}"

#define XLL_XLL_FILENAME L"{{XLL_XLL_FILENAME}}"
#define XLL_XLSX_FILENAME L"{{XLL_XLSX_FILENAME}}"
#define XLL_ZIP_FILENAME L"{{XLL_ZIP_FILENAME}}"

#endif
