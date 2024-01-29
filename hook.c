#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdarg.h>

// use msvcrt

//struct FILE *_stdout;
//struct FILE *fopen(const char *pathname, const char *mode);
//int fprintf(struct FILE*, const char *, ...);
//void fflush(struct FILE*);
//
//#define printf(...) fprintf(_stdout, __VA_ARGS__), fflush(_stdout)

#define GetCurrentProcess() ((HANDLE)-1)

int vsprintf(char *, const char *, va_list);
static CRITICAL_SECTION printf_lock;
static HANDLE hStdout;

NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID     *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

NTSYSCALLAPI NTSTATUS NtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	SIZE_T *NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);

NTSYSCALLAPI NTSTATUS NtWriteFile(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
);

NTSTATUS NTAPI LdrGetProcedureAddress(PVOID BaseAddress, PANSI_STRING Name, ULONG Ordinal, PVOID *ProcedureAddress);
NTSTATUS NTAPI LdrDisableThreadCalloutsForDll (PVOID BaseAddress);

NTSTATUS NTAPI RtlInitializeCriticalSection(PCRITICAL_SECTION);
NTSTATUS NTAPI RtlEnterCriticalSection(PCRITICAL_SECTION);
NTSTATUS NTAPI RtlLeaveCriticalSection(PCRITICAL_SECTION);

int printf(const char *fmt, ...) {
	static char buf[4096];

	va_list args;
	va_start(args, fmt);
	RtlEnterCriticalSection(&printf_lock);
	int r = vsprintf(buf, fmt, args);
	IO_STATUS_BLOCK IoStatusBlock = {};
	NtWriteFile(hStdout, NULL, NULL, NULL, &IoStatusBlock, buf, r, NULL, NULL);
	//DWORD w = 0;
	//WriteConsoleA(hStdout, buf, r, &w, NULL);
	RtlLeaveCriticalSection(&printf_lock);
	va_end(args);
	return r;
}

int puts(const char *s) {
	return printf("%s\n", s);
}

const char *get_exception_name(DWORD code) {
	switch (code) {
		case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
		case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
		case EXCEPTION_BREAKPOINT: return "EXCEPTION_BREAKPOINT";
		case EXCEPTION_SINGLE_STEP: return "EXCEPTION_SINGLE_STEP";
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
		case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
		case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
		case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
		case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
		case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
		case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
		case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
		case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
		case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
		case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
		case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
		case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
		case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
		case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
		case EXCEPTION_INVALID_DISPOSITION: return "EXCEPTION_INVALID_DISPOSITION";
		case EXCEPTION_GUARD_PAGE: return "EXCEPTION_GUARD_PAGE";
		case EXCEPTION_INVALID_HANDLE: return "EXCEPTION_INVALID_HANDLE";
		case EXCEPTION_POSSIBLE_DEADLOCK: return "EXCEPTION_POSSIBLE_DEADLOCK";
	}

	return NULL;
}

NTSTATUS (*my_NtOpenFile)(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  ULONG              ShareAccess,
  ULONG              OpenOptions
);

NTSTATUS hook_NtOpenFile(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  ULONG              ShareAccess,
  ULONG              OpenOptions
  ) {
	LPWSTR path = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
		path = ObjectAttributes->ObjectName->Buffer;
	}

	if (path && wcsstr(path, L"\\NeverGonnaLetYouOpen.txt")) {
		printf("NtOpenFile: %S -> REJECT\n", path);
		return STATUS_ACCESS_DENIED;
	}

	NTSTATUS r = my_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	if (path)
		printf("NtOpenFile: %S -> 0x%.8lx\n", path, r);
	return r;
}

NTSTATUS (*my_NtCreateFile)(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  PLARGE_INTEGER     AllocationSize,
  ULONG              FileAttributes,
  ULONG              ShareAccess,
  ULONG              CreateDisposition,
  ULONG              CreateOptions,
  PVOID              EaBuffer,
  ULONG              EaLength
);

NTSTATUS hook_NtCreateFile(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  PLARGE_INTEGER     AllocationSize,
  ULONG              FileAttributes,
  ULONG              ShareAccess,
  ULONG              CreateDisposition,
  ULONG              CreateOptions,
  PVOID              EaBuffer,
  ULONG              EaLength
  ) {
	LPWSTR path = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
		path = ObjectAttributes->ObjectName->Buffer;
	}

	if (path && wcsstr(path, L"\\NeverGonnaLetYouOpen.txt")) {
		printf("NtCreateFile: %S -> REJECT\n", path);
		return STATUS_ACCESS_DENIED;
	}

	NTSTATUS r = my_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	if (path)
		printf("NtCreateFile: %S -> 0x%.8lx\n", path, r);
	return r;
}

LONG exception_handler(PEXCEPTION_POINTERS ExceptionInfo) {
	printf("exception_handler: 0x%.8lx %s 0x%.8lx %p\n",
			ExceptionInfo->ExceptionRecord->ExceptionCode,
			get_exception_name(ExceptionInfo->ExceptionRecord->ExceptionCode),
			ExceptionInfo->ExceptionRecord->ExceptionFlags,
			ExceptionInfo->ExceptionRecord->ExceptionAddress
			);
	return EXCEPTION_CONTINUE_SEARCH;
}

LPBYTE _stub;

BOOL create_hook(FARPROC addr, LPVOID target, LPVOID *copy) {
	BYTE hook[6+8] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 };
	*(DWORD_PTR*)&hook[6] = (DWORD_PTR)target;

	if (copy) {
		*copy = (_stub += 0x40);
		RtlCopyMemory(*copy, addr, 0x40);
	}

	PVOID Base = addr;
	SIZE_T ProtSize = 16;
	ULONG OldProt;

	if (!NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), &Base, &ProtSize, PAGE_EXECUTE_READWRITE, &OldProt))) {
		MessageBoxW(NULL, L"NtProtectVirtualMemory failed", L"ERROR", MB_ICONERROR);
		return FALSE;
	}

	RtlCopyMemory(addr, hook, sizeof(hook));

	if (!NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), &Base, &ProtSize, OldProt, &OldProt))) {
		MessageBoxW(NULL, L"NtProtectVirtualMemory failed", L"ERROR", MB_ICONERROR);
		return FALSE;
	}

	return TRUE;
}

FARPROC GetProcAddress(HMODULE dll, LPCSTR name) {
	ANSI_STRING ansi_name;
	RtlInitAnsiString(&ansi_name, name);
	FARPROC r = NULL;
	NTSTATUS Status = LdrGetProcedureAddress(dll, &ansi_name, (WORD)0, (PVOID*)&r);
	if (NT_ERROR(Status)) {
		MessageBoxW(NULL, L"LdrGetProcedureAddress failed", L"ERROR", MB_ICONERROR);
		return NULL;
	}
	return r;
}

BOOL install_hook() {
	SIZE_T RegionSize = 0x1000;
	NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), (PVOID*)&_stub, 0, &RegionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		MessageBoxW(NULL, L"NtAllocateVirtualMemory failed", L"ERROR", MB_ICONERROR);
		return FALSE;
	}
	// _stub = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	HMODULE ntdll = NULL;

	PPEB_LDR_DATA ldr = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
	LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
	for (LIST_ENTRY *node = head->Flink; node != head; node = node->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		PUNICODE_STRING BaseDllName = &entry->FullDllName + 1;

		if (_wcsicmp(BaseDllName->Buffer, L"ntdll.dll") == 0) {
			ntdll = entry->DllBase;
		}
	}

	if (ntdll == NULL) {
		MessageBoxW(NULL, L"Can not find NTDLL", L"ERROR", MB_ICONERROR);
		return FALSE;
	}

	if (!create_hook(GetProcAddress(ntdll, "NtOpenFile"), hook_NtOpenFile, (LPVOID*)&my_NtOpenFile)) {
		MessageBoxW(NULL, L"Can not hook NtOpenFile", L"ERROR", MB_ICONERROR);
		return FALSE;
	}
	if (!create_hook(GetProcAddress(ntdll, "NtCreateFile"), hook_NtCreateFile, (LPVOID*)&my_NtCreateFile)) {
		MessageBoxW(NULL, L"Can not hook NtCreateFile", L"ERROR", MB_ICONERROR);
		return FALSE;
	}

	return TRUE;
}

BOOL _unlink_list_entry(LIST_ENTRY *node) {
	if (!node->Flink || !node->Blink) {
		return FALSE;
	}

	LIST_ENTRY *prev = node->Blink, *next = node->Flink;
	prev->Flink = next;
	next->Blink = prev;

	node->Flink = NULL;
	node->Blink = NULL;

	return TRUE;
}

BOOL peb_ldr_unlink(HMODULE mod) {
	PPEB_LDR_DATA ldr = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;

	LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
	for (LIST_ENTRY *node = head->Flink; node != head; node = node->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (entry->DllBase == mod) {
			LIST_ENTRY *links = (LIST_ENTRY*)entry;
			if (!_unlink_list_entry(&links[0])) {
				printf("peb_ldr_unlink: InLoadOrderLinks unlink failed\n");
			}
			if (!_unlink_list_entry(&links[1])) {
				printf("peb_ldr_unlink: InMemoryOrderLinks unlink failed\n");
			}
			if (!_unlink_list_entry(&links[2])) {
				printf("peb_ldr_unlink: InInitializationOrderLinks unlink failed\n");
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		LdrDisableThreadCalloutsForDll(hinstDLL);

		AllocConsole();

		// use kernel32 and ntdll

		RtlInitializeCriticalSection(&printf_lock);
		struct _PARTIAL_RTL_USER_PROCESS_PARAMETERS {
			ULONG MaximumLength;
			ULONG Length;
			ULONG Flags;
			ULONG DebugFlags;
			PVOID ConsoleHandle;
			ULONG ConsoleFlags;
			HANDLE StandardInput;
			HANDLE StandardOutput;
			HANDLE StandardError;
		} *UserProcessParameters = (PVOID)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
		hStdout = UserProcessParameters->StandardOutput;

		// use msvcrt

		// _stdout = fopen("CON", "w");
		// if (_stdout == NULL) {
		// 	MessageBoxW(NULL, L"fopen failed", L"ERROR", MB_ICONERROR);
		// 	return FALSE;
		// }

		// AddVectoredContinueHandler(1, exception_handler);

		if (!install_hook()) {
			return FALSE;
		}

		if (!peb_ldr_unlink(hinstDLL)) {
			return FALSE;
		}

		printf("[+] Init OK\n");
	}
	return TRUE;
}

