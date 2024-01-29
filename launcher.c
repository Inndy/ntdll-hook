#include <windows.h>

int inject_dll(HANDLE hProcess, HANDLE hThread) {
	LPVOID pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");
	LPVOID pBuffer = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pBuffer == NULL) {
		MessageBoxW(NULL, L"VirtualAllocEx failed", L"Error", MB_ICONERROR);
		return 0;
	}

	wchar_t path[1024] = {};
	DWORD r = GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
	if (r == 0) {
		MessageBoxW(NULL, L"GetModuleFileNameW failed", L"Error", MB_ICONERROR);
		return 0;
	}
	wchar_t *p = wcsrchr(path, '\\');
	if (p == NULL) {
		MessageBoxW(NULL, L"wcsrchr: char not failed", L"Error", MB_ICONERROR);
		return 0;
	}
	wcscpy(p + 1, L"hook.dll");

	SIZE_T w = 0;
	if (!WriteProcessMemory(hProcess, pBuffer, (LPCVOID)path, sizeof(path), &w)) {
		MessageBoxW(NULL, L"WriteProcessMemory failed", L"Error", MB_ICONERROR);
		return 0;
	}
	if (QueueUserAPC(pLoadLibraryW, hThread, (ULONG_PTR)pBuffer) == 0) {
		MessageBoxW(NULL, L"QueueUserAPC failed", L"Error", MB_ICONERROR);
		return 0;
	}

	return 1;
}

void entry() {
	int argc = 0;
	LPWSTR * argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	LPWSTR cmd = NULL;
	BOOL flag_suspended = FALSE, flag_wait = FALSE;

	for (int i = 1; i < argc; i++) {
		switch (argv[i][0]) {
			case '-':
				switch (argv[i][1]) {
					case 's':
						flag_suspended = TRUE;
						break;
					case 'w':
						flag_wait = TRUE;
						break;
				}
				break;
			default:
				cmd = argv[i];
		}
	}

	if (cmd == NULL) {
		MessageBoxW(NULL, L"Wrong usage", L"Error", MB_ICONERROR);
		ExitProcess(1);
	}

	STARTUPINFOW si = {};
	PROCESS_INFORMATION pi = {};
	LPWCH env = GetEnvironmentStringsW();
	WCHAR curr_dir[1024] = {};

	GetCurrentDirectoryW(ARRAYSIZE(curr_dir), curr_dir);

	if (!CreateProcessW(cmd, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT, env, curr_dir, &si, &pi)) {
		wchar_t buf[128] = L"CreateProcessW failed, GetLastError: ";
		_itow(GetLastError(), buf + wcslen(buf), 10);
		MessageBoxW(NULL, buf, L"Error", MB_ICONERROR);
		goto failed;
	}

	if (!inject_dll(pi.hProcess, pi.hThread)) {
		goto failed;
	}

	if (!flag_suspended) {
		ResumeThread(pi.hThread);
	}

	if (env) {
		FreeEnvironmentStringsW(env);
	}

	if (flag_wait)
		WaitForSingleObject(pi.hProcess, INFINITE);

	ExitProcess(0);

failed:
	if (pi.hProcess) {
		TerminateProcess(pi.hProcess, 0);
	}

	if (env) {
		FreeEnvironmentStringsW(env);
	}
	ExitProcess(1);
}
