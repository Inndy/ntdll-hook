all: launcher.exe hook.dll

launcher.exe: launcher.c
	x86_64-w64-mingw32-gcc -mwindows -nodefaultlibs -nostartfiles -Wl,--exclude-all-symbols -fno-ident -nostdlib launcher.c -o launcher.exe -lmsvcrt -luser32 -lkernel32 -lshell32 -eentry -O3
	x86_64-w64-mingw32-strip launcher.exe

hook.dll: hook.c ntdll.lib
	x86_64-w64-mingw32-gcc -shared -nodefaultlibs -nostartfiles -Wl,--exclude-all-symbols -fno-ident -nostdlib hook.c -o hook.dll -L. -luser32 -lkernel32 -lntdll -eDllMain -O1 -Wall
	x86_64-w64-mingw32-strip hook.dll

ntdll.def:
	gendef 'C:\Windows\System32\ntdll.dll'

ntdll.lib: ntdll.def
	x86_64-w64-mingw32-dlltool -k --output-lib ntdll.lib --def ntdll.def
