// dllmain.cpp : 定义 DLL 应用程序的入口点。
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#include "stdafx.h"  
#include "HookApi.h"  
using namespace std;
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"ws2_32.lib")

char log_path[255];
char strBuffer[256];//用户名
char hostname[128];//主机名
char spy[6];//监测层，监测程序代号，监测程序模块
char ProcessName[255];
string Log[100];
char dat[100];
char tim[50];
TCHAR pathname[MAX_PATH];
char path[MAX_PATH];
char dlldir[MAX_PATH];


//文件
  ptrCreateFileW realCreateFileW ;  
  ptrCreateFileA realCreateFileA ;  
  ptrReadFile realReadFile;
  ptrMoveFileW realMoveFileW;
  ptrCopyFileW realCopyFileW;
  ptrDeleteFileW realDeleteFileW;
  ptrFindFirstFileW realFindFirstFileW;
  ptrFindNextFileW realFindNextFileW;
  ptrSetFileAttributesW realSetFileAttributesW;
  ptrCreateHardLinkW realCreateHardLinkW;
  ptrSetEndOfFile realSetEndOfFile;
  ptrSetFileValidData realSetFileValidData;
  ptrSetFileTime realSetFileTime;

  //进程API
  ptrBitBlt realBitBlt;
  ptrCreateFileMapping realCreateFileMapping;
  ptrOpenFileMapping realOpenFileMapping;
  ptrCryptAcquireContext realCryptAcquireContext ;
  ptrDeviceIoControl realDeviceIoControl;
  ptrFindWindowEx realFindWindowEx;
  ptrGetAsyncKeyState realGetAsyncKeyState;
  ptrGetDC realGetDC;
  ptrGetKeyState realGetKeyState;
  ptrGetForegroundWindow realGetForegroundWindow;
  ptrGetTempPath realGetTempPath;
  ptrMapViewOfFile realMapViewOfFile;
  ptrOpenFile realOpenFile;
  ptrAdjustTokenPrivileges realAdjustTokenPrivileges;
  ptrAttachThreadInput realAttachThreadInput;
  ptrCallNextHookEx realCallNextHookEx;
  ptrCheckRemoteDebuggerPresent realCheckRemoteDebuggerPresent;
  ptrControlService realControlService;
  ptrCreateRemoteThread realCreateRemoteThread;
  ptrCreateToolhelp32Snapshot realCreateToolhelp32Snapshot;
  ptrEnumProcesses realEnumProcesses;
  ptrEnumProcessModules realEnumProcessModules;
  ptrGetProcAddress realGetProcAddress;
  ptrGetSystemDefaultLangID realGetSystemDefaultLangID;
  ptrGetThreadContext realGetThreadContext;
  ptrGetTickCount realGetTickCount ;
  ptrIsDebuggerPresent realIsDebuggerPresent;
  ptrLoadLibraryEx realLoadLibraryEx;
  ptrLoadResource realLoadResource;
  ptrModule32FirstW realModule32FirstW;
  ptrModule32NextW realModule32NextW;
  ptrOpenProcess realOpenProcess;
  ptrPeekNamedPipe realPeekNamedPipe;
  ptrProcess32First realProcess32First;
  ptrProcess32Next realProcess32Next;
  ptrQueryPerformanceCounter realQueryPerformanceCounter;
  ptrQueueUserAPC realQueueUserAPC;
  ptrReadProcessMemory realReadProcessMemory;
  ptrResumeThread realResumeThread;
  ptrSetThreadContext realSetThreadContext;
  ptrSuspendThread realSuspendThread;
//ptrsystem realsystem;
  ptrThread32First realThread32First;
  ptrThread32Next realThread32Next;
  ptrToolhelp32ReadProcessMemory realToolhelp32ReadProcessMemory;
  ptrVirtualAllocEx realVirtualAllocEx;
  ptrVirtualProtectEx realVirtualProtectEx;
  ptrWinExec realWinExec;
  ptrWriteProcessMemory realWriteProcessMemory;
  ptrRegisterHotKey realRegisterHotKey;
  ptrCreateProcessA realCreateProcessA;
  ptrCertOpenSystemStoreW realCertOpenSystemStoreW;
  ptrCreateMutexW realCreateMutexW;
  ptrFindResourceW realFindResourceW;
  ptrFindWindowW realFindWindowW;
  ptrGetWindowsDirectoryW realGetWindowsDirectoryW;
  ptrMapVirtualKeyW realMapVirtualKeyW;
  ptrOpenMutexW realOpenMutexW;
  ptrOpenSCManagerW realOpenSCManagerW;
  ptrCreateProcessW realCreateProcessW;
  ptrCreateServiceW realCreateServiceW;
  ptrGetModuleFileNameExW realGetModuleFileNameExW;
  ptrGetModuleHandleW realGetModuleHandleW;
  ptrGetStartupInfoW realGetStartupInfoW;
  ptrGetVersionExW realGetVersionExW;
  ptrLoadLibraryW realLoadLibraryW;
  ptrOutputDebugStringW realOutputDebugStringW;
  ptrSetWindowsHookExW realSetWindowsHookExW;
  ptrShellExecuteW realShellExecuteW;
  ptrStartServiceCtrlDispatcherW realStartServiceCtrlDispatcherW;
  ptrSetLocalTime realSetLocalTime;
  ptrTerminateThread realTerminateThread;
  ptrVirtualFree realVirtualFree;
  ptrSetProcessWorkingSetSize realSetProcessWorkingSetSize;
  ptrTerminateProcess realTerminateProcess;
//注册表
  ptrRegOpenKeyEx realRegOpenKeyEx;
  ptrRegOpenKeyW realRegOpenKeyW;
  ptrRegCreateKeyExW realRegCreateKeyExW;
  ptrRegCreateKeyW realRegCreateKeyW;
  ptrRegQueryValueExW realRegQueryValueExW;
  ptrRegQueryValueW realRegQueryValueW;
  ptrRegSetValueExW realRegSetValueExW;
  ptrRegSetValueW realRegSetValueW;
  ptrRegDeleteKeyExW realRegDeleteKeyExW;
  ptrRegDeleteKeyW realRegDeleteKeyW;
  ptrRegSetKeySecurity realRegSetKeySecurity;
  ptrRegRestoreKey realRegRestoreKey;
  ptrRegReplaceKey realRegReplaceKey;
  ptrRegLoadKey realRegLoadKey;
  ptrRegUnLoadKey realRegUnLoadKey;
//网络
  ptraccept realaccept;
  ptrsend realsend;
  ptrbind realbind;
  ptrconnect realconnect;
  ptrConnectNamedPipe realConnectNamedPipe;
  ptrgethostname realgethostname;
  ptrinet_addr realinet_addr;
  ptrInternetReadFile realInternetReadFile;
  ptrInternetWriteFile realInternetWriteFile;
  ptrNetShareEnum realNetShareEnum;
  ptrrecv realrecv;
  ptrWSAStartup realWSAStartup;
  ptrInternetOpenW realInternetOpenW;
  ptrInternetOpenUrlW realInternetOpenUrlW;
  ptrURLDownloadToFileW realURLDownloadToFileW;
  ptrFtpPutFileW realFtpPutFileW;
  ptrHttpSendRequest realHttpSendRequest;
  ptrHttpSendRequestEx realHttpSendRequestEx;
  ptrHttpOpenRequest realHttpOpenRequest;
  ptrInternetConnect realInternetConnect;
  ptrlisten reallisten;
  ptrInternetOpenUrlA realInternetOpenUrlA;
  ptrHttpOpenRequestA realHttpOpenRequestA;

//ptrMessageBeep realMessageBeep = NULL;
//ptrPlaySoundW   realPlaySoundW = NULL;

//HMODULE                 hKernel32 = NULL; 
//文件
//HMODULE                 hKernel32 = NULL; 
//文件
TRACED_HOOK_HANDLE      hHookCreateFileW = new HOOK_TRACE_INFO() ;  
TRACED_HOOK_HANDLE      hHookCreateFileA = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookPlaySoundW  = new HOOK_TRACE_INFO(); 
TRACED_HOOK_HANDLE      hHookReadFile  = new HOOK_TRACE_INFO(); 
TRACED_HOOK_HANDLE		hHookMoveFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookCopyFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookDeleteFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookFindFirstFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookFindNextFileW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetFileAttributesW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookCreateHardLinkW =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetEndOfFile =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetFileValidData =new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE		hHookSetFileTime =new HOOK_TRACE_INFO();

//进程API
TRACED_HOOK_HANDLE      hHookBitBlt = new HOOK_TRACE_INFO();
//TRACED_HOOK_HANDLE      hHookCoCreateInstance = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateFileMapping = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenFileMapping = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCryptAcquireContext = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookDeviceIoControl = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFindWindowEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetAsyncKeyState = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetDC = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetForegroundWindow = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetKeyState = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetTempPath= new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookMapViewOfFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookAdjustTokenPrivileges = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookAttachThreadInput = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCallNextHookEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCheckRemoteDebuggerPresent = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookControlService = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateRemoteThread = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateToolhelp32Snapshot = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookEnumProcesses = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookEnumProcessModules = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetProcAddress = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetSystemDefaultLangID = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetThreadContext = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetTickCount = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookIsDebuggerPresent = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookLoadLibraryEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookLoadResource = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookModule32FirstW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookModule32NextW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenProcess = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookPeekNamedPipe = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookProcess32First = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookProcess32Next = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookQueryPerformanceCounter = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookQueueUserAPC = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookReadProcessMemory = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookResumeThread = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookSetThreadContext = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookSuspendThread = new HOOK_TRACE_INFO();  
//TRACED_HOOK_HANDLE      hHooksystem = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookThread32First = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookThread32Next = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookToolhelp32ReadProcessMemory = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookVirtualAllocEx = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookVirtualProtectEx = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookWinExec = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookWriteProcessMemory = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookRegisterHotKey = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookCreateProcessA = new HOOK_TRACE_INFO();  
TRACED_HOOK_HANDLE      hHookCertOpenSystemStoreW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateMutexW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFindResourceW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFindWindowW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetWindowsDirectoryW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookMapVirtualKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenMutexW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOpenSCManagerW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateProcessW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateServiceW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetModuleFileNameExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetModuleHandleW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetStartupInfoW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookGetVersionExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookLoadLibraryW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookOutputDebugStringW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookSetWindowsHookExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookShellExecuteW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookStartServiceCtrlDispatcherW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookSetLocalTime = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookTerminateThread = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookVirtualFree = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookSetProcessWorkingSetSize = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookTerminateProcess = new HOOK_TRACE_INFO();
//注册表
TRACED_HOOK_HANDLE      hHookRegOpenKeyEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegOpenKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegCreateKeyExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegCreateKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegQueryValueExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegQueryValueW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegSetValueExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegSetValueW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegDeleteKeyExW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegDeleteKeyW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegSetKeySecurity = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegRestoreKey = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegReplaceKey = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegLoadKey = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookRegUnLoadKey = new HOOK_TRACE_INFO();
//网络
TRACED_HOOK_HANDLE      hHookaccept = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHooksend = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookbind = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookconnect = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookConnectNamedPipe = new HOOK_TRACE_INFO();
//TRACED_HOOK_HANDLE      hHookGetAdaptersInfo = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookgethostname = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookinet_addr = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetReadFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetWriteFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookNetShareEnum = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookrecv = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookWSAStartup = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetOpenW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetOpenUrlW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookURLDownloadToFileW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookFtpPutFileW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpSendRequest = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpSendRequestEx = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpOpenRequest = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetConnect = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHooklisten = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookInternetOpenUrlA = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookHttpOpenRequestA = new HOOK_TRACE_INFO();

<<<<<<< .mine
||||||| .r39
static BOOL (WINAPI *RealWriteFile)(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped)=WriteFile;
static HFILE (WINAPI *RealOpenFile)( LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle )=OpenFile;
static BOOL (WINAPI *RealConnectNamedPipe)(HANDLE hNamedPipe,LPOVERLAPPED lpOverlapped )=ConnectNamedPipe;
static LONG (WINAPI *RealRegOpenKeyA)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult )=RegOpenKeyA;
static BOOL (WINAPI *RealRegisterHotKey)(HWND hWnd, int id, UINT fsModifiers, UINT vk)=RegisterHotKey;
static BOOL (WINAPI *RealWriteProcessMemory)( HANDLE hProcess , LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten )=WriteProcessMemory;
static UINT (WINAPI *RealWinExec)(LPCSTR lpCmdLine, UINT uCmdShow )=WinExec;
static BOOL (WINAPI *RealVirtualProtectEx)( HANDLE hProcess , LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )=VirtualProtectEx;
static LPVOID (WINAPI *RealVirtualAllocEx)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )=VirtualAllocEx;
static BOOL (WINAPI *RealToolhelp32ReadProcessMemory)( DWORD th32ProcessID, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T cbRead, SIZE_T *lpNumberOfBytesRead )=Toolhelp32ReadProcessMemory;
static BOOL (WINAPI *RealThread32Next)( HANDLE hSnapshot, LPTHREADENTRY32 lpte )=Thread32Next;
static BOOL (WINAPI *RealThread32First)( HANDLE hSnapshot, LPTHREADENTRY32 lpte )=Thread32First;
static int (*Realsystem)(const char * _Command)=system;
static DWORD (WINAPI *RealSuspendThread)(HANDLE hThread )=SuspendThread;
static BOOL (WINAPI *RealStartServiceCtrlDispatcherA)(CONST SERVICE_TABLE_ENTRYA *lpServiceStartTable )=StartServiceCtrlDispatcherA;
static HINSTANCE (WINAPI *RealShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)=ShellExecuteA;
static HHOOK (WINAPI *RealSetWindowsHookExA)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)=SetWindowsHookExA;
static BOOL (WINAPI *RealSetThreadContext)( HANDLE hThread,  CONST CONTEXT * lpContext )=SetThreadContext;
static DWORD (WINAPI *RealResumeThread)(  HANDLE hThread )=ResumeThread;
static BOOL (WINAPI *RealReadProcessMemory)(  HANDLE hProcess ,  LPCVOID lpBaseAddress, LPVOID lpBuffer,  SIZE_T nSize,  SIZE_T * lpNumberOfBytesRead )=ReadProcessMemory;
static DWORD (WINAPI *RealQueueUserAPC)(  PAPCFUNC pfnAPC,  HANDLE hThread,  ULONG_PTR dwData )=QueueUserAPC;
static BOOL (WINAPI *RealQueryPerformanceCounter)(  LARGE_INTEGER * lpPerformanceCount )=QueryPerformanceCounter;
static BOOL (WINAPI *RealProcess32First)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )=Process32First;
static BOOL (WINAPI *RealProcess32Next)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )=Process32Next;
static BOOL (WINAPI *RealPeekNamedPipe)(  HANDLE hNamedPipe, LPVOID lpBuffer,  DWORD nBufferSize,  LPDWORD lpBytesRead,  LPDWORD lpTotalBytesAvail,  LPDWORD lpBytesLeftThisMessage )=PeekNamedPipe;
static VOID (WINAPI *RealOutputDebugStringA)(  LPCSTR lpOutputString )=OutputDebugStringA;
static HANDLE (WINAPI *RealOpenProcess)(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  DWORD dwProcessId )=OpenProcess;
//static BOOL (WINAPI *RealModule32NextW)( HANDLE hSnapshot, LPMODULEENTRY32W lpme )=Module32NextW;
//static BOOL (WINAPI *RealModule32FirstW)( HANDLE hSnapshot, LPMODULEENTRY32W lpme )=Module32FirstW;
static HGLOBAL (WINAPI *RealLoadResource)(  HMODULE hModule,  HRSRC hResInfo )=LoadResource;
static HMODULE (WINAPI *RealLoadLibraryA)(  LPCSTR lpLibFileName )=LoadLibraryA;
static BOOL (WINAPI *RealIsDebuggerPresent)(VOID)=IsDebuggerPresent;
static BOOL (WINAPI *RealGetVersionExA)(  LPOSVERSIONINFOA lpVersionInformation )= GetVersionExA;
static DWORD (WINAPI *RealGetTickCount)(VOID)=GetTickCount;
static BOOL (WINAPI *RealGetThreadContext)(  HANDLE hThread,  LPCONTEXT lpContext )=GetThreadContext;
static LANGID (WINAPI *RealGetSystemDefaultLangID)(void)=GetSystemDefaultLangID;
static void(WINAPI *RealGetStartupInfoA)(  LPSTARTUPINFOA lpStartupInfo )=GetStartupInfoA;
static FARPROC (WINAPI *RealGetProcAddress)(  HMODULE hModule,  LPCSTR lpProcName )=GetProcAddress;
static HMODULE (WINAPI *RealGetModuleHandleA)(  LPCSTR lpModuleName )=GetModuleHandleA;
static DWORD (WINAPI *RealGetModuleFileNameExA)(  HANDLE hProcess,  HMODULE hModule, LPSTR lpFilename,  DWORD nSize )=GetModuleFileNameExA;
static BOOL (WINAPI *RealEnumProcessModules)(  HANDLE hProcess, HMODULE *lphModule,  DWORD cb,  LPDWORD lpcbNeeded )=EnumProcessModules;
static BOOL (WINAPI *RealEnumProcesses)( DWORD * lpidProcess,  DWORD cb,  LPDWORD lpcbNeeded )=EnumProcesses;
static HANDLE (WINAPI *RealCreateToolhelp32Snapshot)( DWORD dwFlags, DWORD th32ProcessID )=CreateToolhelp32Snapshot;
static SC_HANDLE (WINAPI *RealCreateServiceA)(  SC_HANDLE hSCManager,  LPCSTR lpServiceName,  LPCSTR lpDisplayName,  DWORD dwDesiredAccess,  DWORD dwServiceType,  DWORD dwStartType,  DWORD dwErrorControl,  LPCSTR lpBinaryPathName,  LPCSTR lpLoadOrderGroup,  LPDWORD lpdwTagId,  LPCSTR lpDependencies,  LPCSTR lpServiceStartName,  LPCSTR lpPassword )=CreateServiceA;
static HANDLE (WINAPI *RealCreateRemoteThread)(  HANDLE hProcess,  LPSECURITY_ATTRIBUTES lpThreadAttributes,  SIZE_T dwStackSize,  LPTHREAD_START_ROUTINE lpStartAddress,  LPVOID lpParameter,  DWORD dwCreationFlags,  LPDWORD lpThreadId )=CreateRemoteThread;
static BOOL (WINAPI *RealCreateProcessA)(  LPCSTR lpApplicationName, LPSTR lpCommandLine,  LPSECURITY_ATTRIBUTES lpProcessAttributes,  LPSECURITY_ATTRIBUTES lpThreadAttributes,  BOOL bInheritHandles,  DWORD dwCreationFlags,  LPVOID lpEnvironment,  LPCSTR lpCurrentDirectory,  LPSTARTUPINFOA lpStartupInfo,  LPPROCESS_INFORMATION lpProcessInformation )=CreateProcessA;
static BOOL (WINAPI *RealControlService)(  SC_HANDLE hService,  DWORD dwControl,  LPSERVICE_STATUS lpServiceStatus )=ControlService;
static BOOL (WINAPI *RealCheckRemoteDebuggerPresent)(  HANDLE hProcess,  PBOOL pbDebuggerPresent )=CheckRemoteDebuggerPresent;
static LRESULT (WINAPI *RealCallNextHookEx)( HHOOK hhk,  int nCode,  WPARAM wParam,  LPARAM lParam)=CallNextHookEx;
static BOOL (WINAPI *RealAttachThreadInput)( DWORD idAttach,  DWORD idAttachTo,  BOOL fAttach)=AttachThreadInput;
static BOOL (WINAPI *RealAdjustTokenPrivileges)(  HANDLE TokenHandle,  BOOL DisableAllPrivileges,  PTOKEN_PRIVILEGES NewState,  DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState,  PDWORD ReturnLength )=AdjustTokenPrivileges;
static SC_HANDLE (WINAPI *RealOpenSCManagerA)(  LPCSTR lpMachineName,  LPCSTR lpDatabaseName,  DWORD dwDesiredAccess )=OpenSCManagerA;
static UINT (WINAPI *RealMapVirtualKeyA)( UINT uCode,  UINT uMapType)=MapVirtualKeyA;
static LPVOID (WINAPI *RealMapViewOfFile)(  HANDLE hFileMappingObject,  DWORD dwDesiredAccess,  DWORD dwFileOffsetHigh,  DWORD dwFileOffsetLow,  SIZE_T dwNumberOfBytesToMap)=MapViewOfFile;
static BOOL (WINAPI *RealSetFileTime)(  HANDLE hFile,  CONST FILETIME * lpCreationTime,  CONST FILETIME * lpLastAccessTime,  CONST FILETIME * lpLastWriteTime )=SetFileTime;
static HANDLE (WINAPI *RealOpenMutexA)(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  LPCSTR lpName )=OpenMutexA;
static UINT (WINAPI *RealGetWindowsDirectoryA)(  LPSTR lpBuffer,   UINT uSize)=GetWindowsDirectoryA;
static DWORD (WINAPI *RealGetTempPath)( DWORD nBufferLength, LPWSTR lpBuffer )=GetTempPathW;
static SHORT (WINAPI *RealGetKeyState)( int nVirtKey)=GetKeyState;
static HWND (WINAPI *RealGetForegroundWindow)()=GetForegroundWindow;
static HDC (WINAPI *RealGetDC)( HWND hWnd)=GetDC;
static SHORT (WINAPI *RealGetAsyncKeyState)( int vKey)=GetAsyncKeyState;
static HWND (WINAPI *RealFindWindowA)( LPCSTR lpClassName,  LPCSTR lpWindowName)=FindWindowA;
static HRSRC (WINAPI *RealFindResourceA)(  HMODULE hModule,  LPCSTR lpName,  LPCSTR lpType )=FindResourceA;
static BOOL (WINAPI *RealFindNextFileA)(  HANDLE hFindFile,  LPWIN32_FIND_DATAA lpFindFileData)=FindNextFileA;
static HANDLE (WINAPI *RealFindFirstFileA)(  LPCSTR lpFileName,  LPWIN32_FIND_DATAA lpFindFileData )=FindFirstFileA;
static BOOL (WINAPI *RealDeviceIoControl)(  HANDLE hDevice,  DWORD dwIoControlCode, LPVOID lpInBuffer,  DWORD nInBufferSize, LPVOID lpOutBuffer,  DWORD nOutBufferSize,  LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped )=DeviceIoControl;
static BOOL (WINAPI *RealReadFile)(  HANDLE hFile,  LPVOID lpBuffer,  DWORD nNumberOfBytesToRead,  LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped )=ReadFile;
static HANDLE (WINAPI *RealCreateFile)(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE)=CreateFile;
static HANDLE (WINAPI *RealCreateMutexA)( LPSECURITY_ATTRIBUTES lpMutexAttributes,  BOOL bInitialOwner,  LPCSTR lpName )=CreateMutexA;
static HANDLE (WINAPI *RealCreateFileMapping)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCTSTR)=CreateFileMapping;
static BOOL (WINAPI *RealDeleteFile)( LPCTSTR lpFileName)=DeleteFile;
static BOOL (WINAPI *RealDeleteFileA)(LPCSTR) = DeleteFileA;
static BOOL (WINAPI *RealCopyFileA)(LPCSTR,LPCSTR,BOOL)=CopyFileA;
static BOOL (WINAPI *RealMoveFileA)(LPCSTR,LPCSTR)=MoveFileA;
static HANDLE (WINAPI *RealCreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE)=CreateFileA;
static LONG (WINAPI *RealRegOpenKeyEx)(	HKEY hKey,LPCWSTR lpSubKey,	DWORD ulOptions,	REGSAM samDesired,	PHKEY phkResult	)=RegOpenKeyExW;
=======
static BOOL (WINAPI *RealWriteFile)(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped)=WriteFile;
static HFILE (WINAPI *RealOpenFile)( LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle )=OpenFile;
static BOOL (WINAPI *RealConnectNamedPipe)(HANDLE hNamedPipe,LPOVERLAPPED lpOverlapped )=ConnectNamedPipe;
static LONG (WINAPI *RealRegOpenKeyA)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult )=RegOpenKeyA;
static BOOL (WINAPI *RealRegisterHotKey)(HWND hWnd, int id, UINT fsModifiers, UINT vk)=RegisterHotKey;
static BOOL (WINAPI *RealWriteProcessMemory)( HANDLE hProcess , LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten )=WriteProcessMemory;
static UINT (WINAPI *RealWinExec)(LPCSTR lpCmdLine, UINT uCmdShow )=WinExec;
static BOOL (WINAPI *RealVirtualProtectEx)( HANDLE hProcess , LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )=VirtualProtectEx;
static LPVOID (WINAPI *RealVirtualAllocEx)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )=VirtualAllocEx;
static BOOL (WINAPI *RealToolhelp32ReadProcessMemory)( DWORD th32ProcessID, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T cbRead, SIZE_T *lpNumberOfBytesRead )=Toolhelp32ReadProcessMemory;
static BOOL (WINAPI *RealThread32Next)( HANDLE hSnapshot, LPTHREADENTRY32 lpte )=Thread32Next;
static BOOL (WINAPI *RealThread32First)( HANDLE hSnapshot, LPTHREADENTRY32 lpte )=Thread32First;
static int (*Realsystem)(const char * _Command)=system;
static DWORD (WINAPI *RealSuspendThread)(HANDLE hThread )=SuspendThread;
static BOOL (WINAPI *RealStartServiceCtrlDispatcherA)(CONST SERVICE_TABLE_ENTRYA *lpServiceStartTable )=StartServiceCtrlDispatcherA;
static HINSTANCE (WINAPI *RealShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)=ShellExecuteA;
static HHOOK (WINAPI *RealSetWindowsHookExA)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)=SetWindowsHookExA;
static BOOL (WINAPI *RealSetThreadContext)( HANDLE hThread,  CONST CONTEXT * lpContext )=SetThreadContext;
static DWORD (WINAPI *RealResumeThread)(  HANDLE hThread )=ResumeThread;
static BOOL (WINAPI *RealReadProcessMemory)(  HANDLE hProcess ,  LPCVOID lpBaseAddress, LPVOID lpBuffer,  SIZE_T nSize,  SIZE_T * lpNumberOfBytesRead )=ReadProcessMemory;
static DWORD (WINAPI *RealQueueUserAPC)(  PAPCFUNC pfnAPC,  HANDLE hThread,  ULONG_PTR dwData )=QueueUserAPC;
static BOOL (WINAPI *RealQueryPerformanceCounter)(  LARGE_INTEGER * lpPerformanceCount )=QueryPerformanceCounter;
static BOOL (WINAPI *RealProcess32First)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )=Process32First;
static BOOL (WINAPI *RealProcess32Next)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )=Process32Next;
static BOOL (WINAPI *RealPeekNamedPipe)(  HANDLE hNamedPipe, LPVOID lpBuffer,  DWORD nBufferSize,  LPDWORD lpBytesRead,  LPDWORD lpTotalBytesAvail,  LPDWORD lpBytesLeftThisMessage )=PeekNamedPipe;
static VOID (WINAPI *RealOutputDebugStringA)(  LPCSTR lpOutputString )=OutputDebugStringA;
static HANDLE (WINAPI *RealOpenProcess)(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  DWORD dwProcessId )=OpenProcess;
//static BOOL (WINAPI *RealModule32NextW)( HANDLE hSnapshot, LPMODULEENTRY32W lpme )=Module32NextW;
//static BOOL (WINAPI *RealModule32FirstW)( HANDLE hSnapshot, LPMODULEENTRY32W lpme )=Module32FirstW;
static HGLOBAL (WINAPI *RealLoadResource)(  HMODULE hModule,  HRSRC hResInfo )=LoadResource;
static HMODULE (WINAPI *RealLoadLibraryA)(  LPCSTR lpLibFileName )=LoadLibraryA;
static BOOL (WINAPI *RealIsDebuggerPresent)(VOID)=IsDebuggerPresent;
static BOOL (WINAPI *RealGetVersionExA)(  LPOSVERSIONINFOA lpVersionInformation )= GetVersionExA;
static DWORD (WINAPI *RealGetTickCount)(VOID)=GetTickCount;
static BOOL (WINAPI *RealGetThreadContext)(  HANDLE hThread,  LPCONTEXT lpContext )=GetThreadContext;
static LANGID (WINAPI *RealGetSystemDefaultLangID)(void)=GetSystemDefaultLangID;
static void(WINAPI *RealGetStartupInfoA)(  LPSTARTUPINFOA lpStartupInfo )=GetStartupInfoA;
static FARPROC (WINAPI *RealGetProcAddress)(  HMODULE hModule,  LPCSTR lpProcName )=GetProcAddress;
static HMODULE (WINAPI *RealGetModuleHandleA)(  LPCSTR lpModuleName )=GetModuleHandleA;
static DWORD (WINAPI *RealGetModuleFileNameExA)(  HANDLE hProcess,  HMODULE hModule, LPSTR lpFilename,  DWORD nSize )=GetModuleFileNameExA;
static BOOL (WINAPI *RealEnumProcessModules)(  HANDLE hProcess, HMODULE *lphModule,  DWORD cb,  LPDWORD lpcbNeeded )=EnumProcessModules;
static BOOL (WINAPI *RealEnumProcesses)( DWORD * lpidProcess,  DWORD cb,  LPDWORD lpcbNeeded )=EnumProcesses;
static HANDLE (WINAPI *RealCreateToolhelp32Snapshot)( DWORD dwFlags, DWORD th32ProcessID )=CreateToolhelp32Snapshot;
static SC_HANDLE (WINAPI *RealCreateServiceA)(  SC_HANDLE hSCManager,  LPCSTR lpServiceName,  LPCSTR lpDisplayName,  DWORD dwDesiredAccess,  \
											  DWORD dwServiceType,  DWORD dwStartType,  DWORD dwErrorControl,  LPCSTR lpBinaryPathName,  \
											  LPCSTR lpLoadOrderGroup,  LPDWORD lpdwTagId,  LPCSTR lpDependencies,  LPCSTR lpServiceStartName,  \
											  LPCSTR lpPassword )=CreateServiceA;
static HANDLE (WINAPI *RealCreateRemoteThread)(  HANDLE hProcess,  LPSECURITY_ATTRIBUTES lpThreadAttributes,  SIZE_T dwStackSize,  \
											   LPTHREAD_START_ROUTINE lpStartAddress,  LPVOID lpParameter,  DWORD dwCreationFlags,  \
											   LPDWORD lpThreadId )=CreateRemoteThread;
static BOOL (WINAPI *RealCreateProcessA)(  LPCSTR lpApplicationName, LPSTR lpCommandLine,  LPSECURITY_ATTRIBUTES lpProcessAttributes,  \
										 LPSECURITY_ATTRIBUTES lpThreadAttributes,  BOOL bInheritHandles,  DWORD dwCreationFlags,  \
										 LPVOID lpEnvironment,  LPCSTR lpCurrentDirectory,  LPSTARTUPINFOA lpStartupInfo,  \
										 LPPROCESS_INFORMATION lpProcessInformation )=CreateProcessA;
static BOOL (WINAPI *RealControlService)(  SC_HANDLE hService,  DWORD dwControl,  LPSERVICE_STATUS lpServiceStatus )=ControlService;
static BOOL (WINAPI *RealCheckRemoteDebuggerPresent)(  HANDLE hProcess,  PBOOL pbDebuggerPresent )=CheckRemoteDebuggerPresent;
static LRESULT (WINAPI *RealCallNextHookEx)( HHOOK hhk,  int nCode,  WPARAM wParam,  LPARAM lParam)=CallNextHookEx;
static BOOL (WINAPI *RealAttachThreadInput)( DWORD idAttach,  DWORD idAttachTo,  BOOL fAttach)=AttachThreadInput;
static BOOL (WINAPI *RealAdjustTokenPrivileges)(  HANDLE TokenHandle,  BOOL DisableAllPrivileges,  PTOKEN_PRIVILEGES NewState,  DWORD BufferLength, \
												PTOKEN_PRIVILEGES PreviousState,  PDWORD ReturnLength )=AdjustTokenPrivileges;
static SC_HANDLE (WINAPI *RealOpenSCManagerA)(  LPCSTR lpMachineName,  LPCSTR lpDatabaseName,  DWORD dwDesiredAccess )=OpenSCManagerA;
static UINT (WINAPI *RealMapVirtualKeyA)( UINT uCode,  UINT uMapType)=MapVirtualKeyA;
static LPVOID (WINAPI *RealMapViewOfFile)(  HANDLE hFileMappingObject,  DWORD dwDesiredAccess,  DWORD dwFileOffsetHigh,  DWORD dwFileOffsetLow,  SIZE_T dwNumberOfBytesToMap)=MapViewOfFile;
static BOOL (WINAPI *RealSetFileTime)(  HANDLE hFile,  CONST FILETIME * lpCreationTime,  CONST FILETIME * lpLastAccessTime,  CONST FILETIME * lpLastWriteTime )=SetFileTime;
static HANDLE (WINAPI *RealOpenMutexA)(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  LPCSTR lpName )=OpenMutexA;
static UINT (WINAPI *RealGetWindowsDirectoryA)(  LPSTR lpBuffer,   UINT uSize)=GetWindowsDirectoryA;
static DWORD (WINAPI *RealGetTempPath)( DWORD nBufferLength, LPWSTR lpBuffer )=GetTempPathW;
static SHORT (WINAPI *RealGetKeyState)( int nVirtKey)=GetKeyState;
static HWND (WINAPI *RealGetForegroundWindow)()=GetForegroundWindow;
static HDC (WINAPI *RealGetDC)( HWND hWnd)=GetDC;
static SHORT (WINAPI *RealGetAsyncKeyState)( int vKey)=GetAsyncKeyState;
static HWND (WINAPI *RealFindWindowA)( LPCSTR lpClassName,  LPCSTR lpWindowName)=FindWindowA;
static HRSRC (WINAPI *RealFindResourceA)(  HMODULE hModule,  LPCSTR lpName,  LPCSTR lpType )=FindResourceA;
static BOOL (WINAPI *RealFindNextFileA)(  HANDLE hFindFile,  LPWIN32_FIND_DATAA lpFindFileData)=FindNextFileA;
static HANDLE (WINAPI *RealFindFirstFileA)(  LPCSTR lpFileName,  LPWIN32_FIND_DATAA lpFindFileData )=FindFirstFileA;
static BOOL (WINAPI *RealDeviceIoControl)(  HANDLE hDevice,  DWORD dwIoControlCode, LPVOID lpInBuffer,  DWORD nInBufferSize, LPVOID lpOutBuffer,  \
										  DWORD nOutBufferSize,  LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped )=DeviceIoControl;
static BOOL (WINAPI *RealReadFile)(  HANDLE hFile,  LPVOID lpBuffer,  DWORD nNumberOfBytesToRead,  LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped )=ReadFile;
static HANDLE (WINAPI *RealCreateFile)(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE)=CreateFile;
static HANDLE (WINAPI *RealCreateMutexA)( LPSECURITY_ATTRIBUTES lpMutexAttributes,  BOOL bInitialOwner,  LPCSTR lpName )=CreateMutexA;
static HANDLE (WINAPI *RealCreateFileMapping)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCTSTR)=CreateFileMapping;
static BOOL (WINAPI *RealDeleteFile)( LPCTSTR lpFileName)=DeleteFile;
static BOOL (WINAPI *RealDeleteFileA)(LPCSTR) = DeleteFileA;
static BOOL (WINAPI *RealCopyFileA)(LPCSTR,LPCSTR,BOOL)=CopyFileA;
static BOOL (WINAPI *RealMoveFileA)(LPCSTR,LPCSTR)=MoveFileA;
static HANDLE (WINAPI *RealCreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE)=CreateFileA;
static LONG (WINAPI *RealRegOpenKeyEx)(	HKEY hKey,LPCWSTR lpSubKey,	DWORD ulOptions,	REGSAM samDesired,	PHKEY phkResult	)=RegOpenKeyExW;
>>>>>>> .r53

<<<<<<< .mine
NTSTATUS                statue;  
//文件API
ULONG                   HookCreateFileW_ACLEntries[1] = {0};  
ULONG                   HookCreateFileA_ACLEntries[1] = {0};  
ULONG                   HookReadFile_ACLEntries[1] = {0};  
ULONG                   HookPlaySoundW_ACLEntries[1]   = {0};  
ULONG                   HookMoveFileW_ACLEntries[1]   = {0}; 
ULONG                   HookCopyFileW_ACLEntries[1]   = {0}; 
ULONG                   HookDeleteFileW_ACLEntries[1]   = {0}; 
ULONG                   HookFindFirstFileW_ACLEntries[1]   = {0}; 
ULONG                   HookFindNextFileW_ACLEntries[1]   = {0}; 
ULONG                   HookSetFileAttributesW_ACLEntries[1]   = {0}; 
ULONG                   HookCreateHardLinkW_ACLEntries[1]   = {0}; 
ULONG                   HookSetEndOfFile_ACLEntries[1]   = {0}; 
ULONG                   HookSetFileValidData_ACLEntries[1]   = {0}; 
ULONG                   HookSetFileTime_ACLEntries[1]   = {0}; 
||||||| .r39
//zhangyunan.
static HANDLE (WINAPI *RealCreateFileW)( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)=CreateFileW;//暂时hook不成功，ofstream创建对象时出现问题。
static BOOL (WINAPI *RealMoveFileW)( LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)=MoveFileW;
static BOOL (WINAPI *RealCopyFileW)( LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists)=CopyFileW;
static BOOL (WINAPI *RealDeleteFileW)( LPCWSTR lpFileName) = DeleteFileW;
static HANDLE (WINAPI *RealFindFirstFileW)( LPCWSTR,  LPWIN32_FIND_DATAW)=FindFirstFileW;
static BOOL (WINAPI *RealFindNextFileW)( HANDLE hFindFile,  LPWIN32_FIND_DATAW lpFindFileData)=FindNextFileW;
static HCERTSTORE (WINAPI *RealCertOpenSystemStoreW)( HCRYPTPROV_LEGACY hProv,  LPCWSTR szSubsystemProtocol)=CertOpenSystemStoreW;
static HANDLE (WINAPI *RealCreateMutexW)( LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)=CreateMutexW;
static HRSRC (WINAPI *RealFindResourceW)( HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)=FindResourceW;
static UINT (WINAPI *RealGetWindowsDirectoryW)( LPWSTR lpBuffer, UINT uSize)=GetWindowsDirectoryW;
//static UINT (WINAPI *RealMapVirtualKeyW)( UINT uCode, UINT uMapType)=MapVirtualKeyW;
static HANDLE (WINAPI *RealOpenMutexW)( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)=OpenMutexW;
static SC_HANDLE (WINAPI *RealOpenSCManagerW)( LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)=OpenSCManagerW;
//static BOOL (WINAPI *RealCreateProcessW)( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)=CreateProcessW;
static SC_HANDLE (WINAPI *RealCreateServiceW)( SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword)=CreateServiceW;
static DWORD (WINAPI *RealGetModuleFileNameExW)( HANDLE hProcess, HMODULE hModule, LPWSTR lpFileName, DWORD nSize)=GetModuleFileNameExW;//K32GetModuleFileNameExW;
static HMODULE (WINAPI *RealGetModuleHandleW)( LPCWSTR lpModuleName)=GetModuleHandleW;
static VOID (WINAPI *RealGetStartupInfoW)( LPSTARTUPINFOW lpStartupInfo)=GetStartupInfoW;
static BOOL (WINAPI *RealGetVersionExW)( LPOSVERSIONINFOW lpVersionInfo)=GetVersionExW;
static HMODULE (WINAPI *RealLoadLibraryW)( LPCWSTR lpFileName)=LoadLibraryW;
static VOID (WINAPI *RealOutputDebugStringW)( LPCWSTR lpOutputString)=OutputDebugStringW;
static HHOOK (WINAPI *RealSetWindowsHookExW)( int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)=SetWindowsHookExW;
static HINSTANCE (WINAPI *RealShellExecuteW)( HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)=ShellExecuteW;
static BOOL (WINAPI *RealStartServiceCtrlDispatcherW)( CONST SERVICE_TABLE_ENTRYW *lpServiceTable)=StartServiceCtrlDispatcherW;
static LONG (WINAPI *RealRegOpenKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegOpenKeyW;
//static BOOL (WINAPI *RealModule32Next)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32Next;
//static BOOL (WINAPI *RealModule32First)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32First;
static LONG (WINAPI *RealRegCreateKeyExA)( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExA;
static LONG (WINAPI *RealRegCreateKeyExW)( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExW;
static LONG (WINAPI *RealRegCreateKeyA)( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)=RegCreateKeyA;
static LONG (WINAPI *RealRegCreateKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegCreateKeyW;
static LONG (WINAPI *RealRegQueryValueExA)( HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExA;
static LONG (WINAPI *RealRegQueryValueExW)( HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExW;
static LONG (WINAPI *RealRegQueryValueA)( HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue)=RegQueryValueA;
static LONG (WINAPI *RealRegQueryValueW)( HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue)=RegQueryValueW;
static LONG (WINAPI *RealRegSetValueExA)( HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExA;
static LONG (WINAPI *RealRegSetValueExW)( HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExW;
static LONG (WINAPI *RealRegSetValueA)( HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)=RegSetValueA;
static LONG (WINAPI *RealRegSetValueW)( HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)=RegSetValueW;
static LONG (WINAPI *RealRegDeleteKeyExA)( HKEY hKey, LPCSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExA;
static LONG (WINAPI *RealRegDeleteKeyExW)( HKEY hKey, LPCWSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExW;
static LONG (WINAPI *RealRegDeleteKeyA)( HKEY hKey, LPCSTR lpSubKey)=RegDeleteKeyA;
static LONG (WINAPI *RealRegDeleteKeyW)( HKEY hKey, LPCWSTR lpSubKey)=RegDeleteKeyW;
=======
//zhangyunan.
static HANDLE (WINAPI *RealCreateFileW)( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,\
										DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)\
										=CreateFileW;//暂时hook不成功，ofstream创建对象时出现问题。
static BOOL (WINAPI *RealMoveFileW)( LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)=MoveFileW;
static BOOL (WINAPI *RealCopyFileW)( LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists)=CopyFileW;
static BOOL (WINAPI *RealDeleteFileW)( LPCWSTR lpFileName) = DeleteFileW;
static HANDLE (WINAPI *RealFindFirstFileW)( LPCWSTR,  LPWIN32_FIND_DATAW)=FindFirstFileW;
static BOOL (WINAPI *RealFindNextFileW)( HANDLE hFindFile,  LPWIN32_FIND_DATAW lpFindFileData)=FindNextFileW;
static HCERTSTORE (WINAPI *RealCertOpenSystemStoreW)( HCRYPTPROV_LEGACY hProv,  LPCWSTR szSubsystemProtocol)=CertOpenSystemStoreW;
static HANDLE (WINAPI *RealCreateMutexW)( LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)=CreateMutexW;
static HRSRC (WINAPI *RealFindResourceW)( HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)=FindResourceW;
static UINT (WINAPI *RealGetWindowsDirectoryW)( LPWSTR lpBuffer, UINT uSize)=GetWindowsDirectoryW;
//static UINT (WINAPI *RealMapVirtualKeyW)( UINT uCode, UINT uMapType)=MapVirtualKeyW;
static HANDLE (WINAPI *RealOpenMutexW)( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)=OpenMutexW;
static SC_HANDLE (WINAPI *RealOpenSCManagerW)( LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)=OpenSCManagerW;
//static BOOL (WINAPI *RealCreateProcessW)( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, \
//LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, \
//LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)=CreateProcessW;
static SC_HANDLE (WINAPI *RealCreateServiceW)( SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, \
											  DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, \
											  LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, \
											  LPCWSTR lpPassword)=CreateServiceW;
static DWORD (WINAPI *RealGetModuleFileNameExW)( HANDLE hProcess, HMODULE hModule, LPWSTR lpFileName, DWORD nSize)=K32GetModuleFileNameExW;
static HMODULE (WINAPI *RealGetModuleHandleW)( LPCWSTR lpModuleName)=GetModuleHandleW;
static VOID (WINAPI *RealGetStartupInfoW)( LPSTARTUPINFOW lpStartupInfo)=GetStartupInfoW;
static BOOL (WINAPI *RealGetVersionExW)( LPOSVERSIONINFOW lpVersionInfo)=GetVersionExW;
static HMODULE (WINAPI *RealLoadLibraryW)( LPCWSTR lpFileName)=LoadLibraryW;
static VOID (WINAPI *RealOutputDebugStringW)( LPCWSTR lpOutputString)=OutputDebugStringW;
static HHOOK (WINAPI *RealSetWindowsHookExW)( int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)=SetWindowsHookExW;
static HINSTANCE (WINAPI *RealShellExecuteW)( HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, \
											 INT nShowCmd)=ShellExecuteW;
static BOOL (WINAPI *RealStartServiceCtrlDispatcherW)( CONST SERVICE_TABLE_ENTRYW *lpServiceTable)=StartServiceCtrlDispatcherW;
static LONG (WINAPI *RealRegOpenKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegOpenKeyW;
//static BOOL (WINAPI *RealModule32Next)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32Next;
//static BOOL (WINAPI *RealModule32First)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32First;
static LONG (WINAPI *RealRegCreateKeyExA)( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, \
										  LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExA;
static LONG (WINAPI *RealRegCreateKeyExW)( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, \
										  LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExW;
static LONG (WINAPI *RealRegCreateKeyA)( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)=RegCreateKeyA;
static LONG (WINAPI *RealRegCreateKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegCreateKeyW;
static LONG (WINAPI *RealRegQueryValueExA)( HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExA;
static LONG (WINAPI *RealRegQueryValueExW)( HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExW;
static LONG (WINAPI *RealRegQueryValueA)( HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue)=RegQueryValueA;
static LONG (WINAPI *RealRegQueryValueW)( HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue)=RegQueryValueW;
static LONG (WINAPI *RealRegSetValueExA)( HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExA;
static LONG (WINAPI *RealRegSetValueExW)( HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExW;
static LONG (WINAPI *RealRegSetValueA)( HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)=RegSetValueA;
static LONG (WINAPI *RealRegSetValueW)( HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)=RegSetValueW;
static LONG (WINAPI *RealRegDeleteKeyExA)( HKEY hKey, LPCSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExA;
static LONG (WINAPI *RealRegDeleteKeyExW)( HKEY hKey, LPCWSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExW;
static LONG (WINAPI *RealRegDeleteKeyA)( HKEY hKey, LPCSTR lpSubKey)=RegDeleteKeyA;
static LONG (WINAPI *RealRegDeleteKeyW)( HKEY hKey, LPCWSTR lpSubKey)=RegDeleteKeyW;
>>>>>>> .r53

//进程API
ULONG                   HookBitBlt_ACLEntries[1] = {0};  
//ULONG                   HookCoCreateInstance_ACLEntries[1] = {0};  
ULONG                   HookCreateFileMapping_ACLEntries[1] = {0};  
ULONG					HookOpenFileMapping_ACLEntries[1] = {0}; 
ULONG                   HookCryptAcquireContext_ACLEntries[1] = {0}; 
ULONG                   HookDeviceIoControl_ACLEntries[1] = {0};  
ULONG                   HookFindWindowEx_ACLEntries[1] = {0};  
ULONG                   HookGetAsyncKeyState_ACLEntries[1] = {0};  
ULONG                   HookGetDC_ACLEntries[1] = {0};  
ULONG                   HookGetForegroundWindow_ACLEntries[1] = {0};  
ULONG                   HookGetKeyState_ACLEntries[1] = {0};  
ULONG                   HookGetTempPath_ACLEntries[1] = {0};  
ULONG                   HookMapViewOfFile_ACLEntries[1] = {0};  
ULONG                   HookOpenFile_ACLEntries[1] = {0};  
ULONG                   HookAdjustTokenPrivileges_ACLEntries[1] = {0};  
ULONG                   HookAttachThreadInput_ACLEntries[1] = {0};  
ULONG                   HookCallNextHookEx_ACLEntries[1] = {0};  
ULONG                   HookCheckRemoteDebuggerPresent_ACLEntries[1] = {0};  
ULONG                   HookControlService_ACLEntries[1] = {0};  
ULONG                   HookCreateRemoteThread_ACLEntries[1] = {0};  
ULONG                   HookCreateToolhelp32Snapshot_ACLEntries[1] = {0};  
ULONG                   HookEnumProcesses_ACLEntries[1] = {0};  
ULONG                   HookEnumProcessModules_ACLEntries[1] = {0};  
ULONG                   HookGetProcAddress_ACLEntries[1] = {0};  
ULONG                   HookGetSystemDefaultLangID_ACLEntries[1] = {0}; 
ULONG                   HookGetThreadContext_ACLEntries[1] = {0}; 
ULONG                   HookGetTickCount_ACLEntries[1] = {0}; 
ULONG                   HookIsDebuggerPresent_ACLEntries[1] = {0}; 
ULONG                   HookLoadLibraryEx_ACLEntries[1] = {0}; 
ULONG                   HookLoadResource_ACLEntries[1] = {0}; 
ULONG                   HookModule32FirstW_ACLEntries[1] = {0}; 
ULONG                   HookModule32NextW_ACLEntries[1] = {0}; 
ULONG                   HookOpenProcess_ACLEntries[1] = {0}; 
ULONG                   HookPeekNamedPipe_ACLEntries[1] = {0}; 
ULONG                   HookProcess32First_ACLEntries[1] = {0}; 
ULONG                   HookProcess32Next_ACLEntries[1] = {0}; 
ULONG                   HookQueryPerformanceCounter_ACLEntries[1] = {0}; 
ULONG                   HookQueueUserAPC_ACLEntries[1] = {0}; 
ULONG                   HookReadProcessMemory_ACLEntries[1] = {0}; 
ULONG                   HookResumeThread_ACLEntries[1] = {0}; 
ULONG                   HookSetThreadContext_ACLEntries[1] = {0}; 
ULONG                   HookSuspendThread_ACLEntries[1] = {0}; 
//ULONG                   Hooksystem_ACLEntries[1] = {0}; 
ULONG                   HookThread32First_ACLEntries[1] = {0}; 
ULONG                   HookThread32Next_ACLEntries[1] = {0}; 
ULONG                   HookToolhelp32ReadProcessMemory_ACLEntries[1] = {0}; 
ULONG                   HookVirtualAllocEx_ACLEntries[1] = {0}; 
ULONG                   HookVirtualProtectEx_ACLEntries[1] = {0}; 
ULONG                   HookWinExec_ACLEntries[1] = {0}; 
ULONG                   HookWriteProcessMemory_ACLEntries[1] = {0}; 
ULONG                   HookRegisterHotKey_ACLEntries[1] = {0}; 
ULONG                   HookCreateProcessA_ACLEntries[1] = {0}; 
ULONG                   HookCertOpenSystemStoreW_ACLEntries[1] = {0}; 
ULONG                   HookCreateMutexW_ACLEntries[1] = {0}; 
ULONG                   HookFindResourceW_ACLEntries[1] = {0}; 
ULONG                   HookFindWindowW_ACLEntries[1] = {0}; 
ULONG                   HookGetWindowsDirectoryW_ACLEntries[1] = {0}; 
ULONG                   HookMapVirtualKeyW_ACLEntries[1] = {0}; 
ULONG                   HookOpenMutexW_ACLEntries[1] = {0}; 
ULONG                   HookOpenSCManagerW_ACLEntries[1] = {0}; 
ULONG                   HookCreateProcessW_ACLEntries[1] = {0}; 
ULONG                   HookCreateServiceW_ACLEntries[1] = {0}; 
ULONG                   HookGetModuleFileNameExW_ACLEntries[1] = {0}; 
ULONG                   HookGetModuleHandleW_ACLEntries[1] = {0}; 
ULONG                   HookGetStartupInfoW_ACLEntries[1] = {0}; 
ULONG                   HookGetVersionExW_ACLEntries[1] = {0}; 
ULONG                   HookLoadLibraryW_ACLEntries[1] = {0}; 
ULONG                   HookOutputDebugStringW_ACLEntries[1] = {0}; 
ULONG                   HookSetWindowsHookExW_ACLEntries[1] = {0}; 
ULONG                   HookShellExecuteW_ACLEntries[1] = {0}; 
ULONG                   HookStartServiceCtrlDispatcherW_ACLEntries[1] = {0}; 
ULONG                   HookSetLocalTime_ACLEntries[1] = {0}; 
ULONG                   HookTerminateThread_ACLEntries[1] = {0}; 
ULONG                   HookVirtualFree_ACLEntries[1] = {0}; 
ULONG                   HookSetProcessWorkingSetSize_ACLEntries[1] = {0}; 
ULONG                   HookTerminateProcess_ACLEntries[1] = {0}; 
//注册表
ULONG                   HookRegOpenKeyEx_ACLEntries[1] = {0}; 
ULONG                   HookRegOpenKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegCreateKeyExW_ACLEntries[1] = {0}; 
ULONG                   HookRegCreateKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegQueryValueExW_ACLEntries[1] = {0}; 
ULONG                   HookRegQueryValueW_ACLEntries[1] = {0}; 
ULONG                   HookRegSetValueExW_ACLEntries[1] = {0}; 
ULONG                   HookRegSetValueW_ACLEntries[1] = {0}; 
ULONG                   HookRegDeleteKeyExW_ACLEntries[1] = {0}; 
ULONG                   HookRegDeleteKeyW_ACLEntries[1] = {0}; 
ULONG                   HookRegSetKeySecurity_ACLEntries[1] = {0}; 
ULONG                   HookRegRestoreKey_ACLEntries[1] = {0}; 
ULONG                   HookRegReplaceKey_ACLEntries[1] = {0}; 
ULONG                   HookRegLoadKey_ACLEntries[1] = {0}; 
ULONG                   HookRegUnLoadKey_ACLEntries[1] = {0}; 
//网络
ULONG                   Hookaccept_ACLEntries[1] = {0}; 
ULONG                   Hooksend_ACLEntries[1] = {0}; 
ULONG                   Hookbind_ACLEntries[1] = {0}; 
ULONG                   Hookconnect_ACLEntries[1] = {0}; 
ULONG                   HookConnectNamedPipe_ACLEntries[1] = {0}; 
//ULONG                   HookGetAdaptersInfo_ACLEntries[1] = {0}; 
ULONG                   Hookgethostname_ACLEntries[1] = {0}; 
ULONG                   Hookinet_addr_ACLEntries[1] = {0}; 
ULONG                   HookInternetReadFile_ACLEntries[1] = {0}; 
ULONG                   HookInternetWriteFile_ACLEntries[1] = {0}; 
ULONG                   HookNetShareEnum_ACLEntries[1] = {0}; 
ULONG                   Hookrecv_ACLEntries[1] = {0}; 
ULONG                   HookWSAStartup_ACLEntries[1] = {0}; 
ULONG                   HookInternetOpenW_ACLEntries[1] = {0}; 
ULONG                   HookInternetOpenUrlW_ACLEntries[1] = {0}; 
ULONG                   HookURLDownloadToFileW_ACLEntries[1] = {0}; 
ULONG                   HookFtpPutFileW_ACLEntries[1] = {0}; 
ULONG                   HookHttpSendRequest_ACLEntries[1] = {0}; 
ULONG                   HookHttpSendRequestEx_ACLEntries[1] = {0}; 
ULONG                   HookHttpOpenRequest_ACLEntries[1] = {0}; 
ULONG                   HookInternetConnect_ACLEntries[1] = {0}; 
ULONG                   Hooklisten_ACLEntries[1] = {0}; 
ULONG					HookInternetOpenUrlA_ACLEntries[1]={0};
ULONG					HookHttpOpenRequestA_ACLEntries[1]={0};


int PrepareRealApiEntry()  
{  
	
	//初始化
	sprintf(log_path,"%sLog.txt",dlldir);
	//strcpy(log_path,"C:\\Log\\Log.txt");
	for(int i=0;i<=255;i++){
		strBuffer[i]=0;
	}
<<<<<<< .mine
	strcpy(spy,"00000");
	OutputDebugString(L"PrepareRealApiEntry()\n");  
||||||| .r39
	*/
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteFile>,func_params=<hFile|"<<filepath<<",nNumberOfBytesToWrite|"<<nNumberOfBytesToWrite<<">";
	
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	//RealOutputDebugStringA(sm.c_str());
	FILE *fp;
	HANDLE h;
	//h=RealCreateFileA("C:\\Log\\a.txt", GENERIC_READ, FILE_SHARE_READ, NULL,OPEN_EXISTING, 0, NULL);
	//RealOutputDebugStringA(sm.c_str());
	DWORD dwSize=0;
	char *logstr="Log.txt";
	//RealWriteFile(h,sm.c_str(),strlen(sm.c_str()),&dwSize,NULL);
	
	
	if(strstr(filepath,logstr)==NULL){
		
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)RealWriteFile,HookWriteFile);
		DetourTransactionCommit();
		
		RealOutputDebugStringA(sm.c_str());
		fp=fopen(log_path,"a+");
		fwrite("aa",2,1,fp);
		fputs(sm.c_str(),fp);
		fclose(fp);
		
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)RealWriteFile,HookWriteFile);
		DetourTransactionCommit();
		
	}
	
	sm="";
	logstream.clear();
	return RealWriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
}
=======
	*/
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteFile>,func_params=<hFile|"<<filepath<<",nNumberOfBytesToWrite|"<<nNumberOfBytesToWrite<<">";
	
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	//RealOutputDebugStringA(sm.c_str());
	FILE *fp;
	HANDLE h;
	//h=RealCreateFileA("C:\\Log\\a.txt", GENERIC_READ, FILE_SHARE_READ, NULL,OPEN_EXISTING, 0, NULL);
	//RealOutputDebugStringA(sm.c_str());
	DWORD dwSize=0;
	char *logstr="Log.txt";
	//RealWriteFile(h,sm.c_str(),strlen(sm.c_str()),&dwSize,NULL);
	
	
	if(strstr(filepath,logstr)==NULL){
		
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)RealWriteFile,HookWriteFile);
		DetourTransactionCommit();
		
		RealOutputDebugStringA(sm.c_str());
		fp=fopen(log_path,"a+");
		fwrite("aa",2,1,fp);
		fputs(sm.c_str(),fp);
		fclose(fp);
		
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)RealWriteFile,HookWriteFile);
		DetourTransactionCommit();
		
	}
	
	sm="";
	logstream.clear();
	return RealWriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
}
>>>>>>> .r53

<<<<<<< .mine
	// 获取真实函数地址  
	//HMODULE hws_232=LoadLibrary(L"");
	HMODULE hKernel32 = LoadLibrary(L"Kernel32.dll");
	HMODULE hUser32 = LoadLibrary(L"User32.dll");
	HMODULE hGdi32 = LoadLibrary(L"Gdi32.dll");
	HMODULE hOle32 = LoadLibrary(L"Ole32.dll");
	HMODULE hAdvapi32 = LoadLibrary(L"Advapi32.dll");
	HMODULE hCrypt32 = LoadLibrary(L"Crypt32.dll");
	HMODULE hWininet = LoadLibrary(L"Wininet.dll");
	HMODULE hNetapi32 = LoadLibrary(L"Netapi32.dll");
	HMODULE hWs2_32 = LoadLibrary(L"Ws2_32.dll");
	HMODULE hIphlpapi = LoadLibrary(L"Iphlpapi.dll");
	HMODULE hShell32 = LoadLibrary(L"Shell32.dll");
	HMODULE hUrlmon  = LoadLibrary(L"Urlmon.dll");
	if (hKernel32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Kernel32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Kernel32.dll\") OK\n");  
	if (hUser32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"User32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"User32.dll\") OK\n"); 
	if (hGdi32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Gdi32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Gdi32.dll\") OK\n");  
	if (hOle32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Ole32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Ole32.dll\") OK\n"); 
	if (hAdvapi32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Advapi32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Advapi32.dll\") OK\n");
	if (hCrypt32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Crypt32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Crypt32.dll\") OK\n");
	if (hWininet == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Wininet.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Wininet.dll\") OK\n");
	if (hNetapi32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Netapi32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Netapi32.dll\") OK\n");
	if (hWs2_32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Ws2_32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Ws2_32.dll\") OK\n");
	if (hIphlpapi == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Iphlpapi.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Iphlpapi.dll\") OK\n");
	if (hShell32 == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Shell32.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Shell32.dll\") OK\n");
	if (hUrlmon == NULL)  
	{  
		OutputDebugString(L"LoadLibrary(L\"Urlmon.dll\") Error\n");  
		return -6002;  
	}  
	OutputDebugString(L"LoadLibrary(L\"Urlmon.dll\") OK\n");
	//文件API
	realSetFileTime=(ptrSetFileTime)GetProcAddress(hGdi32,"SetFileTime");
	realSetFileValidData=(ptrSetFileValidData)GetProcAddress(hKernel32,"SetFileValidData");
	realSetEndOfFile=(ptrSetEndOfFile)GetProcAddress(hKernel32,"SetEndOfFile");
	realCreateHardLinkW=(ptrCreateHardLinkW)GetProcAddress(hKernel32,"CreateHardLinkW");
	realSetFileAttributesW=(ptrSetFileAttributesW)GetProcAddress(hKernel32,"SetFileAttributesW");
	realFindNextFileW=(ptrFindNextFileW)GetProcAddress(hKernel32,"FindNextFileW");
	realFindFirstFileW=(ptrFindFirstFileW)GetProcAddress(hKernel32,"FindFirstFileW");
	realDeleteFileW=(ptrDeleteFileW)GetProcAddress(hKernel32,"DeleteFileW");
	realCopyFileW=(ptrCopyFileW)GetProcAddress(hKernel32,"CopyFileW");
    realMoveFileW=(ptrMoveFileW)GetProcAddress(hKernel32,"MoveFileW");
	realCreateFileW = (ptrCreateFileW)GetProcAddress(hKernel32, "CreateFileW");
	realCreateFileA = (ptrCreateFileA)GetProcAddress(hKernel32, "CreateFileA");  
	realReadFile= (ptrReadFile)GetProcAddress(hKernel32,"ReadFile");
	//进程API
	realBitBlt= (ptrBitBlt)GetProcAddress(hGdi32,"BitBlt");
	//realCoCreateInstance= (ptrCoCreateInstance)GetProcAddress(hOle32,"CoCreateInstance");
	realCreateFileMapping= (ptrCreateFileMapping)GetProcAddress(hKernel32,"CreateFileMappingW");
	realOpenFileMapping= (ptrOpenFileMapping)GetProcAddress(hKernel32,"OpenFileMappingW");
	realCryptAcquireContext= (ptrCryptAcquireContext)GetProcAddress(hAdvapi32,"CryptAcquireContextW");
	realDeviceIoControl= (ptrDeviceIoControl)GetProcAddress(hKernel32,"DeviceIoControl");
	realFindWindowEx= (ptrFindWindowEx)GetProcAddress(hUser32,"FindWindowExW");
	realGetAsyncKeyState= (ptrGetAsyncKeyState)GetProcAddress(hUser32,"GetAsyncKeyState");
	realGetDC= (ptrGetDC)GetProcAddress(hUser32,"GetDC");
	realGetForegroundWindow= (ptrGetForegroundWindow)GetProcAddress(hUser32,"GetForegroundWindow");
	realGetKeyState= (ptrGetKeyState)GetProcAddress(hUser32,"GetKeyState");
	realGetTempPath= (ptrGetTempPath)GetProcAddress(hKernel32,"GetTempPath");
	realMapViewOfFile= (ptrMapViewOfFile)GetProcAddress(hKernel32,"MapViewOfFile");
	realOpenFile= (ptrOpenFile)GetProcAddress(hKernel32,"OpenFile");
	realAdjustTokenPrivileges= (ptrAdjustTokenPrivileges)GetProcAddress(hAdvapi32,"AdjustTokenPrivileges");
	realAttachThreadInput= (ptrAttachThreadInput)GetProcAddress(hUser32,"AttachThreadInput");
	realCallNextHookEx= (ptrCallNextHookEx)GetProcAddress(hUser32,"CallNextHookEx");
	realCheckRemoteDebuggerPresent= (ptrCheckRemoteDebuggerPresent)GetProcAddress(hKernel32,"CheckRemoteDebuggerPresent");
	realControlService= (ptrControlService)GetProcAddress(hAdvapi32,"ControlService");
	realCreateRemoteThread= (ptrCreateRemoteThread)GetProcAddress(hKernel32,"CreateRemoteThread");
	realCreateToolhelp32Snapshot= (ptrCreateToolhelp32Snapshot)GetProcAddress(hKernel32,"CreateToolhelp32Snapshot");
	realEnumProcesses= (ptrEnumProcesses)GetProcAddress(hKernel32,"EnumProcesses");
	realEnumProcessModules= (ptrEnumProcessModules)GetProcAddress(hKernel32,"EnumProcessModules");
	realGetProcAddress= (ptrGetProcAddress)GetProcAddress(hKernel32,"GetProcAddress");
	realGetSystemDefaultLangID= (ptrGetSystemDefaultLangID)GetProcAddress(hKernel32,"GetSystemDefaultLangID");
	realGetThreadContext= (ptrGetThreadContext)GetProcAddress(hKernel32,"GetThreadContext");
	realGetTickCount= (ptrGetTickCount)GetProcAddress(hKernel32,"GetTickCount");
	realIsDebuggerPresent= (ptrIsDebuggerPresent)GetProcAddress(hKernel32,"IsDebuggerPresent");
	realLoadLibraryEx= (ptrLoadLibraryEx)GetProcAddress(hKernel32,"LoadLibraryExW");
	realLoadResource= (ptrLoadResource)GetProcAddress(hKernel32,"LoadResource");
	realModule32FirstW= (ptrModule32FirstW)GetProcAddress(hKernel32,"Module32FirstW");
	realModule32NextW= (ptrModule32NextW)GetProcAddress(hKernel32,"Module32NextW");
	realOpenProcess= (ptrOpenProcess)GetProcAddress(hKernel32,"OpenProcess");
	realPeekNamedPipe= (ptrPeekNamedPipe)GetProcAddress(hKernel32,"PeekNamedPipe");
	realProcess32First= (ptrProcess32First)GetProcAddress(hKernel32,"Process32FirstW");
	realProcess32Next= (ptrProcess32Next)GetProcAddress(hKernel32,"Process32NextW");
	realQueryPerformanceCounter= (ptrQueryPerformanceCounter)GetProcAddress(hKernel32,"QueryPerformanceCounter");
	realQueueUserAPC= (ptrQueueUserAPC)GetProcAddress(hKernel32,"QueueUserAPC");
	realReadProcessMemory= (ptrReadProcessMemory)GetProcAddress(hKernel32,"ReadProcessMemory");
	realResumeThread= (ptrResumeThread)GetProcAddress(hKernel32,"ResumeThread");
	realSetThreadContext= (ptrSetThreadContext)GetProcAddress(hKernel32,"SetThreadContext");
	realSuspendThread= (ptrSuspendThread)GetProcAddress(hKernel32,"SuspendThread");
	//realsystem= (ptrsystem)GetProcAddress(hKernel32,"system");
	realThread32First= (ptrThread32First)GetProcAddress(hKernel32,"Thread32First");
	realThread32Next= (ptrThread32Next)GetProcAddress(hKernel32,"Thread32Next");
	realToolhelp32ReadProcessMemory= (ptrToolhelp32ReadProcessMemory)GetProcAddress(hKernel32,"Toolhelp32ReadProcessMemory");
	realVirtualAllocEx= (ptrVirtualAllocEx)GetProcAddress(hKernel32,"VirtualAllocEx");
	realVirtualProtectEx= (ptrVirtualProtectEx)GetProcAddress(hKernel32,"VirtualProtectEx");
	realWinExec= (ptrWinExec)GetProcAddress(hKernel32,"WinExec");
	realWriteProcessMemory= (ptrWriteProcessMemory)GetProcAddress(hKernel32,"WriteProcessMemory");
	realRegisterHotKey= (ptrRegisterHotKey)GetProcAddress(hUser32,"RegisterHotKey");
	realCreateProcessA= (ptrCreateProcessA)GetProcAddress(hKernel32,"CreateProcessA");
	realCertOpenSystemStoreW= (ptrCertOpenSystemStoreW)GetProcAddress(hCrypt32,"CertOpenSystemStoreW");
	realCreateMutexW= (ptrCreateMutexW)GetProcAddress(hKernel32,"CreateMutexW");
	realFindResourceW= (ptrFindResourceW)GetProcAddress(hKernel32,"FindResourceW");
	realFindWindowW= (ptrFindWindowW)GetProcAddress(hUser32,"FindWindowW");
	realGetWindowsDirectoryW= (ptrGetWindowsDirectoryW)GetProcAddress(hKernel32,"GetWindowsDirectoryW");
	realMapVirtualKeyW= (ptrMapVirtualKeyW)GetProcAddress(hUser32,"MapVirtualKeyW");
	realOpenMutexW= (ptrOpenMutexW)GetProcAddress(hKernel32,"OpenMutexW");
	realOpenSCManagerW= (ptrOpenSCManagerW)GetProcAddress(hAdvapi32,"OpenSCManagerW");
	realCreateProcessW= (ptrCreateProcessW)GetProcAddress(hKernel32,"CreateProcessW");
	realCreateServiceW= (ptrCreateServiceW)GetProcAddress(hAdvapi32,"CreateServiceW");
	realGetModuleFileNameExW= (ptrGetModuleFileNameExW)GetProcAddress(hKernel32,"GetModuleFileNameExW");
	realGetModuleHandleW= (ptrGetModuleHandleW)GetProcAddress(hKernel32,"GetModuleHandleW");
	realGetStartupInfoW= (ptrGetStartupInfoW)GetProcAddress(hKernel32,"GetStartupInfoW");
	realGetVersionExW= (ptrGetVersionExW)GetProcAddress(hKernel32,"GetVersionExW");
	realLoadLibraryW= (ptrLoadLibraryW)GetProcAddress(hKernel32,"LoadLibraryW");
	realOutputDebugStringW= (ptrOutputDebugStringW)GetProcAddress(hKernel32,"OutputDebugStringW");
	realSetWindowsHookExW= (ptrSetWindowsHookExW)GetProcAddress(hUser32,"SetWindowsHookExW");
	realShellExecuteW= (ptrShellExecuteW)GetProcAddress(hShell32,"ShellExecuteW");
	realStartServiceCtrlDispatcherW= (ptrStartServiceCtrlDispatcherW)GetProcAddress(hAdvapi32,"StartServiceCtrlDispatcherW");
	realSetLocalTime= (ptrSetLocalTime)GetProcAddress(hKernel32,"SetLocalTime");
	realTerminateThread= (ptrTerminateThread)GetProcAddress(hKernel32,"TerminateThread");
	realVirtualFree= (ptrVirtualFree)GetProcAddress(hKernel32,"VirtualFree");
	realSetProcessWorkingSetSize= (ptrSetProcessWorkingSetSize)GetProcAddress(hKernel32,"SetProcessWorkingSetSize");
	realTerminateProcess= (ptrTerminateProcess)GetProcAddress(hKernel32,"TerminateProcess");
	realRegOpenKeyEx= (ptrRegOpenKeyEx)GetProcAddress(hAdvapi32,"RegOpenKeyExW");
	realRegOpenKeyW= (ptrRegOpenKeyW)GetProcAddress(hAdvapi32,"RegOpenKeyW");
	realRegCreateKeyExW= (ptrRegCreateKeyExW)GetProcAddress(hAdvapi32,"RegCreateKeyExW");
	realRegCreateKeyW= (ptrRegCreateKeyW)GetProcAddress(hAdvapi32,"RegCreateKeyW");
	realRegQueryValueExW= (ptrRegQueryValueExW)GetProcAddress(hAdvapi32,"RegQueryValueExW");
	realRegQueryValueW= (ptrRegQueryValueW)GetProcAddress(hAdvapi32,"RegQueryValueW");
	realRegSetValueExW= (ptrRegSetValueExW)GetProcAddress(hAdvapi32,"RegSetValueExW");
	realRegSetValueW= (ptrRegSetValueW)GetProcAddress(hAdvapi32,"RegSetValueW");
	realRegDeleteKeyExW= (ptrRegDeleteKeyExW)GetProcAddress(hAdvapi32,"RegDeleteKeyExW");
	realRegDeleteKeyW= (ptrRegDeleteKeyW)GetProcAddress(hAdvapi32,"RegDeleteKeyW");
	realRegSetKeySecurity= (ptrRegSetKeySecurity)GetProcAddress(hAdvapi32,"RegSetKeySecurity");
	realRegRestoreKey= (ptrRegRestoreKey)GetProcAddress(hAdvapi32,"RegRestoreKeyW");
	realRegReplaceKey= (ptrRegReplaceKey)GetProcAddress(hAdvapi32,"RegReplaceKeyW");
	realRegLoadKey= (ptrRegLoadKey)GetProcAddress(hAdvapi32,"RegLoadKey");
	realRegUnLoadKey= (ptrRegUnLoadKey)GetProcAddress(hAdvapi32,"RegUnLoadKeyW");
	//网络
	realaccept= (ptraccept)GetProcAddress(hWs2_32,"accept");
	realsend= (ptrsend)GetProcAddress(hWs2_32,"send");
	realbind= (ptrbind)GetProcAddress(hWs2_32,"bind");
	realconnect= (ptrconnect)GetProcAddress(hWs2_32,"connect");
	realConnectNamedPipe= (ptrConnectNamedPipe)GetProcAddress(hKernel32,"ConnectNamedPipe");
	//realGetAdaptersInfo= (ptrGetAdaptersInfo)GetProcAddress(hIphlpapi,"GetAdaptersInfo");
	realgethostname= (ptrgethostname)GetProcAddress(hWs2_32,"gethostname");
	realinet_addr= (ptrinet_addr)GetProcAddress(hWs2_32,"inet_addr");
	realInternetReadFile= (ptrInternetReadFile)GetProcAddress(hWininet,"InternetReadFile");
	realInternetWriteFile= (ptrInternetWriteFile)GetProcAddress(hWininet,"InternetWriteFile");
	realNetShareEnum= (ptrNetShareEnum)GetProcAddress(hNetapi32,"NetShareEnum");
	realrecv= (ptrrecv)GetProcAddress(hWs2_32,"recv");
	realWSAStartup= (ptrWSAStartup)GetProcAddress(hWs2_32,"WSAStartup");
	realInternetOpenW= (ptrInternetOpenW)GetProcAddress(hWininet,"InternetOpenW");
	realInternetOpenUrlW= (ptrInternetOpenUrlW)GetProcAddress(hWininet,"InternetOpenUrlW");
	realURLDownloadToFileW= (ptrURLDownloadToFileW)GetProcAddress(hUrlmon,"URLDownloadToFileW");
	realFtpPutFileW= (ptrFtpPutFileW)GetProcAddress(hWininet,"FtpPutFileW");
	realHttpSendRequest= (ptrHttpSendRequest)GetProcAddress(hWininet,"HttpSendRequestW");
	realHttpSendRequestEx= (ptrHttpSendRequestEx)GetProcAddress(hWininet,"HttpSendRequestExW");
	realHttpOpenRequest= (ptrHttpOpenRequest)GetProcAddress(hWininet,"HttpOpenRequestW");
	reallisten= (ptrlisten)GetProcAddress(hWs2_32,"listen");
	realInternetOpenUrlA = (ptrInternetOpenUrlA)GetProcAddress(hWininet,"InternetOpenUrlA");
	realHttpOpenRequestA = (ptrHttpOpenRequestA)GetProcAddress(hWininet,"HttpOpenRequestA");
||||||| .r39
BOOL HookBitBlt( HDC hdc,  int x,  int y,  int cx,  int cy,  HDC hdcSrc,  int x1,  int y1,  DWORD rop)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<BitBlt>,func_params=<x|"<<x<<",y|"<<y<<",cx|"<<cx<<",cy|"<<cy<<">";
	string s,sm;
	/*
	logstream>>s;
	sm=s;
	while (1)
	{
		logstream>>s;
		if (logstream==NULL)
		{
			break;
		}
		sm=sm+" "+s;
	}//获取日志记录写入数组
	*/
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
    return ((MyBitBlt)RealBitBlt)(hdc,x,y,cx,cy,hdcSrc,x1,y1,rop);
}
HCERTSTORE WINAPI  HookCertOpenSystemStoreA( HCRYPTPROV hProv,  LPCSTR szSubsystemProtocol)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CertOpenSystemStore>,func_params=<szSubsystemProtocol|"<<szSubsystemProtocol<<">";
	string s,sm;
	sm="";
	/*
	logstream>>s;
	sm=s;
	while (1)
	{
		logstream>>s;
		if (logstream==NULL)
		{
			break;
		}
		sm=sm+" "+s;
	}//获取日志记录写入数组
	*/
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	return ((MyCertOpenSystemStoreA)RealCertOpenSystemStoreA)(hProv,szSubsystemProtocol);
}
HRESULT HookCoCreateInstance( REFCLSID rclsid,  LPUNKNOWN pUnkOuter,  DWORD dwClsContext,  REFIID riid, LPVOID FAR* ppv)
{
	//WaitForSingleObject(hMutex,INFINITE);
	char d[12];
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CoCreateInstance>";
=======
BOOL HookBitBlt( HDC hdc,  int x,  int y,  int cx,  int cy,  HDC hdcSrc,  int x1,  int y1,  DWORD rop)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<BitBlt>,func_params=<x|"<<x<<",y|"<<y<<",cx|"<<cx<<",cy|"<<cy<<">";
	string s,sm;
	/*
	logstream>>s;
	sm=s;
	while (1)
	{
		logstream>>s;
		if (logstream==NULL)
		{
			break;
		}
		sm=sm+" "+s;
	}//获取日志记录写入数组
	*/
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
    return ((MyBitBlt)RealBitBlt)(hdc,x,y,cx,cy,hdcSrc,x1,y1,rop);
}
HCERTSTORE WINAPI  HookCertOpenSystemStoreA( HCRYPTPROV hProv,  LPCSTR szSubsystemProtocol)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CertOpenSystemStore>,func_params=<szSubsystemProtocol|"<<szSubsystemProtocol<<">";
	string s,sm;
	sm="";
	/*
	logstream>>s;
	sm=s;
	while (1)
	{
		logstream>>s;
		if (logstream==NULL)
		{
			break;
		}
		sm=sm+" "+s;
	}//获取日志记录写入数组
	*/
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	return ((MyCertOpenSystemStoreA)RealCertOpenSystemStoreA)(hProv,szSubsystemProtocol);
}
HRESULT HookCoCreateInstance( REFCLSID rclsid,  LPUNKNOWN pUnkOuter,  DWORD dwClsContext,  REFIID riid, LPVOID FAR* ppv)
{
	//WaitForSingleObject(hMutex,INFINITE);
	char d[12];
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CoCreateInstance>";
>>>>>>> .r53

<<<<<<< .mine
||||||| .r39
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyCoCreateInstance)RealCoCreateInstance)(rclsid,pUnkOuter,dwClsContext,riid,ppv);
}
HANDLE HookCreateFile(LPCTSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFile>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFile(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}
HANDLE WINAPI HookCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateMutexA>,func_params=<lpName|"<<lpName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateMutexA(lpMutexAttributes,bInitialOwner,lpName);
}
HANDLE WINAPI HookCreateFileMapping(HANDLE hFile,LPSECURITY_ATTRIBUTES lpAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCTSTR lpName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	//GetFileNameFromHandle(hFile);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileMapping>,func_params=<lpName|"<<lpName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFileMapping(hFile,lpAttributes,flProtect,dwMaximumSizeHigh,dwMaximumSizeLow,lpName);
}

BOOL WINAPI HookCryptAcquireContext( HCRYPTPROV *phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags ){
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, proc_func_name=<CryptAcquireContext>,func_params=<pszContainer|"<<(pszContainer==NULL?"NULL":pszContainer)<<",pszProvider|"<<(pszProvider==NULL?"NULL":pszProvider)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyCryptAcquireContext)RealCryptAcquireContext)(phProv,pszContainer,pszProvider,dwProvType,dwFlags);
}
BOOL HookDeleteFile(LPCTSTR lpFileName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFile>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeleteFile(lpFileName);
}
HANDLE WINAPI HookCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwSharedAccess,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFileA(lpFileName,dwDesiredAccess,dwSharedAccess,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}
BOOL WINAPI HookMoveFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName){
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileA>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMoveFileA(lpExistingFileName,lpNewFileName);
}
BOOL WINAPI HookCopyFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName,BOOL bFailIfExists)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CopyFileA>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCopyFileA(lpExistingFileName,lpNewFileName,bFailIfExists);
}
BOOL WINAPI HookDeleteFileA(LPCSTR lpFileName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeleteFileA(lpFileName);
}
BOOL WINAPI HookReadFile( HANDLE hFile, LPVOID lpBuffer,  DWORD nNumberOfBytesToRead,  LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, proc_func_name=<ReadFile>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
}
BOOL WINAPI HookDeviceIoControl(  HANDLE hDevice,  DWORD dwIoControlCode, LPVOID lpInBuffer,  DWORD nInBufferSize,  LPVOID lpOutBuffer,  DWORD nOutBufferSize,  LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeviceIOControl>,func_params=<dwIoControlCode|"<<dwIoControlCode<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeviceIoControl(hDevice,dwIoControlCode,lpInBuffer,nInBufferSize,lpOutBuffer,nOutBufferSize,lpBytesReturned,lpOverlapped);
}
HANDLE WINAPI HookFindFirstFileA(  LPCSTR lpFileName,  LPWIN32_FIND_DATAA lpFindFileData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindFirstFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindFirstFileA(lpFileName,lpFindFileData);
}
BOOL WINAPI HookFindNextFileA(  HANDLE hFindFile,  LPWIN32_FIND_DATAA lpFindFileData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindNextFileA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindNextFileA(hFindFile,lpFindFileData);
}
HRSRC WINAPI HookFindResourceA(  HMODULE hModule,  LPCSTR lpName,  LPCSTR lpType )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindResourceA>,func_params=<lpName|"<<(lpName==NULL?"NULL":lpName)<<",lpType|"<<(lpType==NULL?"NULL":lpType)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindResourceA(hModule,lpName,lpType);
}
HWND WINAPI HookFindWindowA( LPCSTR lpClassName,  LPCSTR lpWindowName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindWindowA>,func_params=<lpClassName|"<<lpClassName<<",lpWindowName|"<<lpWindowName<<">";
	
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindWindowA(lpClassName,lpWindowName);
}
BOOL HookFtpPutFileA(  HINTERNET hConnect,  LPCSTR lpszLocalFile,  LPCSTR lpszNewRemoteFile,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FtpPutFileA>,func_params=<lpszLocalFile|"<<(lpszLocalFile==NULL?"NULL":lpszLocalFile)<<",lpszNewRemoteFile|"<<(lpszNewRemoteFile==NULL?"NULL":lpszNewRemoteFile)<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyFtpPutFileA)RealFtpPutFileA)(hConnect,lpszLocalFile,lpszNewRemoteFile,dwFlags,dwContext);
}

//by zhangyunan this func
BOOL HookFtpPutFileW(  HINTERNET hConnect,  LPCWSTR lpszLocalFile,  LPCWSTR lpszNewRemoteFile,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FtpPutFileW>,func_params=<lpszLocalFile|"<<(lpszLocalFile==NULL?L"NULL":lpszLocalFile)<<",lpszNewRemoteFile|"<<(lpszNewRemoteFile==NULL?L"NULL":lpszNewRemoteFile)<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyFtpPutFileW)RealFtpPutFileW)(hConnect,lpszLocalFile,lpszNewRemoteFile,dwFlags,dwContext);
}
SHORT WINAPI HookGetAsyncKeyState( int vKey)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetAsyncKeyState>,func_params=<vKey|"<<vKey<<">";
	
	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetAsyncKeyState(vKey);
}
HDC HookGetDC( HWND hWnd)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetDC>";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetDC(hWnd);
}
HWND WINAPI HookGetForegroundWindow()
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetForegroundWindow>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetForegroundWindow();
}
SHORT WINAPI HookGetKeyState( int nVirtKey)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetKeyState>,func_params=<nVirtKey|"<<nVirtKey<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetKeyState(nVirtKey);
}
DWORD WINAPI HookGetTempPath(  DWORD nBufferLength, LPWSTR lpBuffer )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetTempPath>,func_params=<nBufferLength|"<<nBufferLength<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetTempPath(nBufferLength,lpBuffer);
}
UINT WINAPI HookGetWindowsDirectoryA(  LPSTR lpBuffer,   UINT uSize)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryA>,func_params=<lpBuffer|"<<(lpBuffer==NULL?"NULL":lpBuffer)<<",uSize|"<<uSize<<">";
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryA>,func_params=<uSize|"<<uSize<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetWindowsDirectoryA(lpBuffer,uSize);
}
HFILE WINAPI HookOpenFile(  LPCSTR lpFileName,  LPOFSTRUCT lpReOpenBuff,  UINT uStyle )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenFile>,func_params=<lpFileName|"<<(lpFileName==NULL?"NULL":lpFileName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenFile(lpFileName,lpReOpenBuff,uStyle);
}
HANDLE WINAPI HookOpenMutexA(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  LPCSTR lpName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenMutexA>,func_params=<lpName|"<<(lpName==NULL?"NULL":lpName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenMutexA(dwDesiredAccess,bInheritHandle,lpName);
}
LPVOID WINAPI HookMapViewOfFile(  HANDLE hFileMappingObject,  DWORD dwDesiredAccess,  DWORD dwFileOffsetHigh,  DWORD dwFileOffsetLow,  SIZE_T dwNumberOfBytesToMap )
{
	//WaitForSingleObject(hMutex,INFINITE);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapViewOfFile>,func_params=<dwNumberOfBytesToMap|"<<dwNumberOfBytesToMap<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMapViewOfFile(hFileMappingObject,dwDesiredAccess,dwFileOffsetHigh,dwFileOffsetLow,dwNumberOfBytesToMap);
}
UINT WINAPI HookMapVirtualKeyA( UINT uCode,  UINT uMapType)
{
	//WaitForSingleObject(hMutex,INFINITE);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapVirtualKeyA>,func_params=<uCode|"<<uCode<<",uMapType|"<<uMapType<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMapVirtualKeyA(uCode,uMapType);

}
SC_HANDLE WINAPI HookOpenSCManagerA(  LPCSTR lpMachineName,  LPCSTR lpDatabaseName,  DWORD dwDesiredAccess )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenSCManagerA>,func_params=<lpMachineName|"<<(lpMachineName==NULL?"NULL":lpMachineName)<<",lpDatabaseName|"<<(lpDatabaseName==NULL?"NULL":lpDatabaseName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenSCManagerA(lpMachineName,lpDatabaseName,dwDesiredAccess);
}
BOOL WINAPI HookSetFileTime(  HANDLE hFile,  CONST FILETIME * lpCreationTime,  CONST FILETIME * lpLastAccessTime,  CONST FILETIME * lpLastWriteTime )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFileTime>,func_params=<lpCreationTime|"<<lpCreationTime<<",lpLastAccessTime|"<<lpLastAccessTime<<",lpLastWriteTime|"<<lpLastWriteTime<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetFileTime(hFile,lpCreationTime,lpLastAccessTime,lpLastWriteTime);
}

/*
进程相关API
*/

BOOL WINAPI HookAdjustTokenPrivileges(  HANDLE TokenHandle,  BOOL DisableAllPrivileges,  PTOKEN_PRIVILEGES NewState,  DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState,  PDWORD ReturnLength )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<AdjustTokenPrivileges>,func_params=<DisableAllPrivileges|"<<DisableAllPrivileges<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealAdjustTokenPrivileges(TokenHandle,DisableAllPrivileges,NewState,BufferLength,PreviousState,ReturnLength);
}
BOOL WINAPI HookAttachThreadInput( DWORD idAttach,  DWORD idAttachTo,  BOOL fAttach)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<AttachThreadInput>,func_params=<idAttach|"<<idAttach<<",idAttachTo|"<<idAttachTo<<",fAttach|"<<fAttach<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealAttachThreadInput(idAttach,idAttachTo,fAttach);
}
LRESULT WINAPI HookCallNextHookEx( HHOOK hhk,  int nCode,  WPARAM wParam,  LPARAM lParam)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CallNextHookEx>,func_params=<nCode|"<<nCode<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCallNextHookEx(hhk,nCode,wParam,lParam);
}
BOOL WINAPI HookCheckRemoteDebuggerPresent(  HANDLE hProcess,  PBOOL pbDebuggerPresent )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CheckRemoteDebuggerPresent>,func_params=<pbDebuggerPresent|"<<pbDebuggerPresent<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCheckRemoteDebuggerPresent(hProcess,pbDebuggerPresent);
}
BOOL WINAPI HookControlService(  SC_HANDLE hService,  DWORD dwControl,  LPSERVICE_STATUS lpServiceStatus )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ControlService>,func_params=<dwControl|"<<dwControl<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealControlService(hService,dwControl,lpServiceStatus);
}
BOOL WINAPI HookCreateProcessA(  LPCSTR lpApplicationName, LPSTR lpCommandLine,  LPSECURITY_ATTRIBUTES lpProcessAttributes,  LPSECURITY_ATTRIBUTES lpThreadAttributes,  BOOL bInheritHandles,  DWORD dwCreationFlags,  LPVOID lpEnvironment,  LPCSTR lpCurrentDirectory,  LPSTARTUPINFOA lpStartupInfo,  LPPROCESS_INFORMATION lpProcessInformation )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateProcessA>,func_params=<lpApplicationName|"<<lpApplicationName<<",lpCommandLine|"<<lpCommandLine<<",lpCurrentDirectory|"<<lpCurrentDirectory<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}
HANDLE WINAPI HookCreateRemoteThread(  HANDLE hProcess,  LPSECURITY_ATTRIBUTES lpThreadAttributes,  SIZE_T dwStackSize,  LPTHREAD_START_ROUTINE lpStartAddress,  LPVOID lpParameter,  DWORD dwCreationFlags,  LPDWORD lpThreadId )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateRemoteThread>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateRemoteThread(hProcess,lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,lpThreadId);
}
SC_HANDLE WINAPI HookCreateServiceA(  SC_HANDLE hSCManager,  LPCSTR lpServiceName,  LPCSTR lpDisplayName,  DWORD dwDesiredAccess,  DWORD dwServiceType,  DWORD dwStartType,  DWORD dwErrorControl,  LPCSTR lpBinaryPathName,  LPCSTR lpLoadOrderGroup,  LPDWORD lpdwTagId,  LPCSTR lpDependencies,  LPCSTR lpServiceStartName,  LPCSTR lpPassword )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateServiceA>,func_params=<lpServiceName|"<<lpServiceName<<",lpDisplayName|"<<lpDisplayName<<",lpBinaryPathName|"<<lpBinaryPathName<<",lpLoadOrderGroup|"<<lpLoadOrderGroup<<",lpServiceStartName|"<<lpServiceStartName<<",lpPassword|"<<lpPassword<<")>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateServiceA(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
}
HANDLE WINAPI HookCreateToolhelp32Snapshot( DWORD dwFlags, DWORD th32ProcessID )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateToolhelp32Snapshot>,func_params=<dwFlags|"<<dwFlags<<",th32ProcessID|"<<th32ProcessID<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateToolhelp32Snapshot(dwFlags,th32ProcessID);
}
BOOL WINAPI HookEnumProcesses( DWORD * lpidProcess,  DWORD cb,  LPDWORD lpcbNeeded )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">proc_func_name=<EnumProcesses>,func_params=<cb|"<<cb<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealEnumProcesses(lpidProcess,cb,lpcbNeeded);
}
BOOL WINAPI HookEnumProcessModules(  HANDLE hProcess, HMODULE *lphModule,  DWORD cb,  LPDWORD lpcbNeeded )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<EnumProcessModules>,func_params=<cb|"<<cb<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealEnumProcessModules(hProcess,lphModule,cb,lpcbNeeded);
}
DWORD WINAPI HookGetModuleFileNameExA(  HANDLE hProcess,  HMODULE hModule, LPSTR lpFilename,  DWORD nSize )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleFileNameExA>,func_params=<lpFilename|"<<(lpFilename==NULL?"NULL":lpFilename)<<">";
	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath();/*<<">,proc_func_name=<GetModuleFileNameExA>";
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	
	return RealGetModuleFileNameExA(hProcess,hModule,lpFilename,nSize);
}
HMODULE WINAPI HookGetModuleHandleA(  LPCSTR lpModuleName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleHandleA>,func_params=<lpModuleName|"<<(lpModuleName==NULL?"NULL":lpModuleName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetModuleHandleA(lpModuleName);
}
FARPROC WINAPI HookGetProcAddress(  HMODULE hModule,  LPCSTR lpProcName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	//f<<LogTime()<<" pathname=<"<<GetProcessPath()<<">, pid=<"<<_getpid()<<">, function=<GetProcAddress(lpProcName="<<lpProcName<<")>"<<endl;
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetProcAddress>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetProcAddress(hModule,lpProcName);
}
VOID WINAPI HookGetStartupInfoA(  LPSTARTUPINFOA lpStartupInfo )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetStartupInfoA>,func_params=<lpStartupInfo|"<<lpStartupInfo<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetStartupInfoA(lpStartupInfo);
}
LANGID WINAPI HookGetSystemDefaultLangID()
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetSystemDefaultLangID>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetSystemDefaultLangID();
}
BOOL WINAPI HookGetThreadContext(  HANDLE hThread,  LPCONTEXT lpContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetThreadContext>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetThreadContext(hThread,lpContext);
}
DWORD WINAPI HookGetTickCount(VOID)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetTickCount>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetTickCount();
}
BOOL WINAPI HookGetVersionExA(  LPOSVERSIONINFOA lpVersionInformation )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetVersionExA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetVersionExA(lpVersionInformation);
}
BOOL WINAPI HookIsDebuggerPresent()
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<IsDebuggerPresent>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealIsDebuggerPresent();
}
HMODULE WINAPI HookLoadLibraryA(  LPCSTR lpLibFileName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadLibraryA>,func_params=<lpLibFileName|"<<lpLibFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealLoadLibraryA(lpLibFileName);
}
HGLOBAL WINAPI HookLoadResource(  HMODULE hModule,  HRSRC hResInfo )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadResource>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealLoadResource(hModule,hResInfo);
}
BOOL WINAPI HookModule32FirstW( HANDLE hSnapshot, LPMODULEENTRY32W lpme )
{
	//WaitForSingleObject(hMutex,INFINITE);
	//::MessageBoxW(NULL,_T("Module32FirstW Hooked"),_T("APIHook"),0);//张宇南测试所加
	cout<<"Module32FirstW hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, pid=<"<<_getpid()<<">,proc_func_name=<Module32FirstW>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32FirstW)RealModule32FirstW)(hSnapshot,lpme);//((MyModule32FirstW)RealModule32FirstW)
}
BOOL WINAPI HookModule32NextW( HANDLE hSnapshot, LPMODULEENTRY32W lpme )
{
	//WaitForSingleObject(hMutex,INFINITE);
	//::MessageBoxW(NULL,_T("Module32NextW Hooked"),_T("APIHook"),0);//张宇南测试所加
	cout<<"Module32NextW hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32NextW>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32NextW)RealModule32NextW)(hSnapshot,lpme);
}
HANDLE WINAPI HookOpenProcess(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  DWORD dwProcessId )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenProcess>,func_params=<dwDesiredAccess|"<<dwDesiredAccess<<",bInheritHandle|"<<bInheritHandle<<",dwProcessId|"<<dwProcessId<<">";//这个函数内如果调用GetProcessPath会崩溃

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId);
}
VOID WINAPI HookOutputDebugStringA(  LPCSTR lpOutputString )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringA>,func_params=<lpOutputString|"<<lpOutputString<<">";
	//lpOutputString可能出现\n会影响日志格式所以不输出这个参数
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOutputDebugStringA(lpOutputString);
}
BOOL WINAPI HookPeekNamedPipe(  HANDLE hNamedPipe, LPVOID lpBuffer,  DWORD nBufferSize,  LPDWORD lpBytesRead,  LPDWORD lpTotalBytesAvail,  LPDWORD lpBytesLeftThisMessage )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<PeekNamedPipe>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealPeekNamedPipe(hNamedPipe,lpBuffer,nBufferSize,lpBytesRead,lpTotalBytesAvail,lpBytesLeftThisMessage);
}
BOOL WINAPI HookProcess32First( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32First>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealProcess32First(hSnapshot,lppe);
}
BOOL WINAPI HookProcess32Next( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32Next>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealProcess32Next(hSnapshot,lppe);
}
BOOL WINAPI HookQueryPerformanceCounter(  LARGE_INTEGER * lpPerformanceCount )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<QueryPerformanceCounter>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealQueryPerformanceCounter(lpPerformanceCount);
}
DWORD WINAPI HookQueueUserAPC(  PAPCFUNC pfnAPC,  HANDLE hThread,  ULONG_PTR dwData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<QueueUserAPC>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealQueueUserAPC(pfnAPC,hThread,dwData);
}
BOOL WINAPI HookReadProcessMemory( HANDLE hProcess,  LPCVOID lpBaseAddress, LPVOID lpBuffer,  SIZE_T nSize,  SIZE_T * lpNumberOfBytesRead )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ReadProcessMemory>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealReadProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesRead);
}
DWORD WINAPI HookResumeThread(  HANDLE hThread )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealResumeThread(hThread);
}
BOOL WINAPI HookSetThreadContext(  HANDLE hThread,  CONST CONTEXT * lpContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetThreadContext>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetThreadContext(hThread,lpContext);
}
HHOOK WINAPI HookSetWindowsHookExA( int idHook,  HOOKPROC lpfn,  HINSTANCE hmod,  DWORD dwThreadId)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetWindowsHookExA>,func_params=<idHook|"<<idHook<<",dwThreadId|"<<dwThreadId<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetWindowsHookExA(idHook,lpfn,hmod,dwThreadId);
}
HINSTANCE WINAPI HookShellExecuteA( HWND hwnd,  LPCSTR lpOperation,  LPCSTR lpFile,  LPCSTR lpParameters,  LPCSTR lpDirectory,  INT nShowCmd)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ShellExecuteA>,func_params=<lpOperation|"<<lpOperation<<",lpFile|"<<lpFile<<",lpParameters|"<<lpParameters<<",lpDirectory|"<<lpDirectory<<",nShowCmd|"<<nShowCmd<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealShellExecuteA(hwnd,lpOperation,lpFile,lpParameters,lpDirectory,nShowCmd);
}
BOOL WINAPI HookStartServiceCtrlDispatcherA(  CONST SERVICE_TABLE_ENTRYA *lpServiceStartTable )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<StartServiceCtrlDispatcherA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealStartServiceCtrlDispatcherA(lpServiceStartTable);
}
DWORD WINAPI HookSuspendThread(  HANDLE hThread )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SuspendThread>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSuspendThread(hThread);
}
int Hooksystem(const char * _Command)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<system>,func_params=<_Command|"<<_Command<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return Realsystem(_Command);
}
BOOL WINAPI HookThread32First( HANDLE hSnapshot, LPTHREADENTRY32 lpte )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Thread32First>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealThread32First(hSnapshot,lpte);
}
BOOL WINAPI HookThread32Next( HANDLE hSnapshot, LPTHREADENTRY32 lpte )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Thread32Next>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealThread32Next(hSnapshot,lpte);
}
BOOL WINAPI HookToolhelp32ReadProcessMemory( DWORD th32ProcessID, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T cbRead, SIZE_T *lpNumberOfBytesRead )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Toolhelp32ReadProcessMemory>,func_params=<th32ProcessID|"<<th32ProcessID<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealToolhelp32ReadProcessMemory(th32ProcessID,lpBaseAddress,lpBuffer,cbRead,lpNumberOfBytesRead);
}
LPVOID WINAPI HookVirtualAllocEx( HANDLE hProcess,  LPVOID lpAddress,  SIZE_T dwSize,  DWORD flAllocationType,  DWORD flProtect )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualAllocEx>,func_params=<flAllocationType|"<<flAllocationType<<",flProtect|"<<flProtect<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealVirtualAllocEx(hProcess,lpAddress,dwSize,flAllocationType,flProtect);
}
BOOL WINAPI HookVirtualProtectEx(  HANDLE hProcess ,  LPVOID lpAddress,  SIZE_T dwSize,  DWORD flNewProtect,  PDWORD lpflOldProtect )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualProtectEx>,func_params=<flNewProtect|"<<flNewProtect<<",lpflOldProtect|"<<lpflOldProtect<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealVirtualProtectEx(hProcess,lpAddress,dwSize,flNewProtect,lpflOldProtect);
}
UINT WINAPI HookWinExec(  LPCSTR lpCmdLine,  UINT uCmdShow )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WinExec>,func_params=<lpCmdLine|"<<lpCmdLine<<",uCmdShow|"<<uCmdShow<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealWinExec(lpCmdLine,uCmdShow);
}
BOOL WINAPI HookWriteProcessMemory( HANDLE hProcess,  LPVOID lpBaseAddress, LPCVOID lpBuffer,  SIZE_T nSize,  SIZE_T * lpNumberOfBytesWritten )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteProcessMemory>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealWriteProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
}
BOOL WINAPI HookRegisterHotKey( HWND hWnd,  int id,  UINT fsModifiers,  UINT vk)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegisterHotKey>,func_params=<id|"<<id<<",fsModifiers|"<<fsModifiers<<",vk|"<<vk<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegisterHotKey(hWnd,id,fsModifiers,vk);
}
BOOL WINAPI HookCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
	DWORD dwLastError = GetLastError();
	BOOL  bResult = FALSE;
	CHAR  szDetouredDll[MAX_PATH];
	CHAR  szDllName[MAX_PATH];
	HMODULE hMod1 = NULL, hMod2 = NULL;

	// get the full path to the detours DLL
	hMod1 = GetModuleHandleA("detoured.dll");
	GetModuleFileNameA(hMod1, szDetouredDll, MAX_PATH);

	// get the full path to the hooking DLL
	GetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
		(LPCTSTR)&HookCreateProcessW,
		&hMod2);

	GetModuleFileNameA(hMod2, szDllName, MAX_PATH);

	OutputDebugStringA(szDllName);
	OutputDebugStringA(szDetouredDll);
	OutputDebugStringA("\n");

	//wprintf(L"[DetoursHooks] Intercepting the creation of %s\n", lpCommandLine);

	// route creation of new process through 
	// the detours API 
	bResult = DetourCreateProcessWithDllW(
		lpApplicationName,
		lpCommandLine, 
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment, 
		lpCurrentDirectory,
		lpStartupInfo, 
		lpProcessInformation, 
		//szDetouredDll, 
		szDllName, 
		(PDETOUR_CREATE_PROCESS_ROUTINEW)RealCreateProcessW);

	SetLastError(dwLastError);
	return bResult;
}
//这个函数到底调试了没有？ 张宇南 2015/10/17.

/*
注册表相关
*/
LONG WINAPI HookRegOpenKeyA(  HKEY hKey,  LPCSTR lpSubKey,  PHKEY phkResult )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyA>,func_params=<lpSubKey|"<<lpSubKey<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyA(hKey,lpSubKey,phkResult);
}
LONG WINAPI HookRegOpenKeyEx(HKEY hKey,LPCWSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)
{
	//WaitForSingleObject(hMutex,INFINITE);
/*	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyEx>,func_params=<lpSubKey|"<<lpSubKey<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);*/
	return RealRegOpenKeyEx(hKey,lpSubKey,ulOptions,samDesired,phkResult);
}

/*
网络相关
*/
int WSAAPI Hookconnect(  SOCKET s, const struct sockaddr FAR * name,  int namelen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in* sock;
	int socklen=sizeof(sock);
	sock=(struct sockaddr_in *)name;
	char *sock_ip=inet_ntoa((*sock).sin_addr);
=======
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyCoCreateInstance)RealCoCreateInstance)(rclsid,pUnkOuter,dwClsContext,riid,ppv);
}
HANDLE HookCreateFile(LPCTSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFile>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFile(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}
HANDLE WINAPI HookCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateMutexA>,func_params=<lpName|"<<lpName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateMutexA(lpMutexAttributes,bInitialOwner,lpName);
}
HANDLE WINAPI HookCreateFileMapping(HANDLE hFile,LPSECURITY_ATTRIBUTES lpAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCTSTR lpName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	//GetFileNameFromHandle(hFile);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileMapping>,func_params=<lpName|"<<lpName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFileMapping(hFile,lpAttributes,flProtect,dwMaximumSizeHigh,dwMaximumSizeLow,lpName);
}

BOOL WINAPI HookCryptAcquireContext( HCRYPTPROV *phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags ){
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, proc_func_name=<CryptAcquireContext>,func_params=<pszContainer|"<<(pszContainer==NULL?"NULL":pszContainer)<<\
		",pszProvider|"<<(pszProvider==NULL?"NULL":pszProvider)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyCryptAcquireContext)RealCryptAcquireContext)(phProv,pszContainer,pszProvider,dwProvType,dwFlags);
}
BOOL HookDeleteFile(LPCTSTR lpFileName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFile>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeleteFile(lpFileName);
}
HANDLE WINAPI HookCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwSharedAccess,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFileA(lpFileName,dwDesiredAccess,dwSharedAccess,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}
BOOL WINAPI HookMoveFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName){
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileA>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMoveFileA(lpExistingFileName,lpNewFileName);
}
BOOL WINAPI HookCopyFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName,BOOL bFailIfExists)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CopyFileA>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCopyFileA(lpExistingFileName,lpNewFileName,bFailIfExists);
}
BOOL WINAPI HookDeleteFileA(LPCSTR lpFileName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeleteFileA(lpFileName);
}
BOOL WINAPI HookReadFile( HANDLE hFile, LPVOID lpBuffer,  DWORD nNumberOfBytesToRead,  LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, proc_func_name=<ReadFile>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
}
BOOL WINAPI HookDeviceIoControl(  HANDLE hDevice,  DWORD dwIoControlCode, LPVOID lpInBuffer,  DWORD nInBufferSize,  LPVOID lpOutBuffer,  DWORD nOutBufferSize,  LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeviceIOControl>,func_params=<dwIoControlCode|"<<dwIoControlCode<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeviceIoControl(hDevice,dwIoControlCode,lpInBuffer,nInBufferSize,lpOutBuffer,nOutBufferSize,lpBytesReturned,lpOverlapped);
}
HANDLE WINAPI HookFindFirstFileA(  LPCSTR lpFileName,  LPWIN32_FIND_DATAA lpFindFileData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindFirstFileA>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindFirstFileA(lpFileName,lpFindFileData);
}
BOOL WINAPI HookFindNextFileA(  HANDLE hFindFile,  LPWIN32_FIND_DATAA lpFindFileData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindNextFileA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindNextFileA(hFindFile,lpFindFileData);
}
HRSRC WINAPI HookFindResourceA(  HMODULE hModule,  LPCSTR lpName,  LPCSTR lpType )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindResourceA>,func_params=<lpName|"<<(lpName==NULL?"NULL":lpName)<<",lpType|"<<(lpType==NULL?"NULL":lpType)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindResourceA(hModule,lpName,lpType);
}
HWND WINAPI HookFindWindowA( LPCSTR lpClassName,  LPCSTR lpWindowName)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindWindowA>,func_params=<lpClassName|"<<lpClassName<<",lpWindowName|"<<lpWindowName<<">";
	
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindWindowA(lpClassName,lpWindowName);
}
BOOL HookFtpPutFileA(  HINTERNET hConnect,  LPCSTR lpszLocalFile,  LPCSTR lpszNewRemoteFile,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FtpPutFileA>,func_params=<lpszLocalFile|"<<(lpszLocalFile==NULL?"NULL":lpszLocalFile)<<\
		",lpszNewRemoteFile|"<<(lpszNewRemoteFile==NULL?"NULL":lpszNewRemoteFile)<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyFtpPutFileA)RealFtpPutFileA)(hConnect,lpszLocalFile,lpszNewRemoteFile,dwFlags,dwContext);
}

//by zhangyunan this func
BOOL HookFtpPutFileW(  HINTERNET hConnect,  LPCWSTR lpszLocalFile,  LPCWSTR lpszNewRemoteFile,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	char pMultiByteLocalFile[512];
	WideCharToMultiByte(CP_ACP,0,lpszLocalFile,-1,pMultiByteLocalFile,(int)strlen(pMultiByteLocalFile),NULL,NULL);
	char pMultiByteNewRemoteFile[512];
	WideCharToMultiByte(CP_ACP,0,lpszNewRemoteFile,-1,pMultiByteNewRemoteFile,(int)strlen(pMultiByteNewRemoteFile),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FtpPutFileW>,func_params=<lpszLocalFile|"<<(lpszLocalFile==NULL?"NULL":pMultiByteLocalFile)<<\
		",lpszNewRemoteFile|"<<(lpszNewRemoteFile==NULL?"NULL":pMultiByteNewRemoteFile)<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyFtpPutFileW)RealFtpPutFileW)(hConnect,lpszLocalFile,lpszNewRemoteFile,dwFlags,dwContext);
}
SHORT WINAPI HookGetAsyncKeyState( int vKey)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetAsyncKeyState>,func_params=<vKey|"<<vKey<<">";
	
	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetAsyncKeyState(vKey);
}
HDC HookGetDC( HWND hWnd)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetDC>";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetDC(hWnd);
}
HWND WINAPI HookGetForegroundWindow()
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetForegroundWindow>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetForegroundWindow();
}
SHORT WINAPI HookGetKeyState( int nVirtKey)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetKeyState>,func_params=<nVirtKey|"<<nVirtKey<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetKeyState(nVirtKey);
}
DWORD WINAPI HookGetTempPath(  DWORD nBufferLength, LPWSTR lpBuffer )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetTempPath>,func_params=<nBufferLength|"<<nBufferLength<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetTempPath(nBufferLength,lpBuffer);
}
UINT WINAPI HookGetWindowsDirectoryA(  LPSTR lpBuffer,   UINT uSize)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
	//GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryA>,func_params=<lpBuffer|"<<(lpBuffer==NULL?"NULL":lpBuffer)<<",uSize|"<<uSize<<">";
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryA>,func_params=<uSize|"<<uSize<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetWindowsDirectoryA(lpBuffer,uSize);
}
HFILE WINAPI HookOpenFile(  LPCSTR lpFileName,  LPOFSTRUCT lpReOpenBuff,  UINT uStyle )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenFile>,func_params=<lpFileName|"<<(lpFileName==NULL?"NULL":lpFileName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenFile(lpFileName,lpReOpenBuff,uStyle);
}
HANDLE WINAPI HookOpenMutexA(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  LPCSTR lpName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenMutexA>,func_params=<lpName|"<<(lpName==NULL?"NULL":lpName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenMutexA(dwDesiredAccess,bInheritHandle,lpName);
}
LPVOID WINAPI HookMapViewOfFile(  HANDLE hFileMappingObject,  DWORD dwDesiredAccess,  DWORD dwFileOffsetHigh,  DWORD dwFileOffsetLow,  SIZE_T dwNumberOfBytesToMap )
{
	//WaitForSingleObject(hMutex,INFINITE);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapViewOfFile>,func_params=<dwNumberOfBytesToMap|"<<dwNumberOfBytesToMap<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMapViewOfFile(hFileMappingObject,dwDesiredAccess,dwFileOffsetHigh,dwFileOffsetLow,dwNumberOfBytesToMap);
}
UINT WINAPI HookMapVirtualKeyA( UINT uCode,  UINT uMapType)
{
	//WaitForSingleObject(hMutex,INFINITE);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapVirtualKeyA>,func_params=<uCode|"<<uCode<<",uMapType|"<<uMapType<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMapVirtualKeyA(uCode,uMapType);

}
SC_HANDLE WINAPI HookOpenSCManagerA(  LPCSTR lpMachineName,  LPCSTR lpDatabaseName,  DWORD dwDesiredAccess )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenSCManagerA>,func_params=<lpMachineName|"<<(lpMachineName==NULL?"NULL":lpMachineName)<<\
		",lpDatabaseName|"<<(lpDatabaseName==NULL?"NULL":lpDatabaseName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenSCManagerA(lpMachineName,lpDatabaseName,dwDesiredAccess);
}
BOOL WINAPI HookSetFileTime(  HANDLE hFile,  CONST FILETIME * lpCreationTime,  CONST FILETIME * lpLastAccessTime,  CONST FILETIME * lpLastWriteTime )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFileTime>,func_params=<lpCreationTime|"<<lpCreationTime<<",lpLastAccessTime|"<<lpLastAccessTime<<\
		",lpLastWriteTime|"<<lpLastWriteTime<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetFileTime(hFile,lpCreationTime,lpLastAccessTime,lpLastWriteTime);
}

/*
进程相关API
*/

BOOL WINAPI HookAdjustTokenPrivileges(  HANDLE TokenHandle,  BOOL DisableAllPrivileges,  PTOKEN_PRIVILEGES NewState,  DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState,  PDWORD ReturnLength )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<AdjustTokenPrivileges>,func_params=<DisableAllPrivileges|"<<DisableAllPrivileges<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealAdjustTokenPrivileges(TokenHandle,DisableAllPrivileges,NewState,BufferLength,PreviousState,ReturnLength);
}
BOOL WINAPI HookAttachThreadInput( DWORD idAttach,  DWORD idAttachTo,  BOOL fAttach)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<AttachThreadInput>,func_params=<idAttach|"<<idAttach<<",idAttachTo|"<<idAttachTo<<",fAttach|"<<fAttach<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealAttachThreadInput(idAttach,idAttachTo,fAttach);
}
LRESULT WINAPI HookCallNextHookEx( HHOOK hhk,  int nCode,  WPARAM wParam,  LPARAM lParam)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CallNextHookEx>,func_params=<nCode|"<<nCode<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCallNextHookEx(hhk,nCode,wParam,lParam);
}
BOOL WINAPI HookCheckRemoteDebuggerPresent(  HANDLE hProcess,  PBOOL pbDebuggerPresent )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CheckRemoteDebuggerPresent>,func_params=<pbDebuggerPresent|"<<pbDebuggerPresent<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCheckRemoteDebuggerPresent(hProcess,pbDebuggerPresent);
}
BOOL WINAPI HookControlService(  SC_HANDLE hService,  DWORD dwControl,  LPSERVICE_STATUS lpServiceStatus )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ControlService>,func_params=<dwControl|"<<dwControl<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealControlService(hService,dwControl,lpServiceStatus);
}
BOOL WINAPI HookCreateProcessA(  LPCSTR lpApplicationName, LPSTR lpCommandLine,  LPSECURITY_ATTRIBUTES lpProcessAttributes,  LPSECURITY_ATTRIBUTES lpThreadAttributes, \
							   BOOL bInheritHandles,  DWORD dwCreationFlags,  LPVOID lpEnvironment,  LPCSTR lpCurrentDirectory,  LPSTARTUPINFOA lpStartupInfo,  LPPROCESS_INFORMATION lpProcessInformation )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateProcessA>,func_params=<lpApplicationName|"<<lpApplicationName<<",lpCommandLine|"<<lpCommandLine<<\
		",lpCurrentDirectory|"<<lpCurrentDirectory<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}
HANDLE WINAPI HookCreateRemoteThread(  HANDLE hProcess,  LPSECURITY_ATTRIBUTES lpThreadAttributes,  SIZE_T dwStackSize,  LPTHREAD_START_ROUTINE lpStartAddress, \
									 LPVOID lpParameter,  DWORD dwCreationFlags,  LPDWORD lpThreadId )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateRemoteThread>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateRemoteThread(hProcess,lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,lpThreadId);
}
SC_HANDLE WINAPI HookCreateServiceA(  SC_HANDLE hSCManager,  LPCSTR lpServiceName,  LPCSTR lpDisplayName,  DWORD dwDesiredAccess,  DWORD dwServiceType,  DWORD dwStartType,\
									DWORD dwErrorControl,  LPCSTR lpBinaryPathName,  LPCSTR lpLoadOrderGroup,  LPDWORD lpdwTagId,  LPCSTR lpDependencies,  LPCSTR lpServiceStartName,  LPCSTR lpPassword )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateServiceA>,func_params=<lpServiceName|"<<lpServiceName<<",lpDisplayName|"<<lpDisplayName<<\
		",lpBinaryPathName|"<<lpBinaryPathName<<",lpLoadOrderGroup|"<<lpLoadOrderGroup<<",lpServiceStartName|"<<lpServiceStartName<<",lpPassword|"<<lpPassword<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateServiceA(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
}
HANDLE WINAPI HookCreateToolhelp32Snapshot( DWORD dwFlags, DWORD th32ProcessID )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateToolhelp32Snapshot>,func_params=<dwFlags|"<<dwFlags<<",th32ProcessID|"<<th32ProcessID<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateToolhelp32Snapshot(dwFlags,th32ProcessID);
}
BOOL WINAPI HookEnumProcesses( DWORD * lpidProcess,  DWORD cb,  LPDWORD lpcbNeeded )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">proc_func_name=<EnumProcesses>,func_params=<cb|"<<cb<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealEnumProcesses(lpidProcess,cb,lpcbNeeded);
}
BOOL WINAPI HookEnumProcessModules(  HANDLE hProcess, HMODULE *lphModule,  DWORD cb,  LPDWORD lpcbNeeded )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<EnumProcessModules>,func_params=<cb|"<<cb<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealEnumProcessModules(hProcess,lphModule,cb,lpcbNeeded);
}
DWORD WINAPI HookGetModuleFileNameExA(  HANDLE hProcess,  HMODULE hModule, LPSTR lpFilename,  DWORD nSize )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleFileNameExA>,func_params=<lpFilename|"<<(lpFilename==NULL?"NULL":lpFilename)<<">";
	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
	//GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath();/*<<">,proc_func_name=<GetModuleFileNameExA>";
	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	
	return RealGetModuleFileNameExA(hProcess,hModule,lpFilename,nSize);
}
HMODULE WINAPI HookGetModuleHandleA(  LPCSTR lpModuleName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleHandleA>,func_params=<lpModuleName|"<<(lpModuleName==NULL?"NULL":lpModuleName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetModuleHandleA(lpModuleName);
}
FARPROC WINAPI HookGetProcAddress(  HMODULE hModule,  LPCSTR lpProcName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	//f<<LogTime()<<" pathname=<"<<GetProcessPath()<<">, pid=<"<<_getpid()<<">, function=<GetProcAddress(lpProcName="<<lpProcName<<")>"<<endl;
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetProcAddress>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetProcAddress(hModule,lpProcName);
}
VOID WINAPI HookGetStartupInfoA(  LPSTARTUPINFOA lpStartupInfo )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetStartupInfoA>,func_params=<lpStartupInfo|"<<lpStartupInfo<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetStartupInfoA(lpStartupInfo);
}
LANGID WINAPI HookGetSystemDefaultLangID()
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetSystemDefaultLangID>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetSystemDefaultLangID();
}
BOOL WINAPI HookGetThreadContext(  HANDLE hThread,  LPCONTEXT lpContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetThreadContext>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetThreadContext(hThread,lpContext);
}
DWORD WINAPI HookGetTickCount(VOID)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetTickCount>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetTickCount();
}
BOOL WINAPI HookGetVersionExA(  LPOSVERSIONINFOA lpVersionInformation )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetVersionExA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetVersionExA(lpVersionInformation);
}
BOOL WINAPI HookIsDebuggerPresent()
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<IsDebuggerPresent>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealIsDebuggerPresent();
}
HMODULE WINAPI HookLoadLibraryA(  LPCSTR lpLibFileName )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadLibraryA>,func_params=<lpLibFileName|"<<lpLibFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealLoadLibraryA(lpLibFileName);
}
HGLOBAL WINAPI HookLoadResource(  HMODULE hModule,  HRSRC hResInfo )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadResource>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealLoadResource(hModule,hResInfo);
}
BOOL WINAPI HookModule32FirstW( HANDLE hSnapshot, LPMODULEENTRY32W lpme )
{
	//WaitForSingleObject(hMutex,INFINITE);
	//::MessageBoxW(NULL,_T("Module32FirstW Hooked"),_T("APIHook"),0);//张宇南测试所加
	cout<<"Module32FirstW hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">, pid=<"<<_getpid()<<">,proc_func_name=<Module32FirstW>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32FirstW)RealModule32FirstW)(hSnapshot,lpme);//((MyModule32FirstW)RealModule32FirstW)
}
BOOL WINAPI HookModule32NextW( HANDLE hSnapshot, LPMODULEENTRY32W lpme )
{
	//WaitForSingleObject(hMutex,INFINITE);
	//::MessageBoxW(NULL,_T("Module32NextW Hooked"),_T("APIHook"),0);//张宇南测试所加
	cout<<"Module32NextW hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32NextW>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32NextW)RealModule32NextW)(hSnapshot,lpme);
}
HANDLE WINAPI HookOpenProcess(  DWORD dwDesiredAccess,  BOOL bInheritHandle,  DWORD dwProcessId )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenProcess>,func_params=<dwDesiredAccess|"<<dwDesiredAccess<<",bInheritHandle|"<<bInheritHandle<<\
		",dwProcessId|"<<dwProcessId<<">";//这个函数内如果调用GetProcessPath会崩溃

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId);
}
VOID WINAPI HookOutputDebugStringA(  LPCSTR lpOutputString )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	//logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
	//GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringA>,func_params=<lpOutputString|"<<lpOutputString<<">";
	//lpOutputString可能出现\n会影响日志格式所以不输出这个参数
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOutputDebugStringA(lpOutputString);
}
BOOL WINAPI HookPeekNamedPipe(  HANDLE hNamedPipe, LPVOID lpBuffer,  DWORD nBufferSize,  LPDWORD lpBytesRead,  LPDWORD lpTotalBytesAvail,  LPDWORD lpBytesLeftThisMessage )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<PeekNamedPipe>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealPeekNamedPipe(hNamedPipe,lpBuffer,nBufferSize,lpBytesRead,lpTotalBytesAvail,lpBytesLeftThisMessage);
}
BOOL WINAPI HookProcess32First( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32First>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealProcess32First(hSnapshot,lppe);
}
BOOL WINAPI HookProcess32Next( HANDLE hSnapshot, LPPROCESSENTRY32 lppe )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Process32Next>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealProcess32Next(hSnapshot,lppe);
}
BOOL WINAPI HookQueryPerformanceCounter(  LARGE_INTEGER * lpPerformanceCount )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<QueryPerformanceCounter>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealQueryPerformanceCounter(lpPerformanceCount);
}
DWORD WINAPI HookQueueUserAPC(  PAPCFUNC pfnAPC,  HANDLE hThread,  ULONG_PTR dwData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<QueueUserAPC>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealQueueUserAPC(pfnAPC,hThread,dwData);
}
BOOL WINAPI HookReadProcessMemory( HANDLE hProcess,  LPCVOID lpBaseAddress, LPVOID lpBuffer,  SIZE_T nSize,  SIZE_T * lpNumberOfBytesRead )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ReadProcessMemory>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealReadProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesRead);
}
DWORD WINAPI HookResumeThread(  HANDLE hThread )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ResumeThread>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealResumeThread(hThread);
}
BOOL WINAPI HookSetThreadContext(  HANDLE hThread,  CONST CONTEXT * lpContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetThreadContext>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetThreadContext(hThread,lpContext);
}
HHOOK WINAPI HookSetWindowsHookExA( int idHook,  HOOKPROC lpfn,  HINSTANCE hmod,  DWORD dwThreadId)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetWindowsHookExA>,func_params=<idHook|"<<idHook<<",dwThreadId|"<<dwThreadId<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetWindowsHookExA(idHook,lpfn,hmod,dwThreadId);
}
HINSTANCE WINAPI HookShellExecuteA( HWND hwnd,  LPCSTR lpOperation,  LPCSTR lpFile,  LPCSTR lpParameters,  LPCSTR lpDirectory,  INT nShowCmd)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ShellExecuteA>,func_params=<lpOperation|"<<lpOperation<<",lpFile|"<<lpFile<<",lpParameters|"<<\
		lpParameters<<",lpDirectory|"<<lpDirectory<<",nShowCmd|"<<nShowCmd<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealShellExecuteA(hwnd,lpOperation,lpFile,lpParameters,lpDirectory,nShowCmd);
}
BOOL WINAPI HookStartServiceCtrlDispatcherA(  CONST SERVICE_TABLE_ENTRYA *lpServiceStartTable )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<StartServiceCtrlDispatcherA>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealStartServiceCtrlDispatcherA(lpServiceStartTable);
}
DWORD WINAPI HookSuspendThread(  HANDLE hThread )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SuspendThread>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSuspendThread(hThread);
}
int Hooksystem(const char * _Command)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<system>,func_params=<_Command|"<<_Command<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return Realsystem(_Command);
}
BOOL WINAPI HookThread32First( HANDLE hSnapshot, LPTHREADENTRY32 lpte )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Thread32First>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealThread32First(hSnapshot,lpte);
}
BOOL WINAPI HookThread32Next( HANDLE hSnapshot, LPTHREADENTRY32 lpte )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Thread32Next>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealThread32Next(hSnapshot,lpte);
}
BOOL WINAPI HookToolhelp32ReadProcessMemory( DWORD th32ProcessID, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T cbRead, SIZE_T *lpNumberOfBytesRead )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Toolhelp32ReadProcessMemory>,func_params=<th32ProcessID|"<<th32ProcessID<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealToolhelp32ReadProcessMemory(th32ProcessID,lpBaseAddress,lpBuffer,cbRead,lpNumberOfBytesRead);
}
LPVOID WINAPI HookVirtualAllocEx( HANDLE hProcess,  LPVOID lpAddress,  SIZE_T dwSize,  DWORD flAllocationType,  DWORD flProtect )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualAllocEx>,func_params=<flAllocationType|"<<flAllocationType<<",flProtect|"<<flProtect<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealVirtualAllocEx(hProcess,lpAddress,dwSize,flAllocationType,flProtect);
}
BOOL WINAPI HookVirtualProtectEx(  HANDLE hProcess ,  LPVOID lpAddress,  SIZE_T dwSize,  DWORD flNewProtect,  PDWORD lpflOldProtect )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualProtectEx>,func_params=<flNewProtect|"<<flNewProtect<<",lpflOldProtect|"<<lpflOldProtect<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealVirtualProtectEx(hProcess,lpAddress,dwSize,flNewProtect,lpflOldProtect);
}
UINT WINAPI HookWinExec(  LPCSTR lpCmdLine,  UINT uCmdShow )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WinExec>,func_params=<lpCmdLine|"<<lpCmdLine<<",uCmdShow|"<<uCmdShow<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealWinExec(lpCmdLine,uCmdShow);
}
BOOL WINAPI HookWriteProcessMemory( HANDLE hProcess,  LPVOID lpBaseAddress, LPCVOID lpBuffer,  SIZE_T nSize,  SIZE_T * lpNumberOfBytesWritten )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteProcessMemory>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealWriteProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
}
BOOL WINAPI HookRegisterHotKey( HWND hWnd,  int id,  UINT fsModifiers,  UINT vk)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegisterHotKey>,func_params=<id|"<<id<<",fsModifiers|"<<fsModifiers<<",vk|"<<vk<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegisterHotKey(hWnd,id,fsModifiers,vk);
}
BOOL WINAPI HookCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,\
							   BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
	DWORD dwLastError = GetLastError();
	BOOL  bResult = FALSE;
	CHAR  szDetouredDll[MAX_PATH];
	CHAR  szDllName[MAX_PATH];
	HMODULE hMod1 = NULL, hMod2 = NULL;

	// get the full path to the detours DLL
	hMod1 = GetModuleHandleA("detoured.dll");
	GetModuleFileNameA(hMod1, szDetouredDll, MAX_PATH);

	// get the full path to the hooking DLL
	GetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
		(LPCTSTR)&HookCreateProcessW,
		&hMod2);

	GetModuleFileNameA(hMod2, szDllName, MAX_PATH);

	OutputDebugStringA(szDllName);
	OutputDebugStringA(szDetouredDll);
	OutputDebugStringA("\n");

	//wprintf(L"[DetoursHooks] Intercepting the creation of %s\n", lpCommandLine);

	// route creation of new process through 
	// the detours API 
	bResult = DetourCreateProcessWithDllW(
		lpApplicationName,
		lpCommandLine, 
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment, 
		lpCurrentDirectory,
		lpStartupInfo, 
		lpProcessInformation, 
		//szDetouredDll, 
		szDllName, 
		(PDETOUR_CREATE_PROCESS_ROUTINEW)RealCreateProcessW);

	SetLastError(dwLastError);
	return bResult;
}
//这个函数到底调试了没有？ 张宇南 2015/10/17.

/*
注册表相关
*/
LONG WINAPI HookRegOpenKeyA(  HKEY hKey,  LPCSTR lpSubKey,  PHKEY phkResult )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyA>,func_params=<lpSubKey|"<<lpSubKey<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyA(hKey,lpSubKey,phkResult);
}
LONG WINAPI HookRegOpenKeyEx(HKEY hKey,LPCWSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)
{
	//WaitForSingleObject(hMutex,INFINITE);
/*	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
	GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyEx>,func_params=<lpSubKey|"<<lpSubKey<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);*/
	return RealRegOpenKeyEx(hKey,lpSubKey,ulOptions,samDesired,phkResult);
}

/*
网络相关
*/
int WSAAPI Hookconnect(  SOCKET s, const struct sockaddr FAR * name,  int namelen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in* sock;
	int socklen=sizeof(sock);
	sock=(struct sockaddr_in *)name;
	char *sock_ip=inet_ntoa((*sock).sin_addr);
>>>>>>> .r53
	/*
	FreeLibrary(hKernel32);
	FreeLibrary(hUser32);
	FreeLibrary(hGdi32);
	FreeLibrary(hOle32);
	FreeLibrary(hAdvapi32);
	FreeLibrary(hCrypt32);
	FreeLibrary(hWininet);
	FreeLibrary(hNetapi32);
	FreeLibrary(hWs2_32);
	FreeLibrary(hIphlpapi);
	FreeLibrary(hShell32);
	FreeLibrary(hUrlmon);
	*/
<<<<<<< .mine
	return 0;  
||||||| .r39
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<connect>,func_params=<ip|"<<sock_ip<<",name|"<<name<<",namelen|"<<namelen<<">";

	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myconnect)Realconnect)(s,name,namelen);
=======
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<connect>,func_params=<ip|"<<sock_ip<<",name|"<<name<<",namelen|"<<namelen<<">";

	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myconnect)Realconnect)(s,name,namelen);
>>>>>>> .r53
}
<<<<<<< .mine
||||||| .r39
int WSAAPI Hookbind(  SOCKET s, const struct sockaddr FAR * name,  int namelen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in* sock;
	int socklen=sizeof(sock);
	sock=(struct sockaddr_in *)name;
	char *sock_ip=inet_ntoa((*sock).sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<bind>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",name|"<<name<<",namelen|"<<namelen<<">";
=======
int WSAAPI Hookbind(  SOCKET s, const struct sockaddr FAR * name,  int namelen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in* sock;
	int socklen=sizeof(sock);
	sock=(struct sockaddr_in *)name;
	char *sock_ip=inet_ntoa((*sock).sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<bind>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",name|"<<name<<",namelen|"<<namelen<<">";
>>>>>>> .r53

<<<<<<< .mine
int api[200];
||||||| .r39
	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return((Mybind)Realbind)(s,name,namelen);
}
SOCKET WSAAPI Hookaccept(  SOCKET s, struct sockaddr FAR * addr, int FAR * addrlen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	char *sock_ip=inet_ntoa(sock.sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<accept>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",addr|"<<addr<<">";
=======
	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return((Mybind)Realbind)(s,name,namelen);
}
SOCKET WSAAPI Hookaccept(  SOCKET s, struct sockaddr FAR * addr, int FAR * addrlen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	char *sock_ip=inet_ntoa(sock.sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<accept>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",addr|"<<addr<<">";
>>>>>>> .r53

<<<<<<< .mine
void DoHook()  
{  
	OutputDebugString(L"DoHook()\n"); 
||||||| .r39
	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myaccept)Realaccept)(s,addr,addrlen);
}
int WINAPI Hooksend(SOCKET s,const char *buf,int len,int flags)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	char *sock_ip=inet_ntoa(sock.sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<send>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",len|"<<len<<",flags|"<<flags<<">";

	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MySend)Realsend)(s,buf,len,flags);
}
BOOL WINAPI HookConnectNamedPipe(  HANDLE hNamedPipe,LPOVERLAPPED lpOverlapped )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ConnectNamedPipe>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealConnectNamedPipe(hNamedPipe,lpOverlapped);
}
ULONG WINAPI HookGetAdaptersInfo( PIP_ADAPTER_INFO AdapterInfo,  PULONG SizePointer )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetAdaptersInfo>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyGetAdaptersInfo)RealGetAdaptersInfo)(AdapterInfo,SizePointer);
}
struct hostent* FAR WINAPI Hookgethostbyname( const char FAR * name )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<gethostbyname>,func_params=<name|"<<name<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Mygethostbyname)Realgethostbyname)(name);
}
int WSAAPI Hookgethostname( char FAR * name,  int namelen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<gethostname>,func_params=<name|"<<static_cast<const void *>(name)<<",namelen|"<<namelen<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Mygethostname)Realgethostname)(name,namelen);
}
unsigned long WSAAPI Hookinet_addr( const char FAR * cp )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<inet_addr>,func_params=<cp|"<<cp<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myinet_addr)Realinet_addr)(cp);
}

EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenA( LPCSTR lpszAgent,  DWORD dwAccessType,  LPCSTR lpszProxy,  LPCSTR lpszProxyBypass,  DWORD dwFlags )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenA>,func_params=<lpszAgent|"<<(lpszAgent==NULL?"NULL":lpszAgent)<<",dwAccessType|"<<dwAccessType<<",lpszProxy|"<<(lpszProxy==NULL?"NULL":lpszProxy)<<",lpszProxyBypass|"<<(lpszProxyBypass==NULL?"NULL":lpszProxyBypass)<<",dwFlags|"<<dwFlags<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);

	return ((MyInternetOpenA)RealInternetOpenA)(lpszAgent,dwAccessType,lpszProxy,lpszProxyBypass,dwFlags);
}

//by zhangyunan this func
EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenW( LPCWSTR lpszAgent,  DWORD dwAccessType,  LPCWSTR lpszProxy,  LPCWSTR lpszProxyBypass,  DWORD dwFlags )
{
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenW>,func_params=<lpszAgent|"<<(lpszAgent==NULL?L"NULL":lpszAgent)<<",dwAccessType|"<<dwAccessType<<",lpszProxy|"<<(lpszProxy==NULL?L"NULL":lpszProxy)<<",lpszProxyBypass|"<<(lpszProxyBypass==NULL?L"NULL":lpszProxyBypass)<<",dwFlags|"<<dwFlags<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);

	return ((MyInternetOpenW)RealInternetOpenW)(lpszAgent,dwAccessType,lpszProxy,lpszProxyBypass,dwFlags);
}

EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenUrlA(  HINTERNET hInternet,  LPCSTR lpszUrl, LPCSTR lpszHeaders,  DWORD dwHeadersLength,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenUrlA>,func_params=<lpszUrl|"<<(lpszUrl==NULL?"NULL":lpszUrl)<<",lpszHeaders|"<<(lpszHeaders==NULL?"NULL":lpszHeaders)<<",dwHeadersLength|"<<dwHeadersLength<<",dwFlags|"<<dwFlags<<",dwContext|"<<dwContext<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetOpenUrlA)RealInternetOpenUrlA)(hInternet,lpszUrl,lpszHeaders,dwHeadersLength,dwFlags,dwContext);
}
//by zhangyunan this func
EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenUrlW(  HINTERNET hInternet,  LPCWSTR lpszUrl, LPCWSTR lpszHeaders,  DWORD dwHeadersLength,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenUrlW>,func_params=<lpszUrl|"<<(lpszUrl==NULL?L"NULL":lpszUrl)<<",lpszHeaders|"<<(lpszHeaders==NULL?L"NULL":lpszHeaders)<<",dwHeadersLength|"<<dwHeadersLength<<",dwFlags|"<<dwFlags<<",dwContext|"<<dwContext<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetOpenUrlW)RealInternetOpenUrlW)(hInternet,lpszUrl,lpszHeaders,dwHeadersLength,dwFlags,dwContext);
}
BOOL WINAPI HookInternetReadFile(  HINTERNET hFile,  LPVOID lpBuffer,  DWORD dwNumberOfBytesToRead,  LPDWORD lpdwNumberOfBytesRead )
{
	//WaitForSingleObject(hMutex,INFINITE);
	//GetFileNameFromHandle(hFile);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetReadFile>,func_params=<dwNumberOfBytesToRead|"<<dwNumberOfBytesToRead<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetReadFile)RealInternetReadFile)(hFile,lpBuffer,dwNumberOfBytesToRead,lpdwNumberOfBytesRead);
}
BOOL WINAPI HookInternetWriteFile(  HINTERNET hFile,  LPCVOID lpBuffer,  DWORD dwNumberOfBytesToWrite,  LPDWORD lpdwNumberOfBytesWritten )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetWriteFile>,func_params=<dwNumberOfBytesToWrite|"<<dwNumberOfBytesToWrite<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetWriteFile)RealInternetWriteFile)(hFile,lpBuffer,dwNumberOfBytesToWrite,lpdwNumberOfBytesWritten);
}
DWORD WINAPI HookNetShareEnum(  LMSTR servername,  DWORD level,  LPBYTE *bufptr,  DWORD prefmaxlen,  LPDWORD entriesread,  LPDWORD totalentries, LPDWORD resume_handle )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<NetShareEnum>,func_params=<servername|"<<servername<<",level|"<<level<<",prefmaxlen|"<<prefmaxlen<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyNetShareEnum)RealNetShareEnum)(servername,level,bufptr,prefmaxlen,entriesread,totalentries,resume_handle);
}
int WSAAPI Hookrecv(  SOCKET s, char FAR * buf,  int len,  int flags )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	char *sock_ip=inet_ntoa(sock.sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<recv>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",len|"<<len<<",flags|"<<flags<<">";

	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myrecv)Realrecv)(s,buf,len,flags);
}
HRESULT WINAPI HookURLDownloadToFileA(LPUNKNOWN pCaller,LPCSTR szURL,LPCSTR szFileName,DWORD dwReserved,LPBINDSTATUSCALLBACK lpfnCB)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<URLDownloadToFileA>,func_params=<szURL|"<<szURL<<",szFileName|"<<szFileName<<",dwReserved|"<<dwReserved<<">";

	string s,sm;
	sm="";
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyURLDownloadToFileA)RealURLDownloadToFileA)(pCaller,szURL,szFileName,dwReserved,lpfnCB);
}

//by zhangyunan this func
HRESULT WINAPI HookURLDownloadToFileW(LPUNKNOWN pCaller,LPCWSTR szURL,LPCWSTR szFileName,DWORD dwReserved,LPBINDSTATUSCALLBACK lpfnCB)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<URLDownloadToFileW>,func_params=<szURL|"<<szURL<<",szFileName|"<<szFileName<<",dwReserved|"<<dwReserved<<">";

	string s,sm;
	sm="";
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyURLDownloadToFileW)RealURLDownloadToFileW)(pCaller,szURL,szFileName,dwReserved,lpfnCB);
}
int WSAAPI HookWSAStartup(  WORD wVersionRequested,  LPWSADATA lpWSAData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WSAStartup>,func_params=<wVersionRequested|"<<wVersionRequested<<",lpWSAData|"<<lpWSAData<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyWSAStartup)RealWSAStartup)(wVersionRequested,lpWSAData);
}


//author zhangyunan
HANDLE WINAPI HookCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileW>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	//ofstream f(log_path,ios::app);
	//f<<sm;
	//f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFileW(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}
BOOL WINAPI HookMoveFileW(LPCWSTR lpExistingFileName,LPCWSTR lpNewFileName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileW>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMoveFileW(lpExistingFileName,lpNewFileName);
}

BOOL WINAPI HookCopyFileW(LPCWSTR lpExistingFileName,LPCWSTR lpNewFileName, BOOL bFailIfExists){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CopyFileW>,func_params=<lpExistingFileName|"<<lpExistingFileName<<",lpNewFileName|"<<lpNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCopyFileW(lpExistingFileName,lpNewFileName,bFailIfExists);
}

BOOL WINAPI HookDeleteFileW(LPCWSTR lpFileName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFileW>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeleteFileW(lpFileName);
}

//static BOOL (WINAPI *RealDeleteFileW)( LPCWSTR lpFileName) = DeleteFileW;
HANDLE WINAPI HookFindFirstFileW(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindFirstFileW>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindFirstFileW(lpFileName,lpFindFileData);
}
//static HANDLE (WINAPI *RealFindFirstFileW)( LPCWSTR,  LPWIN32_FIND_DATAW)=FindFirstFileW;
BOOL WINAPI HookFindNextFileW(HANDLE hFindFile,LPWIN32_FIND_DATA lpFindFileData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindNextFileW>"<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindNextFileW(hFindFile,lpFindFileData);
}

//static BOOL (WINAPI *RealFindNextFileW)( HANDLE hFindFile,  LPWIN32_FIND_DATAW lpFindFileData)=FindNextFileW;
HCERTSTORE WINAPI HookCertOpenSystemStoreW(HCRYPTPROV_LEGACY hProv,LPCWSTR szSubsystemProtocol){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CertOpenSystemStoreW>,func_params=<szSubsystemProtocol|"<<szSubsystemProtocol<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCertOpenSystemStoreW(hProv,szSubsystemProtocol);
}

//static HCERTSTORE (WINAPI *RealCertOpenSystemStore)( HCRYPTPROV_LEGACY hProv,  LPCWSTR szSubsystemProtocol)=CertOpenSystemStoreW;
HANDLE WINAPI HookCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateMutexW>,func_params=<lpName|"<<lpName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateMutexW(lpMutexAttributes,bInitialOwner,lpName);
}

//static HANDLE (WINAPI *RealCreateMutexW)( LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)=CreateMutexW;
HRSRC WINAPI HookFindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindResourceW>,func_params=<lpName|"<<lpName<<",lpType|"<<lpType<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindResourceW(hModule,lpName,lpType);
}

//static HRSRC (WINAPI *RealFindResourceW)( HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)=FindResourceW;
HWND WINAPI HookFindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindWindowW>,func_params=<lpClassName|"<<(lpClassName==NULL?L"NULL":lpClassName)<<",lpWindowName|"<<(lpWindowName==NULL?L"NULL":lpWindowName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyFindWindowW)RealFindWindowW)(lpClassName,lpWindowName);
}

//static HWND (WINAPI *RealFindWindowW)( LPCWSTR lpClassName, LPCWSTR lpWindowName)=FindWindowW;
UINT WINAPI HookGetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryW>,func_params=<lpBuffer|"<<lpBuffer<<",uSize|"<<uSize<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetWindowsDirectoryW(lpBuffer,uSize);
}

//static UINT (WINAPI *RealGetWindowsDirectoryW)( LPWSTR lpBuffer, UINT uSize)=GetWindowsDirectoryW;
UINT WINAPI HookMapVirtualKeyW(UINT uCode, UINT uMapType){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapVirtualKeyW>,func_params=<uCode|"<<uCode<<",uMapType|"<<uMapType<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyMapVirtualKeyW)RealMapVirtualKeyW)(uCode,uMapType);
}
//static UINT (WINAPI *RealMapVirtualKeyW)( UINT uCode, UINT uMapType)=MapVirtualKeyW;

HANDLE WINAPI HookOpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenMutexW>,func_params=<lpName|"<<(lpName==NULL?L"NULL":lpName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenMutexW(dwDesiredAccess,bInheritHandle,lpName);
}
//static HANDLE (WINAPI *RealOpenMutexW)( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)=OpenMutexW;

HANDLE WINAPI HookOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenSCManagerW>,func_params=<lpMachineName|"<<(lpMachineName==NULL?L"NULL":lpMachineName)<<",lpDatabaseName|"<<(lpDatabaseName==NULL?L"NULL":lpDatabaseName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenSCManagerW(lpMachineName,lpDatabaseName,dwDesiredAccess);
}
//static SC_HANDLE (WINAPI *RealOpenSCManagerW)( LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)=OpenSCManagerW;
//BOOL WINAPI HookCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
//	::MessageBoxW(NULL,_T("CreateProcessW Hooked"),_T("APIHook"),0);//张宇南测试所加
//	stringstream logstream;
//	logstream.clear();
//	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateProcessW>,func_params=<lpApplicationName|"<<lpApplicationName<<",lpCommandLine|"<<lpCommandLine<<",lpProcessAttributes|"<<lpProcessAttributes<<",lpThreadAttributes|"<<lpThreadAttributes<<",bInheritHandles|"<<bInheritHandles<<",dwCreationFlags|"<<dwCreationFlags<<",lpEnvironment|"<<lpEnvironment<<",lpCurrentDirectory|"<<lpCurrentDirectory<<",lpStartupInfo|"<<lpStartupInfo<<",lpProcessInformation|"<<lpProcessInformation<<">";
//
//	string s,sm;
//	sm="";
//	sm=logstream.str();
//	sm=sm+"\n\0";
//	ofstream f(log_path,ios::app);
//	f<<sm;
//	f.close();
//	sm="";
//	logstream.clear();
//	//MoveLog();
//	//ReleaseMutex(hMutex);
//	return RealCreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
//}
//static BOOL (WINAPI *RealCreateProcessW)( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)=CreateProcessW;

SC_HANDLE WINAPI HookCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateServiceW>,func_params=<hSCManager|"<<hSCManager<<",lpServiceName|"<<lpServiceName<<",lpDisplayName|"<<lpDisplayName<<",dwDesiredAccess|"<<dwDesiredAccess<<",dwServiceType|"<<dwServiceType<<",dwStartType|"<<dwStartType<<",dwErrorControl|"<<dwErrorControl<<",lpBinaryPathName|"<<lpBinaryPathName<<",lpLoadOrderGroup|"<<lpLoadOrderGroup<<",lpdwTagId|"<<lpdwTagId<<",lpDependencies|"<<lpDependencies<<",lpServiceStartName|"<<lpServiceStartName<<",lpPassword|"<<lpPassword<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateServiceW(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
}
//static SC_HANDLE (WINAPI *RealCreateServiceW)( SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword)=CreateServiceW;
DWORD WINAPI HookGetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFileName, DWORD nSize){
	cout<<"GetModuleFileNameExW hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleFileNameExW>,func_params=<lpFileName|"<<(lpFileName==NULL?L"NULL":lpFileName)<<">";//(lpValue==NULL?"NULL":lpValue)

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetModuleFileNameExW(hProcess,hModule,lpFileName,nSize);
}
//return ((MyMapVirtualKeyW)RealMapVirtualKeyW)(uCode,uMapType);
//static DWORD (WINAPI *RealGetModuleFileNameExW)( HANDLE hProcess, HMODULE hModule, LPWSTR lpFileName, DWORD nSize)=GetModuleFileNameExW;

HMODULE WINAPI HookGetModuleHandleW(LPCWSTR lpModuleName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleHandleW>,func_params=<lpModuleName|"<<(lpModuleName==NULL?L"NULL":lpModuleName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetModuleHandleW(lpModuleName);
}
//static HMODULE (WINAPI *RealGetModuleHandleW)( LPCWSTR lpModuleName)=GetModuleHandleW;

VOID WINAPI HookGetStartupInfoW(LPSTARTUPINFOW lpStartupInfo){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetStartupInfoW>,func_params=<lpStartupInfo|"<<lpStartupInfo<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetStartupInfoW(lpStartupInfo);
}
//static VOID (WINAPI *RealGetStartupInfoW)( LPSTARTUPINFOW lpStartupInfo)=GetStartupInfoW;
BOOL WINAPI HookGetVersionExW(LPOSVERSIONINFOW lpVersionInfo){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetVersionExW"<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetVersionExW(lpVersionInfo);
}
//static BOOL (WINAPI *RealGetVersionExW)( LPOSVERSIONINFOW lpVersionInfo)=GetVersionExW;

HMODULE WINAPI HookLoadLibraryW(LPCWSTR lpFileName){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadLibraryW>,func_params=<lpFileName|"<<lpFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealLoadLibraryW(lpFileName);
}
//static HMODULE (WINAPI *RealLoadLibraryW)( LPCWSTR lpFileName)=LoadLibraryW;

VOID WINAPI HookOutputDebugStringW(LPCWSTR lpOutputString){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringW>,func_params=<lpOutputString|"<<lpOutputString<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOutputDebugStringW(lpOutputString);
}
//static VOID (WINAPI *RealOutputDebugStringW)( LPCWSTR lpOutputString)=OutputDebugStringW;

HHOOK WINAPI HookSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetWindowsHookExW>,func_params=<idHook|"<<idHook<<",dwThreadId|"<<dwThreadId<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetWindowsHookExW(idHook,lpfn,hMod,dwThreadId);
}
//static HHOOK (WINAPI *RealSetWindowsHookExW)( int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)=SetWindowsHookExW;

HINSTANCE WINAPI HookShellExecuteW( HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ShellExecuteW>,func_params=<lpOperation|"<<(lpOperation==NULL?L"NULL":lpOperation)<<",lpFile|"<<lpFile<<",lpParameters|"<<(lpParameters==NULL?L"NULL":lpParameters)<<",lpDirectory|"<<(lpDirectory==NULL?L"NULL":lpDirectory)<<",nShowCmd|"<<nShowCmd<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealShellExecuteW(hwnd,lpOperation,lpFile,lpParameters,lpDirectory,nShowCmd);
}
//static HINSTANCE (WINAPI *RealShellExecuteW)( HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)=ShellExecuteW;

BOOL WINAPI HookStartServiceCtrlDispatcherW( CONST SERVICE_TABLE_ENTRYW *lpServiceTable){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<StartServiceCtrlDispatcherW>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealStartServiceCtrlDispatcherW(lpServiceTable);
}
//static BOOL (WINAPI *RealStartServiceCtrlDispatcherW)( CONST SERVICE_TABLE_ENTRYW *lpServiceTable)=StartServiceCtrlDispatcherW;

LONG WINAPI HookRegOpenKeyW( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<",phkResult|"<<phkResult<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyW(hKey,lpSubKey,phkResult);
}
//static LONG (WINAPI *RealRegOpenKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegOpenKeyW;

BOOL WINAPI HookModule32Next( HANDLE hSnapshot, LPMODULEENTRY32 lpme ){
	cout<<"Module32Next hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32Next>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32Next)RealModule32Next)(hSnapshot,lpme);
}
//static BOOL (WINAPI *RealModule32Next)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32Next;
BOOL WINAPI HookModule32First( HANDLE hSnapshot, LPMODULEENTRY32 lpme ){
	cout<<"Module32First hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32First>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32First)RealModule32First)(hSnapshot,lpme);
}
//static BOOL (WINAPI *RealModule32First)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32First;

LONG WINAPI HookRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateKeyExA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?"NULL":lpSubKey)<<",lpClass|"<<(lpClass==NULL?"NULL":lpClass)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegCreateKeyExA(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,phkResult,lpdwDisposition);
}
//static LONG (WINAPI *RealRegCreateKeyExA)( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExA;
LONG WINAPI HookRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyExW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<",lpClass|"<<(lpClass==NULL?L"NULL":lpClass)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegCreateKeyExW(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,phkResult,lpdwDisposition);
}
//static LONG (WINAPI *RealRegCreateKeyExA)( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExW;

LONG WINAPI HookRegCreateKeyA(  HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?"NULL":lpSubKey)<<",phkResult|"<<phkResult<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyA(hKey,lpSubKey,phkResult);
}
//static LONG (WINAPI *RealRegCreateKeyA)( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)=RegCreateKeyA;
LONG WINAPI HookRegCreateKeyW(  HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<",phkResult|"<<phkResult<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyW(hKey,lpSubKey,phkResult);
}
//static LONG (WINAPI *RealRegCreateKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegCreateKeyW;

LONG WINAPI HookRegQueryValueExA(  HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueExA>,func_params=<hKey|"<<hKey<<",lpValueName|"<<(lpValueName==NULL?"NULL":lpValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueExA(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
}
//static LONG (WINAPI *RealRegQueryValueExA)( HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExA;
LONG WINAPI HookRegQueryValueExW(  HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueExW>,func_params=<hKey|"<<hKey<<",lpValueName|"<<(lpValueName==NULL?L"NULL":lpValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueExW(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
}
//static LONG (WINAPI *RealRegQueryValueExW)( HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExW;

LONG WINAPI HookRegQueryValueA( HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?"NULL":lpSubKey)<<",lpValue|"<<(lpValue==NULL?"NULL":lpValue)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueA( hKey, lpSubKey, lpValue, lpcbValue);
}
//static LONG (WINAPI *RealRegQueryValueA)( HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue)=RegQueryValueA;
LONG WINAPI HookRegQueryValueW( HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<",lpValue|"<<(lpValue==NULL?L"NULL":lpValue)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueW( hKey, lpSubKey, lpValue, lpcbValue);
}
//static LONG (WINAPI *RealRegQueryValueW)( HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue)=RegQueryValueW;

LONG WINAPI HookRegSetValueExA(  HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueExA>,func_params=<hKey|"<<hKey<<",lpValueName|"<<(lpValueName==NULL?"NULL":lpValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueExA(hKey,lpValueName,Reserved,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueExA)( HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExA;
LONG WINAPI HookRegSetValueExW(  HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueExW>,func_params=<hKey|"<<hKey<<",lpValueName|"<<(lpValueName==NULL?L"NULL":lpValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueExW(hKey,lpValueName,Reserved,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueExW)( HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExW;

LONG WINAPI HookRegSetValueA( HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueA(hKey,lpSubKey,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueA)( HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)=RegSetValueA;
LONG WINAPI HookRegSetValueW( HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueW(hKey,lpSubKey,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueW)( HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)=RegSetValueW;

LONG WINAPI HookRegDeleteKeyExA(  HKEY hKey, LPCSTR lpSubKey,REGSAM samDesired, DWORD Reserved){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyExA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyExA(hKey,lpSubKey,samDesired,Reserved);
}
//static LONG (WINAPI *RealRegDeleteKeyExA)( HKEY hKey, LPCSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExA;
LONG WINAPI HookRegDeleteKeyExW(  HKEY hKey, LPCWSTR lpSubKey,REGSAM samDesired, DWORD Reserved){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyExW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyExW(hKey,lpSubKey,samDesired,Reserved);
}
//static LONG (WINAPI *RealRegDeleteKeyExW)( HKEY hKey, LPCWSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExW;

LONG WINAPI HookRegDeleteKeyA(  HKEY hKey, LPCSTR lpSubKey){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyA(hKey,lpSubKey);
}
//static LONG (WINAPI *RealRegDeleteKeyA)( HKEY hKey, LPCSTR lpSubKey)=RegDeleteKeyA;
LONG WINAPI HookRegDeleteKeyW(  HKEY hKey, LPCWSTR lpSubKey){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyW>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<(lpSubKey==NULL?L"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyW(hKey,lpSubKey);
}
//static LONG (WINAPI *RealRegDeleteKeyW)( HKEY hKey, LPCWSTR lpSubKey)=RegDeleteKeyW;


extern "C" __declspec(dllexport) void DummyFunc(void)
{
	return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  dwReason,
                       LPVOID lpReserved
					 )
{
	//Realsend=DetourFindFunction("Ws2_32.dll","send");
	// install the hook(s)
	/*
	hMutex=OpenMutexA(MUTEX_ALL_ACCESS, false, "mutex");
	if (hMutex==NULL)
	{
		hMutex=CreateMutexA(NULL,FALSE,"mutex");
		ftest<<"create"<<endl;
	}else{
		ftest<<"open"<<endl;
	}
	*/
	/*
	if(s.compare("D:\\Program Files (x86)\\Tencent\\QQ\\bin\\QQ.exe")==0){
		ftest<<"create"<<endl;
		hMutex=CreateMutexA(NULL,TRUE,"mutex");
	}else{
		hMutex=OpenMutexA(MUTEX_ALL_ACCESS, false, "mutex");
		ftest<<"open"<<endl;
	}
	*/
	
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//ofstream f(log_path,ios::app);
		//f.close();
		DWORD dwSize = 256;
		int len=200;
		GetUserNameA(strBuffer,&dwSize);//获取用户名
		WSAData wsaData;
		WSAStartup(MAKEWORD(1,1), &wsaData); 
		gethostname(hostname,128);//获取主机名
		GetProcessName(ProcessName,&len);//获取进程名
		cout<<ProcessName<<endl;
		cout<<hostname<<endl;
		cout<<strBuffer<<endl;
		//ofstream ftest("C:\\Log\\test.txt",ios::app);
	    
		char windire[100] ={0};  
		GetSystemDirectoryA(windire, 100 );
		SHGetSpecialFolderPathA(NULL,windire,CSIDL_PROGRAM_FILES,FALSE);
		//wprintf(L"%s",windire);
		char configpath[1000]={0};
		sprintf_s(configpath,"%s\\UserMonitor\\bin\\config.xml",windire);
		//sprintf_s(log_path,"%s\\UserMonitor\\bin\\Log.txt",windire);
		//printf(L"%s",configpath);
		
=======
	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myaccept)Realaccept)(s,addr,addrlen);
}
int WINAPI Hooksend(SOCKET s,const char *buf,int len,int flags)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	char *sock_ip=inet_ntoa(sock.sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<send>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",len|"<<len<<",flags|"<<flags<<">";

	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MySend)Realsend)(s,buf,len,flags);
}
BOOL WINAPI HookConnectNamedPipe(  HANDLE hNamedPipe,LPOVERLAPPED lpOverlapped )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ConnectNamedPipe>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealConnectNamedPipe(hNamedPipe,lpOverlapped);
}
ULONG WINAPI HookGetAdaptersInfo( PIP_ADAPTER_INFO AdapterInfo,  PULONG SizePointer )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetAdaptersInfo>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyGetAdaptersInfo)RealGetAdaptersInfo)(AdapterInfo,SizePointer);
}
struct hostent* FAR WINAPI Hookgethostbyname( const char FAR * name )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<gethostbyname>,func_params=<name|"<<name<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Mygethostbyname)Realgethostbyname)(name);
}
int WSAAPI Hookgethostname( char FAR * name,  int namelen )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<gethostname>,func_params=<name|"<<static_cast<const void *>(name)<<",namelen|"<<namelen<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Mygethostname)Realgethostname)(name,namelen);
}
unsigned long WSAAPI Hookinet_addr( const char FAR * cp )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<inet_addr>,func_params=<cp|"<<cp<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myinet_addr)Realinet_addr)(cp);
}

EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenA( LPCSTR lpszAgent,  DWORD dwAccessType,  LPCSTR lpszProxy,  LPCSTR lpszProxyBypass,  DWORD dwFlags )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenA>,func_params=<lpszAgent|"<<(lpszAgent==NULL?"NULL":lpszAgent)<<",dwAccessType|"<<\
		dwAccessType<<",lpszProxy|"<<(lpszProxy==NULL?"NULL":lpszProxy)<<",lpszProxyBypass|"<<(lpszProxyBypass==NULL?"NULL":lpszProxyBypass)<<",dwFlags|"<<dwFlags<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);

	return ((MyInternetOpenA)RealInternetOpenA)(lpszAgent,dwAccessType,lpszProxy,lpszProxyBypass,dwFlags);
}

//by zhangyunan this func
EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenW( LPCWSTR lpszAgent,  DWORD dwAccessType,  LPCWSTR lpszProxy,  LPCWSTR lpszProxyBypass,  DWORD dwFlags )
{
	char pMultiByteAgent[512];
	WideCharToMultiByte(CP_ACP,0,lpszAgent,-1,pMultiByteAgent,(int)strlen(pMultiByteAgent),NULL,NULL);
	char pMultiByteProxy[512];
	WideCharToMultiByte(CP_ACP,0,lpszProxy,-1,pMultiByteProxy,(int)strlen(pMultiByteProxy),NULL,NULL);
	char pMultiByteProxyBypass[512];
	WideCharToMultiByte(CP_ACP,0,lpszProxyBypass,-1,pMultiByteProxyBypass,(int)strlen(pMultiByteProxyBypass),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenW>,func_params=<lpszAgent|"<<(lpszAgent==NULL?"NULL":pMultiByteAgent)<<\
		",dwAccessType|"<<dwAccessType<<",lpszProxy|"<<(lpszProxy==NULL?"NULL":pMultiByteProxy)<<",lpszProxyBypass|"<<(lpszProxyBypass==NULL?"NULL":pMultiByteProxyBypass)<<",dwFlags|"<<dwFlags<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);

	return ((MyInternetOpenW)RealInternetOpenW)(lpszAgent,dwAccessType,lpszProxy,lpszProxyBypass,dwFlags);
}

EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenUrlA(  HINTERNET hInternet,  LPCSTR lpszUrl, LPCSTR lpszHeaders,  DWORD dwHeadersLength,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenUrlA>,func_params=<lpszUrl|"<<(lpszUrl==NULL?"NULL":lpszUrl)<<",lpszHeaders|"<<\
		(lpszHeaders==NULL?"NULL":lpszHeaders)<<",dwHeadersLength|"<<dwHeadersLength<<",dwFlags|"<<dwFlags<<",dwContext|"<<dwContext<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetOpenUrlA)RealInternetOpenUrlA)(hInternet,lpszUrl,lpszHeaders,dwHeadersLength,dwFlags,dwContext);
}
//by zhangyunan this func
EXTERN_C HINTERNET STDAPICALLTYPE HookInternetOpenUrlW(  HINTERNET hInternet,  LPCWSTR lpszUrl, LPCWSTR lpszHeaders,  DWORD dwHeadersLength,  DWORD dwFlags,  DWORD_PTR dwContext )
{
	//WaitForSingleObject(hMutex,INFINITE);
	char pMultiByteUrl[512];
	WideCharToMultiByte(CP_ACP,0,lpszUrl,-1,pMultiByteUrl,(int)strlen(pMultiByteUrl),NULL,NULL);
	char pMultiByteHeaders[512];
	WideCharToMultiByte(CP_ACP,0,lpszHeaders,-1,pMultiByteHeaders,(int)strlen(pMultiByteHeaders),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetOpenUrlW>,func_params=<lpszUrl|"<<(lpszUrl==NULL?"NULL":pMultiByteUrl)<<",lpszHeaders|"<<\
		(lpszHeaders==NULL?"NULL":pMultiByteHeaders)<<",dwHeadersLength|"<<dwHeadersLength<<",dwFlags|"<<dwFlags<<",dwContext|"<<dwContext<<">";

	string s,sm;
	sm="";
	
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetOpenUrlW)RealInternetOpenUrlW)(hInternet,lpszUrl,lpszHeaders,dwHeadersLength,dwFlags,dwContext);
}
BOOL WINAPI HookInternetReadFile(  HINTERNET hFile,  LPVOID lpBuffer,  DWORD dwNumberOfBytesToRead,  LPDWORD lpdwNumberOfBytesRead )
{
	//WaitForSingleObject(hMutex,INFINITE);
	//GetFileNameFromHandle(hFile);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetReadFile>,func_params=<dwNumberOfBytesToRead|"<<dwNumberOfBytesToRead<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetReadFile)RealInternetReadFile)(hFile,lpBuffer,dwNumberOfBytesToRead,lpdwNumberOfBytesRead);
}
BOOL WINAPI HookInternetWriteFile(  HINTERNET hFile,  LPCVOID lpBuffer,  DWORD dwNumberOfBytesToWrite,  LPDWORD lpdwNumberOfBytesWritten )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<InternetWriteFile>,func_params=<dwNumberOfBytesToWrite|"<<dwNumberOfBytesToWrite<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyInternetWriteFile)RealInternetWriteFile)(hFile,lpBuffer,dwNumberOfBytesToWrite,lpdwNumberOfBytesWritten);
}
DWORD WINAPI HookNetShareEnum(  LMSTR servername,  DWORD level,  LPBYTE *bufptr,  DWORD prefmaxlen,  LPDWORD entriesread,  LPDWORD totalentries, LPDWORD resume_handle )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<NetShareEnum>,func_params=<servername|"<<servername<<",level|"<<level<<",prefmaxlen|"<<prefmaxlen<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyNetShareEnum)RealNetShareEnum)(servername,level,bufptr,prefmaxlen,entriesread,totalentries,resume_handle);
}
int WSAAPI Hookrecv(  SOCKET s, char FAR * buf,  int len,  int flags )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	char *sock_ip=inet_ntoa(sock.sin_addr);
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<recv>,func_params=<ip|"<<sock_ip<<",s|"<<s<<",len|"<<len<<",flags|"<<flags<<">";

	string st,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((Myrecv)Realrecv)(s,buf,len,flags);
}
HRESULT WINAPI HookURLDownloadToFileA(LPUNKNOWN pCaller,LPCSTR szURL,LPCSTR szFileName,DWORD dwReserved,LPBINDSTATUSCALLBACK lpfnCB)
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<URLDownloadToFileA>,func_params=<szURL|"<<szURL<<",szFileName|"<<szFileName<<",dwReserved|"<<dwReserved<<">";

	string s,sm;
	sm="";
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyURLDownloadToFileA)RealURLDownloadToFileA)(pCaller,szURL,szFileName,dwReserved,lpfnCB);
}

//by zhangyunan this func
HRESULT WINAPI HookURLDownloadToFileW(LPUNKNOWN pCaller,LPCWSTR szURL,LPCWSTR szFileName,DWORD dwReserved,LPBINDSTATUSCALLBACK lpfnCB)
{
	//WaitForSingleObject(hMutex,INFINITE);
	char pMultiByteURL[512];
	WideCharToMultiByte(CP_ACP,0,szURL,-1,pMultiByteURL,(int)strlen(pMultiByteURL),NULL,NULL);
	char pMultiByteFileName[512];
	WideCharToMultiByte(CP_ACP,0,szFileName,-1,pMultiByteFileName,(int)strlen(pMultiByteFileName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<URLDownloadToFileW>,func_params=<szURL|"<<pMultiByteURL<<",szFileName|"<<pMultiByteFileName<<">";

	string s,sm;
	sm="";
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyURLDownloadToFileW)RealURLDownloadToFileW)(pCaller,szURL,szFileName,dwReserved,lpfnCB);
}
int WSAAPI HookWSAStartup(  WORD wVersionRequested,  LPWSADATA lpWSAData )
{
	//WaitForSingleObject(hMutex,INFINITE);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<\
		">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WSAStartup>,func_params=<wVersionRequested|"<<\
		wVersionRequested<<",lpWSAData|"<<lpWSAData<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyWSAStartup)RealWSAStartup)(wVersionRequested,lpWSAData);
}


//author zhangyunan
HANDLE WINAPI HookCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,\
							  DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	cout<<"CreateFileW Hooked!"<<endl;
	char pMultiByteFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpFileName,-1,pMultiByteFileName,(int)strlen(pMultiByteFileName),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateFileW>,func_params=<lpFileName|"<<pMultiByteFileName<<">";

	//string s,sm;
	//sm="";
	//sm=logstream.str();
	//sm=sm+"\n\0";
	//ofstream f(log_path,ios::app);
	//f<<sm;
	//f.close();
	//sm="";
	//logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateFileW(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}
BOOL WINAPI HookMoveFileW(LPCWSTR lpExistingFileName,LPCWSTR lpNewFileName)
{
	char pMultiByteExistingFileName[512];
	char pMultiByteNewFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpExistingFileName,-1,pMultiByteExistingFileName,(int)strlen(pMultiByteExistingFileName),NULL,NULL);
	WideCharToMultiByte(CP_ACP,0,lpNewFileName,-1,pMultiByteNewFileName,(int)strlen(pMultiByteNewFileName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileW>,func_params=<lpExistingFileName|"<<pMultiByteExistingFileName<<",lpNewFileName|"<<\
		pMultiByteNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealMoveFileW(lpExistingFileName,lpNewFileName);
}

BOOL WINAPI HookCopyFileW(LPCWSTR lpExistingFileName,LPCWSTR lpNewFileName, BOOL bFailIfExists)
{
	char pMultiByteExistingFileName[512];
	char pMultiByteNewFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpExistingFileName,-1,pMultiByteExistingFileName,(int)strlen(pMultiByteExistingFileName),NULL,NULL);
	WideCharToMultiByte(CP_ACP,0,lpNewFileName,-1,pMultiByteNewFileName,(int)strlen(pMultiByteNewFileName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CopyFileW>,func_params=<lpExistingFileName|"<<pMultiByteExistingFileName<<",lpNewFileName|"<<\
		pMultiByteNewFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCopyFileW(lpExistingFileName,lpNewFileName,bFailIfExists);
}

BOOL WINAPI HookDeleteFileW(LPCWSTR lpFileName)
{
	char pMultiByteFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpFileName,-1,pMultiByteFileName,(int)strlen(pMultiByteFileName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<DeleteFileW>,func_params=<lpFileName|"<<pMultiByteFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealDeleteFileW(lpFileName);
}

//static BOOL (WINAPI *RealDeleteFileW)( LPCWSTR lpFileName) = DeleteFileW;
HANDLE WINAPI HookFindFirstFileW(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData)
{
	char pMultiByteFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpFileName,-1,pMultiByteFileName,(int)strlen(pMultiByteFileName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindFirstFileW>,func_params=<lpFileName|"<<pMultiByteFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindFirstFileW(lpFileName,lpFindFileData);
}
//static HANDLE (WINAPI *RealFindFirstFileW)( LPCWSTR,  LPWIN32_FIND_DATAW)=FindFirstFileW;
BOOL WINAPI HookFindNextFileW(HANDLE hFindFile,LPWIN32_FIND_DATA lpFindFileData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindNextFileW>"<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindNextFileW(hFindFile,lpFindFileData);
}

//static BOOL (WINAPI *RealFindNextFileW)( HANDLE hFindFile,  LPWIN32_FIND_DATAW lpFindFileData)=FindNextFileW;
HCERTSTORE WINAPI HookCertOpenSystemStoreW(HCRYPTPROV_LEGACY hProv,LPCWSTR szSubsystemProtocol){
	char pMultiByteSubsystemProtocol[512];
	WideCharToMultiByte(CP_ACP,0,szSubsystemProtocol,-1,pMultiByteSubsystemProtocol,(int)strlen(pMultiByteSubsystemProtocol),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CertOpenSystemStoreW>,func_params=<szSubsystemProtocol|"<<pMultiByteSubsystemProtocol<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCertOpenSystemStoreW(hProv,szSubsystemProtocol);
}

//static HCERTSTORE (WINAPI *RealCertOpenSystemStore)( HCRYPTPROV_LEGACY hProv,  LPCWSTR szSubsystemProtocol)=CertOpenSystemStoreW;
HANDLE WINAPI HookCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName){
	char pMultiByteName[512]={0};
	if(lpName!=NULL) {
		WideCharToMultiByte(CP_ACP,0,lpName,-1,pMultiByteName,(int)strlen(pMultiByteName),NULL,NULL);
	}
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateMutexW>,func_params=<lpName|"<<(lpName==NULL?"NULL":pMultiByteName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateMutexW(lpMutexAttributes,bInitialOwner,lpName);
}

//static HANDLE (WINAPI *RealCreateMutexW)( LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)=CreateMutexW;
HRSRC WINAPI HookFindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType){
	string sMultiByteName;
	string sMultiByteType;
	//if(lpName!=NULL) WideCharToMultiByte(CP_ACP,0,MAKEINTRESOURCE(lpName),-1,(LPSTR)&sMultiByteName,(int)strlen(sMultiByteName.c_str()),NULL,NULL);
	//if(lpType!=NULL) WideCharToMultiByte(CP_ACP,0,MAKEINTRESOURCE(lpType),-1,(LPSTR)&sMultiByteType,(int)strlen(sMultiByteType.c_str()),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindResourceW>,func_params=<hModule|"<<hModule<<",lpName|"<<(lpName==NULL?L"NULL":lpName)\
		<<",lpType|"<<(lpType==NULL?L"NULL":lpType)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealFindResourceW(hModule,lpName,lpType);
}

//static HRSRC (WINAPI *RealFindResourceW)( HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)=FindResourceW;
HWND WINAPI HookFindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName){
	char pMultiByteClassName[512];
	WideCharToMultiByte(CP_ACP,0,lpClassName,-1,pMultiByteClassName,(int)strlen(pMultiByteClassName),NULL,NULL);
	char pMultiByteWindowName[512];
	WideCharToMultiByte(CP_ACP,0,lpWindowName,-1,pMultiByteWindowName,(int)strlen(pMultiByteWindowName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<FindWindowW>,func_params=<lpClassName|"<<(lpClassName==NULL?"NULL":pMultiByteClassName)<<\
		",lpWindowName|"<<(lpWindowName==NULL?"NULL":pMultiByteWindowName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyFindWindowW)RealFindWindowW)(lpClassName,lpWindowName);
}

//static HWND (WINAPI *RealFindWindowW)( LPCWSTR lpClassName, LPCWSTR lpWindowName)=FindWindowW;
UINT WINAPI HookGetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize){
	char pMultiByteBuffer[512];
	WideCharToMultiByte(CP_ACP,0,lpBuffer,-1,pMultiByteBuffer,(int)strlen(pMultiByteBuffer),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetWindowsDirectoryW>,func_params=<lpBuffer|"<<pMultiByteBuffer<<",uSize|"<<uSize<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetWindowsDirectoryW(lpBuffer,uSize);
}

//static UINT (WINAPI *RealGetWindowsDirectoryW)( LPWSTR lpBuffer, UINT uSize)=GetWindowsDirectoryW;
UINT WINAPI HookMapVirtualKeyW(UINT uCode, UINT uMapType){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MapVirtualKeyW>,func_params=<uCode|"<<uCode<<",uMapType|"<<uMapType<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyMapVirtualKeyW)RealMapVirtualKeyW)(uCode,uMapType);
}
//static UINT (WINAPI *RealMapVirtualKeyW)( UINT uCode, UINT uMapType)=MapVirtualKeyW;

HANDLE WINAPI HookOpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName){
	char pMultiByteName[512];
	WideCharToMultiByte(CP_ACP,0,lpName,-1,pMultiByteName,(int)strlen(pMultiByteName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenMutexW>,func_params=<lpName|"<<(lpName==NULL?"NULL":pMultiByteName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenMutexW(dwDesiredAccess,bInheritHandle,lpName);
}
//static HANDLE (WINAPI *RealOpenMutexW)( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)=OpenMutexW;

HANDLE WINAPI HookOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess){
	char pMultiByteMachineName[512];
	WideCharToMultiByte(CP_ACP,0,lpMachineName,-1,pMultiByteMachineName,(int)strlen(pMultiByteMachineName),NULL,NULL);
	char pMultiByteDatabaseName[512];
	WideCharToMultiByte(CP_ACP,0,lpDatabaseName,-1,pMultiByteDatabaseName,(int)strlen(pMultiByteDatabaseName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OpenSCManagerW>,func_params=<lpMachineName|"<<(lpMachineName==NULL?"NULL":pMultiByteMachineName)<<\
		",lpDatabaseName|"<<(lpDatabaseName==NULL?"NULL":pMultiByteDatabaseName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOpenSCManagerW(lpMachineName,lpDatabaseName,dwDesiredAccess);
}
//static SC_HANDLE (WINAPI *RealOpenSCManagerW)( LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess)=OpenSCManagerW;
//BOOL WINAPI HookCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
//	::MessageBoxW(NULL,_T("CreateProcessW Hooked"),_T("APIHook"),0);//张宇南测试所加
//	stringstream logstream;
//	logstream.clear();
//	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
//GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateProcessW>,func_params=<lpApplicationName|"<<lpApplicationName<<",lpCommandLine|"<<\
//lpCommandLine<<",lpProcessAttributes|"<<lpProcessAttributes<<",lpThreadAttributes|"<<lpThreadAttributes<<",bInheritHandles|"<<bInheritHandles<<",dwCreationFlags|"<<\
//dwCreationFlags<<",lpEnvironment|"<<lpEnvironment<<",lpCurrentDirectory|"<<lpCurrentDirectory<<",lpStartupInfo|"<<lpStartupInfo<<",lpProcessInformation|"<<lpProcessInformation<<">";
//
//	string s,sm;
//	sm="";
//	sm=logstream.str();
//	sm=sm+"\n\0";
//	ofstream f(log_path,ios::app);
//	f<<sm;
//	f.close();
//	sm="";
//	logstream.clear();
//	//MoveLog();
//	//ReleaseMutex(hMutex);
//	return RealCreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
//}
//static BOOL (WINAPI *RealCreateProcessW)( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, \
//BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)=CreateProcessW;

SC_HANDLE WINAPI HookCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, \
									DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, \
									LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword)
{
	char pMultiByteServiceName[512];
	WideCharToMultiByte(CP_ACP,0,lpServiceName,-1,pMultiByteServiceName,(int)strlen(pMultiByteServiceName),NULL,NULL);
	char pMultiByteDisplayName[512];
	WideCharToMultiByte(CP_ACP,0,lpDisplayName,-1,pMultiByteDisplayName,(int)strlen(pMultiByteDisplayName),NULL,NULL);
	char pMultiByteBinaryPathName[512];
	WideCharToMultiByte(CP_ACP,0,lpBinaryPathName,-1,pMultiByteBinaryPathName,(int)strlen(pMultiByteBinaryPathName),NULL,NULL);
	char pMultiByteLoadOrderGroup[512];
	WideCharToMultiByte(CP_ACP,0,lpLoadOrderGroup,-1,pMultiByteLoadOrderGroup,(int)strlen(pMultiByteLoadOrderGroup),NULL,NULL);
	char pMultiByteServiceStartName[512];
	WideCharToMultiByte(CP_ACP,0,lpServiceStartName,-1,pMultiByteServiceStartName,(int)strlen(pMultiByteServiceStartName),NULL,NULL);
	char pMultiBytePassword[512];
	WideCharToMultiByte(CP_ACP,0,lpPassword,-1,pMultiBytePassword,(int)strlen(pMultiBytePassword),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateServiceW>,func_params=<hSCManager|"<<hSCManager<<",lpServiceName|"<<\
		pMultiByteServiceName<<",lpDisplayName|"<<pMultiByteDisplayName<<",dwDesiredAccess|"<<dwDesiredAccess<<",dwServiceType|"<<dwServiceType<<",dwStartType|"<<\
		dwStartType<<",dwErrorControl|"<<dwErrorControl<<",lpBinaryPathName|"<<pMultiByteBinaryPathName<<",lpLoadOrderGroup|"<<pMultiByteLoadOrderGroup<<",lpdwTagId|"<<\
		lpdwTagId<<",lpDependencies|"<<lpDependencies<<",lpServiceStartName|"<<pMultiByteServiceStartName<<",lpPassword|"<<pMultiBytePassword<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealCreateServiceW(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,\
		lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
}
//static SC_HANDLE (WINAPI *RealCreateServiceW)( SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess,\
//DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies,\
//LPCWSTR lpServiceStartName, LPCWSTR lpPassword)=CreateServiceW;
DWORD WINAPI HookGetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFileName, DWORD nSize){
	char pMultiByteFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpFileName,-1,pMultiByteFileName,(int)strlen(pMultiByteFileName),NULL,NULL);
	cout<<"GetModuleFileNameExW hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleFileNameExW>,func_params=<lpFileName|"<<(lpFileName==NULL?"NULL":pMultiByteFileName)<<\
		">";//(lpValue==NULL?"NULL":lpValue)

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetModuleFileNameExW(hProcess,hModule,lpFileName,nSize);
}
//return ((MyMapVirtualKeyW)RealMapVirtualKeyW)(uCode,uMapType);
//static DWORD (WINAPI *RealGetModuleFileNameExW)( HANDLE hProcess, HMODULE hModule, LPWSTR lpFileName, DWORD nSize)=GetModuleFileNameExW;

HMODULE WINAPI HookGetModuleHandleW(LPCWSTR lpModuleName){
	char pMultiByteModuleName[512];
	WideCharToMultiByte(CP_ACP,0,lpModuleName,-1,pMultiByteModuleName,(int)strlen(pMultiByteModuleName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetModuleHandleW>,func_params=<lpModuleName|"<<(lpModuleName==NULL?"NULL":pMultiByteModuleName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetModuleHandleW(lpModuleName);
}
//static HMODULE (WINAPI *RealGetModuleHandleW)( LPCWSTR lpModuleName)=GetModuleHandleW;

VOID WINAPI HookGetStartupInfoW(LPSTARTUPINFOW lpStartupInfo){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetStartupInfoW>,func_params=<lpStartupInfo|"<<lpStartupInfo<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetStartupInfoW(lpStartupInfo);
}
//static VOID (WINAPI *RealGetStartupInfoW)( LPSTARTUPINFOW lpStartupInfo)=GetStartupInfoW;
BOOL WINAPI HookGetVersionExW(LPOSVERSIONINFOW lpVersionInfo){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<GetVersionExW"<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealGetVersionExW(lpVersionInfo);
}
//static BOOL (WINAPI *RealGetVersionExW)( LPOSVERSIONINFOW lpVersionInfo)=GetVersionExW;

HMODULE WINAPI HookLoadLibraryW(LPCWSTR lpFileName){
	char pMultiByteFileName[512];
	WideCharToMultiByte(CP_ACP,0,lpFileName,-1,pMultiByteFileName,(int)strlen(pMultiByteFileName),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<LoadLibraryW>,func_params=<lpFileName|"<<pMultiByteFileName<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealLoadLibraryW(lpFileName);
}
//static HMODULE (WINAPI *RealLoadLibraryW)( LPCWSTR lpFileName)=LoadLibraryW;

VOID WINAPI HookOutputDebugStringW(LPCWSTR lpOutputString){
	char pMultiByteOutputString[512];
	WideCharToMultiByte(CP_ACP,0,lpOutputString,-1,pMultiByteOutputString,(int)strlen(pMultiByteOutputString),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<OutputDebugStringW>,func_params=<lpOutputString|"<<pMultiByteOutputString<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealOutputDebugStringW(lpOutputString);
}
//static VOID (WINAPI *RealOutputDebugStringW)( LPCWSTR lpOutputString)=OutputDebugStringW;

HHOOK WINAPI HookSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetWindowsHookExW>,func_params=<idHook|"<<idHook<<",dwThreadId|"<<dwThreadId<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealSetWindowsHookExW(idHook,lpfn,hMod,dwThreadId);
}
//static HHOOK (WINAPI *RealSetWindowsHookExW)( int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)=SetWindowsHookExW;

HINSTANCE WINAPI HookShellExecuteW( HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd){
	char pMultiByteOperation[512];
	WideCharToMultiByte(CP_ACP,0,lpOperation,-1,pMultiByteOperation,(int)strlen(pMultiByteOperation),NULL,NULL);
	char pMultiByteFile[512];
	WideCharToMultiByte(CP_ACP,0,lpFile,-1,pMultiByteFile,(int)strlen(pMultiByteFile),NULL,NULL);
	char pMultiByteParameters[512];
	WideCharToMultiByte(CP_ACP,0,lpParameters,-1,pMultiByteParameters,(int)strlen(pMultiByteParameters),NULL,NULL);
	char pMultiByteDirectory[512];
	WideCharToMultiByte(CP_ACP,0,lpDirectory,-1,pMultiByteDirectory,(int)strlen(pMultiByteDirectory),NULL,NULL);
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ShellExecuteW>,func_params=<lpOperation|"<<(lpOperation==NULL?"NULL":pMultiByteOperation)<<\
		",lpFile|"<<pMultiByteFile<<",lpParameters|"<<(lpParameters==NULL?"NULL":pMultiByteParameters)<<",lpDirectory|"<<(lpDirectory==NULL?"NULL":pMultiByteDirectory)<<",nShowCmd|"<<nShowCmd<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealShellExecuteW(hwnd,lpOperation,lpFile,lpParameters,lpDirectory,nShowCmd);
}
//static HINSTANCE (WINAPI *RealShellExecuteW)( HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)=ShellExecuteW;

BOOL WINAPI HookStartServiceCtrlDispatcherW( CONST SERVICE_TABLE_ENTRYW *lpServiceTable){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<StartServiceCtrlDispatcherW>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealStartServiceCtrlDispatcherW(lpServiceTable);
}
//static BOOL (WINAPI *RealStartServiceCtrlDispatcherW)( CONST SERVICE_TABLE_ENTRYW *lpServiceTable)=StartServiceCtrlDispatcherW;

LONG WINAPI HookRegOpenKeyW( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegOpenKeyW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<",phkResult|"<<phkResult<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyW(hKey,lpSubKey,phkResult);
}
//static LONG (WINAPI *RealRegOpenKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegOpenKeyW;

BOOL WINAPI HookModule32Next( HANDLE hSnapshot, LPMODULEENTRY32 lpme ){
	cout<<"Module32Next hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32Next>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32Next)RealModule32Next)(hSnapshot,lpme);
}
//static BOOL (WINAPI *RealModule32Next)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32Next;
BOOL WINAPI HookModule32First( HANDLE hSnapshot, LPMODULEENTRY32 lpme ){
	cout<<"Module32First hooked!"<<endl;
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<Module32First>";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return ((MyModule32First)RealModule32First)(hSnapshot,lpme);
}
//static BOOL (WINAPI *RealModule32First)( HANDLE hSnapshot, LPMODULEENTRY32 lpme )=Module32First;

LONG WINAPI HookRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired,\
								LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<CreateKeyExA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":lpSubKey)<<",lpClass|"<<(lpClass==NULL?"NULL":lpClass)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegCreateKeyExA(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,phkResult,lpdwDisposition);
}
//static LONG (WINAPI *RealRegCreateKeyExA)( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, \
//LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExA;
LONG WINAPI HookRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, \
								LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);
	char pMultiByteClass[512];
	WideCharToMultiByte(CP_ACP,0,lpClass,-1,pMultiByteClass,(int)strlen(pMultiByteClass),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyExW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<",lpClass|"<<(lpClass==NULL?"NULL":pMultiByteClass)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegCreateKeyExW(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,phkResult,lpdwDisposition);
}
//static LONG (WINAPI *RealRegCreateKeyExA)( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, \
//LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)=RegCreateKeyExW;

LONG WINAPI HookRegCreateKeyA(  HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":lpSubKey)<<",phkResult|"<<phkResult<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegOpenKeyA(hKey,lpSubKey,phkResult);
}
//static LONG (WINAPI *RealRegCreateKeyA)( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)=RegCreateKeyA;
LONG WINAPI HookRegCreateKeyW(  HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegCreateKeyW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegCreateKeyW(hKey,lpSubKey,phkResult);
}
//static LONG (WINAPI *RealRegCreateKeyW)( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)=RegCreateKeyW;

LONG WINAPI HookRegQueryValueExA(  HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueExA>,func_params=<hKey|"<<hKey<<",lpValueName|"<<\
		(lpValueName==NULL?"NULL":lpValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueExA(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
}
//static LONG (WINAPI *RealRegQueryValueExA)( HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExA;
LONG WINAPI HookRegQueryValueExW(  HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteValueName[512];
	WideCharToMultiByte(CP_ACP,0,lpValueName,-1,pMultiByteValueName,(int)strlen(pMultiByteValueName),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueExW>,func_params=<hKey|"<<hKeyToString<<",lpValueName|"<<\
		(lpValueName==NULL?"NULL":pMultiByteValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueExW(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
}
//static LONG (WINAPI *RealRegQueryValueExW)( HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)=RegQueryValueExW;

LONG WINAPI HookRegQueryValueA( HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":lpSubKey)<<",lpValue|"<<(lpValue==NULL?"NULL":lpValue)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueA( hKey, lpSubKey, lpValue, lpcbValue);
}
//static LONG (WINAPI *RealRegQueryValueA)( HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue)=RegQueryValueA;
LONG WINAPI HookRegQueryValueW( HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);
	char pMultiByteValue[512];
	WideCharToMultiByte(CP_ACP,0,lpValue,-1,pMultiByteValue,(int)strlen(pMultiByteValue),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegQueryValueW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<",lpValue|"<<(lpValue==NULL?"NULL":pMultiByteValue)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegQueryValueW( hKey, lpSubKey, lpValue, lpcbValue);
}
//static LONG (WINAPI *RealRegQueryValueW)( HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue)=RegQueryValueW;

LONG WINAPI HookRegSetValueExA(  HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueExA>,func_params=<hKey|"<<hKey<<",lpValueName|"<<\
		(lpValueName==NULL?"NULL":lpValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueExA(hKey,lpValueName,Reserved,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueExA)( HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExA;
LONG WINAPI HookRegSetValueExW(  HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteValueName[512];
	WideCharToMultiByte(CP_ACP,0,lpValueName,-1,pMultiByteValueName,(int)strlen(pMultiByteValueName),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueExW>,func_params=<hKey|"<<hKeyToString<<",lpValueName|"<<\
		(lpValueName==NULL?"NULL":pMultiByteValueName)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueExW(hKey,lpValueName,Reserved,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueExW)( HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)=RegSetValueExW;

LONG WINAPI HookRegSetValueA( HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueA(hKey,lpSubKey,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueA)( HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)=RegSetValueA;
LONG WINAPI HookRegSetValueW( HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);
	char pMultiByteData[512];
	WideCharToMultiByte(CP_ACP,0,lpData,-1,pMultiByteData,(int)strlen(pMultiByteData),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegSetValueW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<(lpData==NULL?"NULL":pMultiByteData)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegSetValueW(hKey,lpSubKey,dwType,lpData,cbData);
}
//static LONG (WINAPI *RealRegSetValueW)( HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)=RegSetValueW;

LONG WINAPI HookRegDeleteKeyExA(  HKEY hKey, LPCSTR lpSubKey,REGSAM samDesired, DWORD Reserved){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyExA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyExA(hKey,lpSubKey,samDesired,Reserved);
}
//static LONG (WINAPI *RealRegDeleteKeyExA)( HKEY hKey, LPCSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExA;
LONG WINAPI HookRegDeleteKeyExW(  HKEY hKey, LPCWSTR lpSubKey,REGSAM samDesired, DWORD Reserved){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyExW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyExW(hKey,lpSubKey,samDesired,Reserved);
}
//static LONG (WINAPI *RealRegDeleteKeyExW)( HKEY hKey, LPCWSTR lpSubKey,REGSAM samDesired, DWORD Reserved)=RegDeleteKeyExW;

LONG WINAPI HookRegDeleteKeyA(  HKEY hKey, LPCSTR lpSubKey){
	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyA>,func_params=<hKey|"<<hKey<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":lpSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyA(hKey,lpSubKey);
}
//static LONG (WINAPI *RealRegDeleteKeyA)( HKEY hKey, LPCSTR lpSubKey)=RegDeleteKeyA;
LONG WINAPI HookRegDeleteKeyW(  HKEY hKey, LPCWSTR lpSubKey){
	string hKeyToString;
	if(HKEY_CLASSES_ROOT==hKey) hKeyToString="HKEY_CLASSES_ROOT";
	else if(HKEY_CURRENT_USER==hKey) hKeyToString="HKEY_CURRENT_USER";
	else if(HKEY_LOCAL_MACHINE==hKey) hKeyToString="HKEY_LOCAL_MACHINE";
	else if(HKEY_USERS==hKey) hKeyToString="HKEY_USERS";
	else hKeyToString="HKEY_CURRENT_CONFIG";

	char pMultiByteSubKey[512];
	WideCharToMultiByte(CP_ACP,0,lpSubKey,-1,pMultiByteSubKey,(int)strlen(pMultiByteSubKey),NULL,NULL);

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<\
		GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<RegDeleteKeyW>,func_params=<hKey|"<<hKeyToString<<",lpSubKey|"<<\
		(lpSubKey==NULL?"NULL":pMultiByteSubKey)<<">";

	string s,sm;
	sm="";
	sm=logstream.str();
	sm=sm+"\n\0";
	ofstream f(log_path,ios::app);
	f<<sm;
	f.close();
	sm="";
	logstream.clear();
	//MoveLog();
	//ReleaseMutex(hMutex);
	return RealRegDeleteKeyW(hKey,lpSubKey);
}
//static LONG (WINAPI *RealRegDeleteKeyW)( HKEY hKey, LPCWSTR lpSubKey)=RegDeleteKeyW;


extern "C" __declspec(dllexport) void DummyFunc(void)
{
	return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  dwReason,
                       LPVOID lpReserved
					 )
{
	//Realsend=DetourFindFunction("Ws2_32.dll","send");
	// install the hook(s)
	/*
	hMutex=OpenMutexA(MUTEX_ALL_ACCESS, false, "mutex");
	if (hMutex==NULL)
	{
		hMutex=CreateMutexA(NULL,FALSE,"mutex");
		ftest<<"create"<<endl;
	}else{
		ftest<<"open"<<endl;
	}
	*/
	/*
	if(s.compare("D:\\Program Files (x86)\\Tencent\\QQ\\bin\\QQ.exe")==0){
		ftest<<"create"<<endl;
		hMutex=CreateMutexA(NULL,TRUE,"mutex");
	}else{
		hMutex=OpenMutexA(MUTEX_ALL_ACCESS, false, "mutex");
		ftest<<"open"<<endl;
	}
	*/
	
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//ofstream f(log_path,ios::app);
		//f.close();
		DWORD dwSize = 256;
		int len=200;
		GetUserNameA(strBuffer,&dwSize);//获取用户名
		WSAData wsaData;
		WSAStartup(MAKEWORD(1,1), &wsaData); 
		gethostname(hostname,128);//获取主机名
		GetProcessName(ProcessName,&len);//获取进程名
		cout<<ProcessName<<endl;
		cout<<hostname<<endl;
		cout<<strBuffer<<endl;
		//ofstream ftest("C:\\Log\\test.txt",ios::app);
	    
		char windire[100] ={0};  
		GetSystemDirectoryA(windire, 100 );
		SHGetSpecialFolderPathA(NULL,windire,CSIDL_PROGRAM_FILES,FALSE);
		//wprintf(L"%s",windire);
		char configpath[1000]={0};
		sprintf_s(configpath,"%s\\UserMonitor\\bin\\config.xml",windire);
		//sprintf_s(log_path,"%s\\UserMonitor\\bin\\Log.txt",windire);
		//printf(L"%s",configpath);
		
>>>>>>> .r53
	TiXmlDocument doc;
	char configpath[MAX_PATH]={0};
	sprintf(configpath,"%sconfig.xml",dlldir);
	if(!doc.LoadFile(configpath)) 
	{
		///OutputDebugStringA(doc.ErrorDesc()+"\n");
		//ftest<<doc.ErrorDesc()<<endl;
	}
	memset(api,0,200*sizeof(api[0]));
	TiXmlElement* root = doc.FirstChildElement();
	if(root == NULL)
	{
		//ftest<< "Failed to load file: No root element."<<endl;
		doc.Clear();
	}
	int count=0;
	string s=GetProcessPath();
	//OutputDebugStringA(s.c_str());
	//OutputDebugStringA("\n");
	for(TiXmlElement* elem = root->FirstChildElement(); elem != NULL; elem = elem->NextSiblingElement())
	{
		//cout<<elem->Attribute("name")<<endl;
		TiXmlElement* e1=elem->FirstChildElement("isMonitored");
		//ftest<<atoi(e1->FirstChild()->ToText()->Value())<<endl;
		api[count]=atoi(e1->FirstChild()->ToText()->Value());

		for(TiXmlElement* elem1 = e1->NextSiblingElement();elem1 != NULL; elem1 = elem1->NextSiblingElement())
		{
			if(strcmp(elem1->FirstChild()->ToText()->Value(),s.c_str())==0) 
			{
				api[count]=0;
			}
			//获取到的进程的路径格式是：F:\Program Files\AnyDesk\AnyDesk.exe  单斜杆
		}

		count++;
	}
	for (int i=0;i<=123;i++)
	{
		//api[i]=1;//测试完了要去掉
		char out[100];
		sprintf(out,"%d %d\n",i,api[i]);
		OutputDebugStringA(out);
	}
	/*
	statue = LhInstallHook(realCreateFileA,  MyCreateFileA, NULL, hHookCreateFileA); 
	LhInstallHook(realReadFile,MyReadFile,NULL,hHookReadFile);
	if(!SUCCEEDED(statue))  
	{  
		switch (statue)  
		{  
		case STATUS_NO_MEMORY:  
			OutputDebugString(L"STATUS_NO_MEMORY\n");  
			break;  
		case STATUS_NOT_SUPPORTED:  
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");  
			break;  
		case STATUS_INSUFFICIENT_RESOURCES:  
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");  
			break;  
		default:  
			WCHAR dbgstr[512] = {0};  
			wsprintf(dbgstr, L"%d\n", statue);  
			OutputDebugString(dbgstr);  
		}  
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");  
		return;  
	}  
	OutputDebugString(L"Hook CreateFileA OK\n"); 
	*/
	//文件API
	if (api[0]==1&&realCreateFileA!=NULL)
	{
		LhInstallHook(realCreateFileA,MyCreateFileA,NULL,hHookCreateFileA);
		LhSetExclusiveACL(HookCreateFileA_ACLEntries, 1, hHookCreateFileA);
	}
	if (api[1]==1&&realReadFile!=NULL)
	{
		LhInstallHook(realReadFile,MyReadFile,NULL,hHookReadFile);
		LhSetExclusiveACL(HookReadFile_ACLEntries,1,hHookReadFile);
	}
	if (api[2]==1&&realCreateFileW!=NULL)
	{
		LhInstallHook(realCreateFileW,MyCreateFileW,NULL,hHookCreateFileW);
		LhSetExclusiveACL(HookCreateFileW_ACLEntries,1,hHookCreateFileW);
	}   
	if (api[3]==1&&realMoveFileW!=NULL)
	{
		LhInstallHook(realMoveFileW,MyMoveFileW,NULL,hHookMoveFileW);
		LhSetExclusiveACL(HookMoveFileW_ACLEntries,1,hHookMoveFileW);
	}
	if (api[4]==1&&realCopyFileW!=NULL)
	{
		LhInstallHook(realCopyFileW,MyCopyFileW,NULL,hHookCopyFileW);
		LhSetExclusiveACL(HookCopyFileW_ACLEntries,1,hHookCopyFileW);
	}
	if (api[5]==1&&realDeleteFileW!=NULL)
	{
		LhInstallHook(realDeleteFileW,MyDeleteFileW,NULL,hHookDeleteFileW);
		LhSetExclusiveACL(HookDeleteFileW_ACLEntries,1,hHookDeleteFileW);
	}
	if (api[6]==1&&realFindFirstFileW!=NULL)
	{
		LhInstallHook(realFindFirstFileW,MyFindFirstFileW,NULL,hHookFindFirstFileW);
		LhSetExclusiveACL(HookFindFirstFileW_ACLEntries,1,hHookFindFirstFileW);
	}
	if (api[7]==1&&realFindNextFileW!=NULL)
	{
		LhInstallHook(realFindNextFileW,MyFindNextFileW,NULL,hHookFindNextFileW);
		LhSetExclusiveACL(HookFindNextFileW_ACLEntries,1,hHookFindNextFileW);
	}
	if (api[8]==1&&realSetFileAttributesW!=NULL)
	{
		LhInstallHook(realSetFileAttributesW,MySetFileAttributesW,NULL,hHookSetFileAttributesW);
		LhSetExclusiveACL(HookSetFileAttributesW_ACLEntries,1,hHookSetFileAttributesW);
	}
	if (api[9]==1&&realCreateHardLinkW!=NULL)
	{
		LhInstallHook(realCreateHardLinkW,MyCreateHardLinkW,NULL,hHookCreateHardLinkW);
		LhSetExclusiveACL(HookCreateHardLinkW_ACLEntries,1,hHookCreateHardLinkW);
	}
	if (api[10]==1&&realSetEndOfFile!=NULL)
	{
		
		LhInstallHook(realSetEndOfFile,MySetEndOfFile,NULL,hHookSetEndOfFile);
		LhSetExclusiveACL(HookSetEndOfFile_ACLEntries,1,hHookSetEndOfFile);
		
	}
	//问题在下面
	//进程API
	if (api[11]==1&&realBitBlt!=NULL)
	{
	    //据说捕获屏幕的时候会调用，但是调用过于频繁
		
		//LhInstallHook(realBitBlt,MyBitBlt,NULL,hHookBitBlt);
		//LhSetExclusiveACL(HookBitBlt_ACLEntries, 1, hHookBitBlt);
		
	}
	if (api[12]==1&&realCreateFileMapping!=NULL)
	{
		OutputDebugStringA("CreateFileMapping is ok\n");
		LhInstallHook(realCreateFileMapping,MyCreateFileMapping,NULL,hHookCreateFileMapping);
		LhSetExclusiveACL(HookCreateFileMapping_ACLEntries, 1, hHookCreateFileMapping);
	}else{
		OutputDebugStringA("CreateFileMapping is not ok\n");
	}
	if (api[13]==1&&realOpenFileMapping!=NULL)
	{
		OutputDebugStringA("OpenFileMapping is ok\n");
		LhInstallHook(realOpenFileMapping,MyOpenFileMapping,NULL,hHookOpenFileMapping);
		LhSetExclusiveACL(HookOpenFileMapping_ACLEntries,1,hHookOpenFileMapping);
	}else{
		OutputDebugStringA("OpenFileMapping is not ok\n");
	}
	if (api[14]==1&&realCryptAcquireContext!=NULL)
	{
		LhInstallHook(realCryptAcquireContext,MyCryptAcquireContext,NULL,hHookCryptAcquireContext);
		LhSetExclusiveACL(HookCryptAcquireContext_ACLEntries, 1, hHookCryptAcquireContext);
	}
	if (api[15]==1&&realDeviceIoControl!=NULL)
	{
		LhInstallHook(realDeviceIoControl,MyDeviceIoControl,NULL,hHookDeviceIoControl);
		LhSetExclusiveACL(HookDeviceIoControl_ACLEntries, 1, hHookDeviceIoControl);
	}
	if (api[16]==1&&realFindWindowEx!=NULL)
	{
		LhInstallHook(realFindWindowEx,MyFindWindowEx,NULL,hHookFindWindowEx);
		LhSetExclusiveACL(HookFindWindowEx_ACLEntries, 1, hHookFindWindowEx);
	}
	if (api[17]==1&&realGetAsyncKeyState!=NULL)
	{
		LhInstallHook(realGetAsyncKeyState,MyGetAsyncKeyState,NULL,hHookGetAsyncKeyState);
		LhSetExclusiveACL(HookGetAsyncKeyState_ACLEntries, 1, hHookGetAsyncKeyState);
	}
	if (api[18]==1&&realGetDC!=NULL)
	{
		
		//LhInstallHook(realGetDC,MyGetDC,NULL,hHookGetDC);
		//LhSetExclusiveACL(HookGetDC_ACLEntries, 1, hHookGetDC);
		
<<<<<<< .mine
	}
	
	if (api[19]==1&&realGetForegroundWindow!=NULL)//抛出这样的异常，0x000000007757CD02 (user32.dll) (explorer.exe 中)处的第一机会异常: 0xC0000005: 写入位置 0x000007FEEEC441B4 时发生访问冲突。
	{
		//LhInstallHook(realGetForegroundWindow,MyGetForegroundWindow,NULL,hHookGetForegroundWindow);
		//LhSetExclusiveACL(HookGetForegroundWindow_ACLEntries, 1, hHookGetForegroundWindow);
	}
	if (api[20]==1&&realGetKeyState!=NULL)
	{
||||||| .r39
		//网络相关API
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realaccept!=NULL) mydetour=(api[79]==1)?DetourAttach(&(PVOID&)Realaccept,Hookaccept):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realsend!=NULL) mydetour=(api[80]==1)?DetourAttach(&(PVOID&)Realsend,Hooksend):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realbind!=NULL) mydetour=(api[81]==1)?DetourAttach(&(PVOID&)Realbind,Hookbind):0;//XP下崩溃
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realconnect!=NULL) mydetour=(api[82]==1)?DetourAttach(&(PVOID&)Realconnect,Hookconnect):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		mydetour=(api[83]==1)?DetourAttach(&(PVOID&)RealConnectNamedPipe,HookConnectNamedPipe):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealGetAdaptersInfo!=NULL) mydetour=(api[84]==1)?DetourAttach(&(PVOID&)RealGetAdaptersInfo,HookGetAdaptersInfo):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realgethostbyname!=NULL) mydetour=(api[85]==1)?DetourAttach(&(PVOID&)Realgethostbyname,Hookgethostbyname):0;//XP下崩溃，这个API只支持Vista或者8.1以上的版本
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realgethostname!=NULL) mydetour=(api[86]==1)?DetourAttach(&(PVOID&)Realgethostname,Hookgethostname):0;//XP下崩溃，这个API只支持Vista或者8.1以上的版本
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realinet_addr!=NULL) mydetour=(api[87]==1)?DetourAttach(&(PVOID&)Realinet_addr,Hookinet_addr):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetOpenA!=NULL) mydetour=(api[88]==1)?DetourAttach(&(PVOID&)RealInternetOpenA,HookInternetOpenA):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetOpenUrlA!=NULL) mydetour=(api[89]==1)?DetourAttach(&(PVOID&)RealInternetOpenUrlA,HookInternetOpenUrlA):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetReadFile!=NULL) mydetour=(api[90]==1)?DetourAttach(&(PVOID&)RealInternetReadFile,HookInternetReadFile):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetWriteFile!=NULL) mydetour=(api[91]==1)?DetourAttach(&(PVOID&)RealInternetWriteFile,HookInternetWriteFile):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealNetShareEnum!=NULL) mydetour=(api[92]==1)?DetourAttach(&(PVOID&)RealNetShareEnum,HookNetShareEnum):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realrecv!=NULL) mydetour=(api[93]==1)?DetourAttach(&(PVOID&)Realrecv,Hookrecv):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealURLDownloadToFileA!=NULL) mydetour=(api[94]==1)?DetourAttach(&(PVOID&)RealURLDownloadToFileA,HookURLDownloadToFileA):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealWSAStartup!=NULL) mydetour=(api[95]==1)?DetourAttach(&(PVOID&)RealWSAStartup,HookWSAStartup):0;
		DetourTransactionCommit();

		//by zhangyunan.
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCreateFileW!=NULL)mydetour=(api[96]==1)?DetourAttach(&(PVOID&)RealCreateFileW,HookCreateFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealMoveFileW!=NULL)mydetour=(api[97]==1)?DetourAttach(&(PVOID&)RealMoveFileW,HookMoveFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCopyFileW!=NULL)mydetour=(api[98]==1)?DetourAttach(&(PVOID&)RealCopyFileW,HookCopyFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealDeleteFileW!=NULL)mydetour=(api[99]==1)?DetourAttach(&(PVOID&)RealDeleteFileW,HookDeleteFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindFirstFileW!=NULL)mydetour=(api[100]==1)?DetourAttach(&(PVOID&)RealFindFirstFileW,HookFindFirstFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindNextFileW!=NULL)mydetour=(api[101]==1)?DetourAttach(&(PVOID&)RealFindNextFileW,HookFindNextFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCertOpenSystemStoreW!=NULL)mydetour=(api[102]==1)?DetourAttach(&(PVOID&)RealCertOpenSystemStoreW,HookCertOpenSystemStoreW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCreateMutexW!=NULL)mydetour=(api[103]==1)?DetourAttach(&(PVOID&)RealCreateMutexW,HookCreateMutexW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindResourceW!=NULL)mydetour=(api[104]==1)?DetourAttach(&(PVOID&)RealFindResourceW,HookFindResourceW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindWindowW!=NULL)mydetour=(api[105]==1)?DetourAttach(&(PVOID&)RealFindWindowW,HookFindWindowW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealGetWindowsDirectoryW!=NULL)mydetour=(api[106]==1)?DetourAttach(&(PVOID&)RealGetWindowsDirectoryW,HookGetWindowsDirectoryW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealMapVirtualKeyW!=NULL)mydetour=(api[107]==1)?DetourAttach(&(PVOID&)RealMapVirtualKeyW,HookMapVirtualKeyW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealOpenMutexW!=NULL)mydetour=(api[108]==1)?DetourAttach(&(PVOID&)RealOpenMutexW,HookOpenMutexW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealOpenSCManagerW!=NULL)mydetour=(api[109]==1)?DetourAttach(&(PVOID&)RealOpenSCManagerW,HookOpenSCManagerW):0;
		DetourTransactionCommit();

		//DetourTransactionBegin();
		//DetourUpdateThread(GetCurrentThread());
		//if(RealCreateProcessW!=NULL)mydetour=(api[110]==1)?DetourAttach(&(PVOID&)RealCreateProcessW,HookCreateProcessW):0;
		//DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCreateServiceW!=NULL)mydetour=(api[111]==1)?DetourAttach(&(PVOID&)RealCreateServiceW,HookCreateServiceW):0;
		DetourTransactionCommit();

		//DetourTransactionBegin();
		//DetourUpdateThread(GetCurrentThread());
		//mydetour=(api[112]==1)?DetourAttach(&(PVOID&)RealGetModuleFileNameExW,HookGetModuleFileNameExW):0;
		//DetourTransactionCommit();
=======
		//网络相关API
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realaccept!=NULL) mydetour=(api[79]==1)?DetourAttach(&(PVOID&)Realaccept,Hookaccept):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realsend!=NULL) mydetour=(api[80]==1)?DetourAttach(&(PVOID&)Realsend,Hooksend):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realbind!=NULL) mydetour=(api[81]==1)?DetourAttach(&(PVOID&)Realbind,Hookbind):0;//XP下崩溃
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realconnect!=NULL) mydetour=(api[82]==1)?DetourAttach(&(PVOID&)Realconnect,Hookconnect):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		mydetour=(api[83]==1)?DetourAttach(&(PVOID&)RealConnectNamedPipe,HookConnectNamedPipe):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealGetAdaptersInfo!=NULL) mydetour=(api[84]==1)?DetourAttach(&(PVOID&)RealGetAdaptersInfo,HookGetAdaptersInfo):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realgethostbyname!=NULL) mydetour=(api[85]==1)?DetourAttach(&(PVOID&)Realgethostbyname,Hookgethostbyname):0;//XP下崩溃，这个API只支持Vista或者8.1以上的版本
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realgethostname!=NULL) mydetour=(api[86]==1)?DetourAttach(&(PVOID&)Realgethostname,Hookgethostname):0;//XP下崩溃，这个API只支持Vista或者8.1以上的版本
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realinet_addr!=NULL) mydetour=(api[87]==1)?DetourAttach(&(PVOID&)Realinet_addr,Hookinet_addr):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetOpenA!=NULL) mydetour=(api[88]==1)?DetourAttach(&(PVOID&)RealInternetOpenA,HookInternetOpenA):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetOpenUrlA!=NULL) mydetour=(api[89]==1)?DetourAttach(&(PVOID&)RealInternetOpenUrlA,HookInternetOpenUrlA):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetReadFile!=NULL) mydetour=(api[90]==1)?DetourAttach(&(PVOID&)RealInternetReadFile,HookInternetReadFile):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealInternetWriteFile!=NULL) mydetour=(api[91]==1)?DetourAttach(&(PVOID&)RealInternetWriteFile,HookInternetWriteFile):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealNetShareEnum!=NULL) mydetour=(api[92]==1)?DetourAttach(&(PVOID&)RealNetShareEnum,HookNetShareEnum):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(Realrecv!=NULL) mydetour=(api[93]==1)?DetourAttach(&(PVOID&)Realrecv,Hookrecv):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealURLDownloadToFileA!=NULL) mydetour=(api[94]==1)?DetourAttach(&(PVOID&)RealURLDownloadToFileA,HookURLDownloadToFileA):0;
		DetourTransactionCommit();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealWSAStartup!=NULL) mydetour=(api[95]==1)?DetourAttach(&(PVOID&)RealWSAStartup,HookWSAStartup):0;
		DetourTransactionCommit();

		//by zhangyunan.
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		mydetour=(api[96]==1)?DetourAttach(&(PVOID&)RealCreateFileW,HookCreateFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealMoveFileW!=NULL)mydetour=(api[97]==1)?DetourAttach(&(PVOID&)RealMoveFileW,HookMoveFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCopyFileW!=NULL)mydetour=(api[98]==1)?DetourAttach(&(PVOID&)RealCopyFileW,HookCopyFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealDeleteFileW!=NULL)mydetour=(api[99]==1)?DetourAttach(&(PVOID&)RealDeleteFileW,HookDeleteFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindFirstFileW!=NULL)mydetour=(api[100]==1)?DetourAttach(&(PVOID&)RealFindFirstFileW,HookFindFirstFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindNextFileW!=NULL)mydetour=(api[101]==1)?DetourAttach(&(PVOID&)RealFindNextFileW,HookFindNextFileW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCertOpenSystemStoreW!=NULL)mydetour=(api[102]==1)?DetourAttach(&(PVOID&)RealCertOpenSystemStoreW,HookCertOpenSystemStoreW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCreateMutexW!=NULL)mydetour=(api[103]==1)?DetourAttach(&(PVOID&)RealCreateMutexW,HookCreateMutexW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindResourceW!=NULL)mydetour=(api[104]==1)?DetourAttach(&(PVOID&)RealFindResourceW,HookFindResourceW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealFindWindowW!=NULL)mydetour=(api[105]==1)?DetourAttach(&(PVOID&)RealFindWindowW,HookFindWindowW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealGetWindowsDirectoryW!=NULL)mydetour=(api[106]==1)?DetourAttach(&(PVOID&)RealGetWindowsDirectoryW,HookGetWindowsDirectoryW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealMapVirtualKeyW!=NULL)mydetour=(api[107]==1)?DetourAttach(&(PVOID&)RealMapVirtualKeyW,HookMapVirtualKeyW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealOpenMutexW!=NULL)mydetour=(api[108]==1)?DetourAttach(&(PVOID&)RealOpenMutexW,HookOpenMutexW):0;
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealOpenSCManagerW!=NULL)mydetour=(api[109]==1)?DetourAttach(&(PVOID&)RealOpenSCManagerW,HookOpenSCManagerW):0;
		DetourTransactionCommit();

		//DetourTransactionBegin();
		//DetourUpdateThread(GetCurrentThread());
		//if(RealCreateProcessW!=NULL)mydetour=(api[110]==1)?DetourAttach(&(PVOID&)RealCreateProcessW,HookCreateProcessW):0;
		//DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if(RealCreateServiceW!=NULL)mydetour=(api[111]==1)?DetourAttach(&(PVOID&)RealCreateServiceW,HookCreateServiceW):0;
		DetourTransactionCommit();

		//DetourTransactionBegin();
		//DetourUpdateThread(GetCurrentThread());
		//mydetour=(api[112]==1)?DetourAttach(&(PVOID&)RealGetModuleFileNameExW,HookGetModuleFileNameExW):0;
		//DetourTransactionCommit();
>>>>>>> .r53
		
		//LhInstallHook(realGetKeyState,MyGetKeyState,NULL,hHookGetKeyState);
		//LhSetExclusiveACL(HookGetKeyState_ACLEntries, 1, hHookGetKeyState);
		
	}
	if (api[21]==1&&realGetTempPath!=NULL)
	{
		LhInstallHook(realGetTempPath,MyGetTempPath,NULL,hHookGetTempPath);
		LhSetExclusiveACL(HookGetTempPath_ACLEntries, 1, hHookGetTempPath);
	}	
	if (api[22]==1&&realMapViewOfFile!=NULL)
	{
		
		//LhInstallHook(realMapViewOfFile,MyMapViewOfFile,NULL,hHookMapViewOfFile);
		//LhSetExclusiveACL(HookMapViewOfFile_ACLEntries, 1, hHookMapViewOfFile);
		
	}
	if (api[23]==1&&realOpenFile!=NULL)
	{
		LhInstallHook(realOpenFile,MyOpenFile,NULL,hHookOpenFile);
		LhSetExclusiveACL(HookOpenFile_ACLEntries, 1, hHookOpenFile);
	}
	if (api[24]==1&&realAdjustTokenPrivileges!=NULL)
	{
		LhInstallHook(realAdjustTokenPrivileges,MyAdjustTokenPrivileges,NULL,hHookAdjustTokenPrivileges);
		LhSetExclusiveACL(HookAdjustTokenPrivileges_ACLEntries, 1, hHookAdjustTokenPrivileges);
	}
	if (api[25]==1&&realAttachThreadInput!=NULL)
	{
		LhInstallHook(realAttachThreadInput,MyAttachThreadInput,NULL,hHookAttachThreadInput);
		LhSetExclusiveACL(HookAttachThreadInput_ACLEntries, 1, hHookAttachThreadInput);
	}
	if (api[26]==1&&realCallNextHookEx!=NULL)
	{
		LhInstallHook(realCallNextHookEx,MyCallNextHookEx,NULL,hHookCallNextHookEx);
		LhSetExclusiveACL(HookCallNextHookEx_ACLEntries, 1, hHookCallNextHookEx);
	}
	if (api[27]==1&&realCheckRemoteDebuggerPresent!=NULL)
	{
		LhInstallHook(realCheckRemoteDebuggerPresent,MyCheckRemoteDebuggerPresent,NULL,hHookCheckRemoteDebuggerPresent);
		LhSetExclusiveACL(HookCheckRemoteDebuggerPresent_ACLEntries, 1, hHookCheckRemoteDebuggerPresent);
	}
	if (api[28]==1&&realControlService!=NULL)
	{
		LhInstallHook(realControlService,MyControlService,NULL,hHookControlService);
		LhSetExclusiveACL(HookControlService_ACLEntries, 1, hHookControlService);
	}
	if (api[29]==1&&realCreateRemoteThread!=NULL)
	{
		LhInstallHook(realCreateRemoteThread,MyCreateRemoteThread,NULL,hHookCreateRemoteThread);
		LhSetExclusiveACL(HookCreateRemoteThread_ACLEntries, 1, hHookCreateRemoteThread);
	}
	if (api[30]==1&&realCreateToolhelp32Snapshot!=NULL)
	{
		LhInstallHook(realCreateToolhelp32Snapshot,MyCreateToolhelp32Snapshot,NULL,hHookCreateToolhelp32Snapshot);
		LhSetExclusiveACL(HookCreateToolhelp32Snapshot_ACLEntries, 1, hHookCreateToolhelp32Snapshot);
	}
	//问题在下面
	if (api[31]==1&&realEnumProcesses!=NULL)
	{
		LhInstallHook(realEnumProcesses,MyEnumProcesses,NULL,hHookEnumProcesses);
		LhSetExclusiveACL(HookEnumProcesses_ACLEntries, 1, hHookEnumProcesses);
	}
	if (api[32]==1&&realEnumProcessModules!=NULL)
	{
		LhInstallHook(realEnumProcessModules,MyEnumProcessModules,NULL,hHookEnumProcessModules);
		LhSetExclusiveACL(HookEnumProcessModules_ACLEntries, 1, hHookEnumProcessModules);
	}
	if (api[33]==1&&realGetProcAddress!=NULL)
	{
		//LhInstallHook(realGetProcAddress,MyGetProcAddress,NULL,hHookGetProcAddress);
		//LhSetExclusiveACL(HookGetProcAddress_ACLEntries, 1, hHookGetProcAddress);
	}
	if (api[34]==1&&realGetSystemDefaultLangID!=NULL)
	{
		LhInstallHook(realGetSystemDefaultLangID,MyGetSystemDefaultLangID,NULL,hHookGetSystemDefaultLangID);
		LhSetExclusiveACL(HookGetSystemDefaultLangID_ACLEntries, 1, hHookGetSystemDefaultLangID);
	}
	if (api[35]==1&&realGetThreadContext!=NULL)////导致Explorer.exe崩溃,执行GetThreadId(hThread)发生崩溃
	{
		//LhInstallHook(realGetThreadContext,MyGetThreadContext,NULL,hHookGetThreadContext);
		//LhSetExclusiveACL(HookGetThreadContext_ACLEntries, 1, hHookGetThreadContext);
	}
    if (api[36]==1&&realGetTickCount!=NULL)
	{
		LhInstallHook(realGetTickCount,MyGetTickCount,NULL,hHookGetTickCount);
		LhSetExclusiveACL(HookGetTickCount_ACLEntries, 1, hHookGetTickCount);
	}
    if (api[37]==1&&realIsDebuggerPresent!=NULL)
	{
		LhInstallHook(realIsDebuggerPresent,MyIsDebuggerPresent,NULL,hHookIsDebuggerPresent);
		LhSetExclusiveACL(HookIsDebuggerPresent_ACLEntries, 1, hHookIsDebuggerPresent);
	}
    if (api[38]==1&&realLoadLibraryEx!=NULL)
	{
		LhInstallHook(realLoadLibraryEx,MyLoadLibraryEx,NULL,hHookLoadLibraryEx);
		LhSetExclusiveACL(HookLoadLibraryEx_ACLEntries, 1, hHookLoadLibraryEx);
	}
    if (api[39]==1&&realLoadResource!=NULL)
	{
		LhInstallHook(realLoadResource,MyLoadResource,NULL,hHookLoadResource);
		LhSetExclusiveACL(HookLoadResource_ACLEntries, 1, hHookLoadResource);
	}
    if (api[40]==1&&realModule32FirstW!=NULL)
	{
		LhInstallHook(realModule32FirstW,MyModule32FirstW,NULL,hHookModule32FirstW);
		LhSetExclusiveACL(HookModule32FirstW_ACLEntries, 1, hHookModule32FirstW);
	}
    if (api[41]==1&&realModule32NextW!=NULL)
	{
		LhInstallHook(realModule32NextW,MyModule32NextW,NULL,hHookModule32NextW);
		LhSetExclusiveACL(HookModule32NextW_ACLEntries, 1, hHookModule32NextW);
	}
	if (api[42]==1&&realOpenProcess!=NULL)
	{
		LhInstallHook(realOpenProcess,MyOpenProcess,NULL,hHookOpenProcess);
		LhSetExclusiveACL(HookOpenProcess_ACLEntries, 1, hHookOpenProcess);
	}
	if (api[43]==1&&realPeekNamedPipe!=NULL)
	{
		LhInstallHook(realPeekNamedPipe,MyPeekNamedPipe,NULL,hHookPeekNamedPipe);
		LhSetExclusiveACL(HookPeekNamedPipe_ACLEntries, 1, hHookPeekNamedPipe);
	}
	if (api[44]==1&&realProcess32First!=NULL)
	{
		LhInstallHook(realProcess32First,MyProcess32First,NULL,hHookProcess32First);
		LhSetExclusiveACL(HookProcess32First_ACLEntries, 1, hHookProcess32First);
	}
	//问题在下面
	if (api[45]==1&&realProcess32Next!=NULL)
	{
		LhInstallHook(realProcess32Next,MyProcess32Next,NULL,hHookProcess32Next);
		LhSetExclusiveACL(HookProcess32Next_ACLEntries, 1, hHookProcess32Next);
	}
	if (api[46]==1&&realQueryPerformanceCounter!=NULL)
	{
		LhInstallHook(realQueryPerformanceCounter,MyQueryPerformanceCounter,NULL,hHookQueryPerformanceCounter);
		LhSetExclusiveACL(HookQueryPerformanceCounter_ACLEntries, 1, hHookQueryPerformanceCounter);
	}
	if (api[47]==1&&realQueueUserAPC!=NULL)
	{
		LhInstallHook(realQueueUserAPC,MyQueueUserAPC,NULL,hHookQueueUserAPC);
		LhSetExclusiveACL(HookQueueUserAPC_ACLEntries, 1, hHookQueueUserAPC);
	}
	if (api[48]==1&&realReadProcessMemory!=NULL)
	{
		LhInstallHook(realReadProcessMemory,MyReadProcessMemory,NULL,hHookReadProcessMemory);
		LhSetExclusiveACL(HookReadProcessMemory_ACLEntries, 1, hHookReadProcessMemory);
	}
	if (api[49]==1&&realResumeThread!=NULL)
	{
		LhInstallHook(realResumeThread,MyResumeThread,NULL,hHookResumeThread);
		LhSetExclusiveACL(HookResumeThread_ACLEntries, 1, hHookResumeThread);
	}
	if (api[50]==1&&realSetThreadContext!=NULL)
	{
		LhInstallHook(realSetThreadContext,MySetThreadContext,NULL,hHookSetThreadContext);
		LhSetExclusiveACL(HookSetThreadContext_ACLEntries, 1, hHookSetThreadContext);
	}
	if (api[51]==1&&realSuspendThread!=NULL)
	{
		LhInstallHook(realSuspendThread,MySuspendThread,NULL,hHookSuspendThread);
		LhSetExclusiveACL(HookSuspendThread_ACLEntries, 1, hHookSuspendThread);
	}
	if (api[52]==1&&realThread32First!=NULL)
	{
		LhInstallHook(realThread32First,MyThread32First,NULL,hHookThread32First);
		LhSetExclusiveACL(HookThread32First_ACLEntries, 1, hHookThread32First);
	}
	if (api[53]==1&&realThread32Next!=NULL)
	{
		LhInstallHook(realThread32Next,MyThread32Next,NULL,hHookThread32Next);
		LhSetExclusiveACL(HookThread32Next_ACLEntries, 1, hHookThread32Next);
	}
	if (api[54]==1&&realToolhelp32ReadProcessMemory!=NULL)
	{
		LhInstallHook(realToolhelp32ReadProcessMemory,MyToolhelp32ReadProcessMemory,NULL,hHookToolhelp32ReadProcessMemory);
		LhSetExclusiveACL(HookToolhelp32ReadProcessMemory_ACLEntries, 1, hHookToolhelp32ReadProcessMemory);
	}
	if (api[55]==1&&realVirtualAllocEx!=NULL)
	{
		LhInstallHook(realVirtualAllocEx,MyVirtualAllocEx,NULL,hHookVirtualAllocEx);
		LhSetExclusiveACL(HookVirtualAllocEx_ACLEntries, 1, hHookVirtualAllocEx);
	}
	if (api[56]==1&&realVirtualProtectEx!=NULL)
	{
		LhInstallHook(realVirtualProtectEx,MyVirtualProtectEx,NULL,hHookVirtualProtectEx);
		LhSetExclusiveACL(HookVirtualProtectEx_ACLEntries, 1, hHookVirtualProtectEx);
	}
	if (api[57]==1&&realWinExec!=NULL)
	{
		LhInstallHook(realWinExec,MyWinExec,NULL,hHookWinExec);
		LhSetExclusiveACL(HookWinExec_ACLEntries, 1, hHookWinExec);
	}
	if (api[58]==1&&realWriteProcessMemory!=NULL)
	{
		LhInstallHook(realWriteProcessMemory,MyWriteProcessMemory,NULL,hHookWriteProcessMemory);
		LhSetExclusiveACL(HookWriteProcessMemory_ACLEntries, 1, hHookWriteProcessMemory);
	}
	if (api[59]==1&&realRegisterHotKey!=NULL)//抛出异常点：0x000000007757CD02 (user32.dll) (explorer.exe 中)处的第一机会异常: 0xC0000005: 写入位置 0x000007FEED531B10 时发生访问冲突。
	{
		//LhInstallHook(realRegisterHotKey,MyRegisterHotKey,NULL,hHookRegisterHotKey);
		//LhSetExclusiveACL(HookRegisterHotKey_ACLEntries, 1, hHookRegisterHotKey);
	}
	if (api[60]==1&&realCreateProcessA!=NULL)
	{
		//LhInstallHook(realCreateProcessA,MyCreateProcessA,NULL,hHookCreateProcessA);
		//LhSetExclusiveACL(HookCreateProcessA_ACLEntries, 1, hHookCreateProcessA);
	}
	if (api[61]==1&&realCertOpenSystemStoreW!=NULL)
	{
		LhInstallHook(realCertOpenSystemStoreW,MyCertOpenSystemStoreW,NULL,hHookCertOpenSystemStoreW);
		LhSetExclusiveACL(HookCertOpenSystemStoreW_ACLEntries, 1, hHookCertOpenSystemStoreW);
	}
	
	if (api[62]==1&&realCreateMutexW!=NULL)
	{
		LhInstallHook(realCreateMutexW,MyCreateMutexW,NULL,hHookCreateMutexW);
		LhSetExclusiveACL(HookCreateMutexW_ACLEntries, 1, hHookCreateMutexW);
	}
	if (api[63]==1&&realFindResourceW!=NULL) //导致Explorer.exe崩溃
	{
		//LhInstallHook(realFindResourceW,MyFindResourceW,NULL,hHookFindResourceW);
		//LhSetExclusiveACL(HookFindResourceW_ACLEntries, 1, hHookFindResourceW);
	}
	if (api[64]==1&&realFindWindowW!=NULL)
	{
		LhInstallHook(realFindWindowW,MyFindWindowW,NULL,hHookFindWindowW);
		LhSetExclusiveACL(HookFindWindowW_ACLEntries, 1, hHookFindWindowW);
	}
	
	if (api[65]==1&&realGetWindowsDirectoryW!=NULL)
	{
		LhInstallHook(realGetWindowsDirectoryW,MyGetWindowsDirectoryW,NULL,hHookGetWindowsDirectoryW);
		LhSetExclusiveACL(HookGetWindowsDirectoryW_ACLEntries, 1, hHookGetWindowsDirectoryW);
	}
	//问题在下面
	if (api[66]==1&&realMapVirtualKeyW!=NULL)
	{
		LhInstallHook(realMapVirtualKeyW,MyMapVirtualKeyW,NULL,hHookMapVirtualKeyW);
		LhSetExclusiveACL(HookMapVirtualKeyW_ACLEntries, 1, hHookMapVirtualKeyW);
	}
	if (api[67]==1&&realOpenMutexW!=NULL)
	{
		LhInstallHook(realOpenMutexW,MyOpenMutexW,NULL,hHookOpenMutexW);
		LhSetExclusiveACL(HookOpenMutexW_ACLEntries, 1, hHookOpenMutexW);
	}
	if (api[68]==1&&realOpenSCManagerW!=NULL)
	{
		LhInstallHook(realOpenSCManagerW,MyOpenSCManagerW,NULL,hHookOpenSCManagerW);
		LhSetExclusiveACL(HookOpenSCManagerW_ACLEntries, 1, hHookOpenSCManagerW);
	}
	if (api[69]==1&&realCreateProcessW!=NULL)
	{
		//LhInstallHook(realCreateProcessW,MyCreateProcessW,NULL,hHookCreateProcessW);
		//LhSetExclusiveACL(HookCreateProcessW_ACLEntries, 1, hHookCreateProcessW);
	}
	if (api[70]==1&&realCreateServiceW!=NULL)
	{
		LhInstallHook(realCreateServiceW,MyCreateServiceW,NULL,hHookCreateServiceW);
		LhSetExclusiveACL(HookCreateServiceW_ACLEntries, 1, hHookCreateServiceW);
	}
	if (api[71]==1&&realGetModuleFileNameExW!=NULL)
	{
		LhInstallHook(realGetModuleFileNameExW,MyGetModuleFileNameExW,NULL,hHookGetModuleFileNameExW);
		LhSetExclusiveACL(HookGetModuleFileNameExW_ACLEntries, 1, hHookGetModuleFileNameExW);
	}
	if (api[72]==1&&realGetModuleHandleW!=NULL)
	{
		LhInstallHook(realGetModuleHandleW,MyGetModuleHandleW,NULL,hHookGetModuleHandleW);
		LhSetExclusiveACL(HookGetModuleHandleW_ACLEntries, 1, hHookGetModuleHandleW);
	}
	//问题在下面
	if (api[73]==1&&realGetStartupInfoW!=NULL)
	{
		LhInstallHook(realGetStartupInfoW,MyGetStartupInfoW,NULL,hHookGetStartupInfoW);
		LhSetExclusiveACL(HookGetStartupInfoW_ACLEntries, 1, hHookGetStartupInfoW);
	}
	if (api[74]==1&&realGetVersionExW!=NULL)
	{
		LhInstallHook(realGetVersionExW,MyGetVersionExW,NULL,hHookGetVersionExW);
		LhSetExclusiveACL(HookGetVersionExW_ACLEntries, 1, hHookGetVersionExW);
	}
	if (api[75]==1&&realLoadLibraryW!=NULL)
	{
		LhInstallHook(realLoadLibraryW,MyLoadLibraryW,NULL,hHookLoadLibraryW);
		LhSetExclusiveACL(HookLoadLibraryW_ACLEntries, 1, hHookLoadLibraryW);
	}
	if (api[76]==1&&realOutputDebugStringW!=NULL)
	{
		LhInstallHook(realOutputDebugStringW,MyOutputDebugStringW,NULL,hHookOutputDebugStringW);
		LhSetExclusiveACL(HookOutputDebugStringW_ACLEntries, 1, hHookOutputDebugStringW);
	}
	if (api[77]==1&&realSetWindowsHookExW!=NULL)
	{
		LhInstallHook(realSetWindowsHookExW,MySetWindowsHookExW,NULL,hHookSetWindowsHookExW);
		LhSetExclusiveACL(HookSetWindowsHookExW_ACLEntries, 1, hHookSetWindowsHookExW);
	}
	
	if (api[78]==1&&realShellExecuteW!=NULL)
	{
		LhInstallHook(realShellExecuteW,MyShellExecuteW,NULL,hHookShellExecuteW);
		LhSetExclusiveACL(HookShellExecuteW_ACLEntries, 1, hHookShellExecuteW);
	}
	
	if (api[79]==1&&realStartServiceCtrlDispatcherW!=NULL)
	{
		LhInstallHook(realStartServiceCtrlDispatcherW,MyStartServiceCtrlDispatcherW,NULL,hHookStartServiceCtrlDispatcherW);
		LhSetExclusiveACL(HookStartServiceCtrlDispatcherW_ACLEntries, 1, hHookStartServiceCtrlDispatcherW);
	}
	if (api[80]==1&&realSetLocalTime!=NULL)
	{
		LhInstallHook(realSetLocalTime,MySetLocalTime,NULL,hHookSetLocalTime);
		LhSetExclusiveACL(HookSetLocalTime_ACLEntries, 1, hHookSetLocalTime);
	}
	if (api[81]==1&&realTerminateThread!=NULL)
	{
		LhInstallHook(realTerminateThread,MyTerminateThread,NULL,hHookTerminateThread);
		LhSetExclusiveACL(HookTerminateThread_ACLEntries, 1, hHookTerminateThread);
	}
	if (api[82]==1&&realVirtualFree!=NULL)
	{
		LhInstallHook(realVirtualFree,MyVirtualFree,NULL,hHookVirtualFree);
		LhSetExclusiveACL(HookVirtualFree_ACLEntries, 1, hHookVirtualFree);
	}
	if (api[83]==1&&realSetProcessWorkingSetSize!=NULL)
	{
		LhInstallHook(realSetProcessWorkingSetSize,MySetProcessWorkingSetSize,NULL,hHookSetProcessWorkingSetSize);
		LhSetExclusiveACL(HookSetProcessWorkingSetSize_ACLEntries, 1, hHookSetProcessWorkingSetSize);
	}
	if (api[84]==1&&realTerminateProcess!=NULL)
	{
		LhInstallHook(realTerminateProcess,MyTerminateProcess,NULL,hHookTerminateProcess);
		LhSetExclusiveACL(HookTerminateProcess_ACLEntries, 1, hHookTerminateProcess);
	}
	//下面没有问题
	//注册表
	if (api[85]==1&&realRegOpenKeyEx!=NULL)
	{
		LhInstallHook(realRegOpenKeyEx,MyRegOpenKeyEx,NULL,hHookRegOpenKeyEx);
		LhSetExclusiveACL(HookRegOpenKeyEx_ACLEntries, 1, hHookRegOpenKeyEx);
	}
	if (api[86]==1&&realRegOpenKeyW!=NULL)
	{
		LhInstallHook(realRegOpenKeyW,MyRegOpenKeyW,NULL,hHookRegOpenKeyW);
		LhSetExclusiveACL(HookRegOpenKeyW_ACLEntries, 1, hHookRegOpenKeyW);
	}
	if (api[87]==1&&realRegCreateKeyExW!=NULL)
	{
		LhInstallHook(realRegCreateKeyExW,MyRegCreateKeyExW,NULL,hHookRegCreateKeyExW);
		LhSetExclusiveACL(HookRegCreateKeyExW_ACLEntries, 1, hHookRegCreateKeyExW);
	}
	if (api[88]==1&&realRegCreateKeyW!=NULL)
	{
		LhInstallHook(realRegCreateKeyW,MyRegCreateKeyW,NULL,hHookRegCreateKeyW);
		LhSetExclusiveACL(HookRegCreateKeyW_ACLEntries, 1, hHookRegCreateKeyW);
	}
	if (api[89]==1&&realRegQueryValueExW!=NULL)
	{
		LhInstallHook(realRegQueryValueExW,MyRegQueryValueExW,NULL,hHookRegQueryValueExW);
		LhSetExclusiveACL(HookRegQueryValueExW_ACLEntries, 1, hHookRegQueryValueExW);
	}
	if (api[90]==1&&realRegQueryValueW!=NULL)
	{
		LhInstallHook(realRegQueryValueW,MyRegQueryValueW,NULL,hHookRegQueryValueW);
		LhSetExclusiveACL(HookRegQueryValueW_ACLEntries, 1, hHookRegQueryValueW);
	}
	if (api[91]==1&&realRegSetValueExW!=NULL)
	{
		LhInstallHook(realRegSetValueExW,MyRegSetValueExW,NULL,hHookRegSetValueExW);
		LhSetExclusiveACL(HookRegSetValueExW_ACLEntries, 1, hHookRegSetValueExW);
	}
	if (api[92]==1&&realRegSetValueW!=NULL)
	{
		LhInstallHook(realRegSetValueW,MyRegSetValueW,NULL,hHookRegSetValueW);
		LhSetExclusiveACL(HookRegSetValueW_ACLEntries, 1, hHookRegSetValueW);
	}
	if (api[93]==1&&realRegDeleteKeyExW!=NULL)
	{
		LhInstallHook(realRegDeleteKeyExW,MyRegDeleteKeyExW,NULL,hHookRegDeleteKeyExW);
		LhSetExclusiveACL(HookRegDeleteKeyExW_ACLEntries, 1, hHookRegDeleteKeyExW);
	}
	if (api[94]==1&&realRegDeleteKeyW!=NULL)
	{
		LhInstallHook(realRegDeleteKeyW,MyRegDeleteKeyW,NULL,hHookRegDeleteKeyW);
		LhSetExclusiveACL(HookRegDeleteKeyW_ACLEntries, 1, hHookRegDeleteKeyW);
	}
	if (api[95]==1&&realRegSetKeySecurity!=NULL)
	{
		LhInstallHook(realRegSetKeySecurity,MyRegSetKeySecurity,NULL,hHookRegSetKeySecurity);
		LhSetExclusiveACL(HookRegSetKeySecurity_ACLEntries, 1, hHookRegSetKeySecurity);
	}
	if (api[96]==1&&realRegRestoreKey!=NULL)
	{
		LhInstallHook(realRegRestoreKey,MyRegRestoreKey,NULL,hHookRegRestoreKey);
		LhSetExclusiveACL(HookRegRestoreKey_ACLEntries, 1, hHookRegRestoreKey);
	}
	if (api[97]==1&&realRegReplaceKey!=NULL)
	{
		LhInstallHook(realRegReplaceKey,MyRegReplaceKey,NULL,hHookRegReplaceKey);
		LhSetExclusiveACL(HookRegReplaceKey_ACLEntries, 1, hHookRegReplaceKey);
	}
	if (api[98]==1&&realRegLoadKey!=NULL)
	{
		LhInstallHook(realRegLoadKey,MyRegLoadKey,NULL,hHookRegLoadKey);
		LhSetExclusiveACL(HookRegLoadKey_ACLEntries, 1, hHookRegLoadKey);
	}
	if (api[99]==1&&realRegUnLoadKey!=NULL)
	{
		LhInstallHook(realRegUnLoadKey,MyRegUnLoadKey,NULL,hHookRegUnLoadKey);
		LhSetExclusiveACL(HookRegUnLoadKey_ACLEntries, 1, hHookRegUnLoadKey);
	}
	//网络相关API
	if (api[100]==1&&realaccept!=NULL)
	{
		LhInstallHook(realaccept,Myaccept,NULL,hHookaccept);
		LhSetExclusiveACL(Hookaccept_ACLEntries, 1, hHookaccept);
	}
	if (api[101]==1&&realsend!=NULL)
	{
		LhInstallHook(realsend,Mysend,NULL,hHooksend);
		LhSetExclusiveACL(Hooksend_ACLEntries, 1, hHooksend);
	}
	if (api[102]==1&&realbind!=NULL)
	{
		LhInstallHook(realbind,Mybind,NULL,hHookbind);
		LhSetExclusiveACL(Hookbind_ACLEntries, 1, hHookbind);
	}
	if (api[103]==1&&realconnect!=NULL)
	{
		LhInstallHook(realconnect,Myconnect,NULL,hHookconnect);
		LhSetExclusiveACL(Hookconnect_ACLEntries, 1, hHookconnect);
	}
	if (api[104]==1&&realConnectNamedPipe!=NULL)
	{
		LhInstallHook(realConnectNamedPipe,MyConnectNamedPipe,NULL,hHookConnectNamedPipe);
		LhSetExclusiveACL(HookConnectNamedPipe_ACLEntries, 1, hHookConnectNamedPipe);
	}
	
	//if (api[105]==1&&realGetAdaptersInfo!=NULL)
	//{
		//LhInstallHook(realGetAdaptersInfo,MyGetAdaptersInfo,NULL,hHookGetAdaptersInfo);
		//LhSetExclusiveACL(HookGetAdaptersInfo_ACLEntries, 1, hHookGetAdaptersInfo);
	//}
	if (api[106]==1&&realgethostname!=NULL)
	{
		LhInstallHook(realgethostname,Mygethostname,NULL,hHookgethostname);
		LhSetExclusiveACL(Hookgethostname_ACLEntries, 1, hHookgethostname);
	}
	if (api[107]==1&&realinet_addr!=NULL)
	{
		LhInstallHook(realinet_addr,Myinet_addr,NULL,hHookinet_addr);
		LhSetExclusiveACL(Hookinet_addr_ACLEntries, 1, hHookinet_addr);
	}
	if (api[108]==1&&realInternetReadFile!=NULL)
	{
		OutputDebugStringA("InternetReadFile is ok\n");
		LhInstallHook(realInternetReadFile,MyInternetReadFile,NULL,hHookInternetReadFile);
		LhSetExclusiveACL(HookInternetReadFile_ACLEntries, 1, hHookInternetReadFile);
	}
	if (api[109]==1&&realInternetWriteFile!=NULL)
	{
		OutputDebugStringA("InternetWriteFile is ok\n");
		LhInstallHook(realInternetWriteFile,MyInternetWriteFile,NULL,hHookInternetWriteFile);
		LhSetExclusiveACL(HookInternetWriteFile_ACLEntries, 1, hHookInternetWriteFile);
	}
	if (api[110]==1&&realNetShareEnum!=NULL)
	{
		LhInstallHook(realNetShareEnum,MyNetShareEnum,NULL,hHookNetShareEnum);
		LhSetExclusiveACL(HookNetShareEnum_ACLEntries, 1, hHookNetShareEnum);
	}
	if (api[111]==1&&realrecv!=NULL)
	{
		LhInstallHook(realrecv,Myrecv,NULL,hHookrecv);
		LhSetExclusiveACL(Hookrecv_ACLEntries, 1, hHookrecv);
	}
	if (api[112]==1&&realWSAStartup!=NULL)
	{
		//LhInstallHook(realWSAStartup,MyWSAStartup,NULL,hHookWSAStartup);
		//LhSetExclusiveACL(HookWSAStartup_ACLEntries, 1, hHookWSAStartup);
	}
	if (api[113]==1&&realInternetOpenW!=NULL)
	{
		LhInstallHook(realInternetOpenW,MyInternetOpenW,NULL,hHookInternetOpenW);
		LhSetExclusiveACL(HookInternetOpenW_ACLEntries, 1, hHookInternetOpenW);
	}
	if (api[114]==1&&realInternetOpenUrlW!=NULL)
	{
		OutputDebugStringA("InternetOpenUrlW is ok");
		LhInstallHook(realInternetOpenUrlW,MyInternetOpenUrlW,NULL,hHookInternetOpenUrlW);
		LhSetExclusiveACL(HookInternetOpenUrlW_ACLEntries, 1, hHookInternetOpenUrlW);
	}
	if (api[115]==1&&realURLDownloadToFileW!=NULL)
	{
		LhInstallHook(realURLDownloadToFileW,MyURLDownloadToFileW,NULL,hHookURLDownloadToFileW);
		LhSetExclusiveACL(HookURLDownloadToFileW_ACLEntries, 1, hHookURLDownloadToFileW);
	}
	if (api[116]==1&&realFtpPutFileW!=NULL)
	{
		LhInstallHook(realFtpPutFileW,MyFtpPutFileW,NULL,hHookFtpPutFileW);
		LhSetExclusiveACL(HookFtpPutFileW_ACLEntries, 1, hHookFtpPutFileW);
	}
	if (api[117]==1&&realHttpSendRequest!=NULL)
	{
		OutputDebugStringA("HttpSendRequestW is ok\n");
		LhInstallHook(realHttpSendRequest,MyHttpSendRequest,NULL,hHookHttpSendRequest);
		LhSetExclusiveACL(HookHttpSendRequest_ACLEntries, 1, hHookHttpSendRequest);
	}
	if (api[118]==1&&realHttpSendRequestEx!=NULL)
	{
		OutputDebugStringA("HttpSendRequestExW is ok\n");
		LhInstallHook(realHttpSendRequestEx,MyHttpSendRequestEx,NULL,hHookHttpSendRequestEx);
		LhSetExclusiveACL(HookHttpSendRequestEx_ACLEntries, 1, hHookHttpSendRequestEx);
	}
	if (api[119]==1&&realHttpOpenRequest!=NULL)
	{
		LhInstallHook(realHttpOpenRequest,MyHttpOpenRequest,NULL,hHookHttpOpenRequest);
		LhSetExclusiveACL(HookHttpOpenRequest_ACLEntries, 1, hHookHttpOpenRequest);
	}
	if (api[120]==1&&realInternetConnect!=NULL)
	{
		LhInstallHook(realInternetConnect,MyInternetConnect,NULL,hHookInternetConnect);
		LhSetExclusiveACL(HookInternetConnect_ACLEntries, 1, hHookInternetConnect);
	}
	if (api[121]==1&&reallisten!=NULL)
	{
		LhInstallHook(reallisten,Mylisten,NULL,hHooklisten);
		LhSetExclusiveACL(Hooklisten_ACLEntries, 1, hHooklisten);
	}
	if (api[122]==1&&realInternetOpenUrlA!=NULL)
	{
		LhInstallHook(realInternetOpenUrlA,MyInternetOpenUrlA,NULL,hHookInternetOpenUrlA);
		LhSetExclusiveACL(HookInternetOpenUrlA_ACLEntries,1,hHookInternetOpenUrlA);
	}
	if (api[123]==1&&realHttpOpenRequestA!=NULL)
	{
		LhInstallHook(realHttpOpenRequestA,MyHttpOpenRequestA,NULL,hHookHttpOpenRequestA);
		LhSetExclusiveACL(HookHttpOpenRequestA_ACLEntries,1,hHookHttpOpenRequestA);
	}
}  

void DoneHook()  
{  
	OutputDebugString(L"DoneHook()\n");  

	// this will also invalidate "hHook", because it is a traced handle...  
	LhUninstallAllHooks();  

	// this will do nothing because the hook is already removed...  
	LhUninstallHook(hHookCreateFileA);  
	LhUninstallHook(hHookReadFile);

	//文件API
	if (api[0]==1&&realCreateFileW!=NULL)
	{
		//LhUninstallHook(hHookCreateFileW);
		//delete hHookCreateFileW;
		//hHookCreateFileW=NULL;
	}
	if (api[1]==1&&realMoveFileW!=NULL)
	{
		LhUninstallHook(hHookMoveFileW);
		delete hHookMoveFileW;
		hHookMoveFileW=NULL;
	}
	if (api[2]==1&&realCopyFileW!=NULL)
	{
		LhUninstallHook(hHookCopyFileW);
		delete hHookCopyFileW;
		hHookCopyFileW=NULL;
	}
	if (api[3]==1&&realDeleteFileW!=NULL)
	{
		LhUninstallHook(hHookDeleteFileW);
		delete hHookDeleteFileW;
		hHookDeleteFileW=NULL;
	}
	if (api[4]==1&&realFindFirstFileW!=NULL)
	{
		LhUninstallHook(hHookFindFirstFileW);
		delete hHookFindFirstFileW;
		hHookFindFirstFileW=NULL;
	}
	if (api[5]==1&&realFindNextFileW!=NULL)
	{
		LhUninstallHook(hHookFindNextFileW);
		delete hHookFindNextFileW;
		hHookFindNextFileW=NULL;
	}
	if (api[6]==1&&realSetFileAttributesW!=NULL)
	{
		LhUninstallHook(hHookSetFileAttributesW);
		delete hHookSetFileAttributesW;
		hHookSetFileAttributesW=NULL;
	}
	if (api[7]==1&&realCreateHardLinkW!=NULL)
	{
		LhUninstallHook(hHookCreateHardLinkW);
		delete hHookCreateHardLinkW;
		hHookCreateHardLinkW=NULL;
	}
	if (api[8]==1&&realSetEndOfFile!=NULL)
	{
		LhUninstallHook(hHookSetEndOfFile);
		delete hHookSetEndOfFile;
		hHookSetEndOfFile=NULL;
	}
	if (api[9]==1&&realSetFileValidData!=NULL)
	{
		LhUninstallHook(hHookSetFileValidData);
		delete hHookSetFileValidData;
		hHookSetFileValidData=NULL;
	}
	if (api[10]==1&&realSetFileTime!=NULL)
	{
		LhUninstallHook(hHookSetFileTime);
		delete hHookSetFileTime;
		hHookSetFileTime=NULL;
	}

	//进程API
	if (api[11]==1&&realBitBlt!=NULL)
	{
		LhUninstallHook(hHookBitBlt);
		delete hHookBitBlt;
		hHookBitBlt=NULL;
	}
	/*
	if (api[12]==1&&realCoCreateInstance!=NULL)
	{
		LhUninstallHook(hHookCoCreateInstance);
		delete hHookCoCreateInstance;
		hHookCoCreateInstance=NULL;
	}*/
    if (api[13]==1&&realCreateFileMapping!=NULL)
	{
		LhUninstallHook(hHookCreateFileMapping);
		delete hHookCreateFileMapping;
		hHookCreateFileMapping=NULL;
	}
	
    if (api[14]==1&&realCryptAcquireContext!=NULL)
	{
		LhUninstallHook(hHookCryptAcquireContext);
		delete hHookCryptAcquireContext;
		hHookCryptAcquireContext=NULL;
	}
    if (api[15]==1&&realDeviceIoControl!=NULL)
	{
		LhUninstallHook(hHookDeviceIoControl);
		delete hHookDeviceIoControl;
		hHookDeviceIoControl=NULL;
	}
    if (api[16]==1&&realFindWindowEx!=NULL)
	{
		LhUninstallHook(hHookFindWindowEx);
		delete hHookFindWindowEx;
		hHookFindWindowEx=NULL;
    } 
    if (api[17]==1&&realGetAsyncKeyState!=NULL)
	{
		LhUninstallHook(hHookGetAsyncKeyState);
		delete hHookGetAsyncKeyState;
		hHookGetAsyncKeyState=NULL;
	}
    if (api[18]==1&&realGetDC!=NULL)
	{
		LhUninstallHook(hHookGetDC);
		delete hHookGetDC;
		hHookGetDC=NULL;
	}
    if (api[19]==1&&realGetForegroundWindow!=NULL)
	{
		LhUninstallHook(hHookGetForegroundWindow);
		delete hHookGetForegroundWindow;
		hHookGetForegroundWindow=NULL;
	}
    if (api[20]==1&&realGetKeyState!=NULL)
	{
		LhUninstallHook(hHookGetKeyState);
		delete hHookGetKeyState;
		hHookGetKeyState=NULL;
	}
    if (api[21]==1&&realGetTempPath!=NULL)
	{
		LhUninstallHook(hHookGetTempPath);
		delete hHookGetTempPath;
		hHookGetTempPath=NULL;
	}
    if (api[22]==1&&realMapViewOfFile!=NULL)
	{
		LhUninstallHook(hHookMapViewOfFile);
		delete hHookMapViewOfFile;
		hHookMapViewOfFile=NULL;
	}
    if (api[23]==1&&realOpenFile!=NULL)
	{
		LhUninstallHook(hHookOpenFile);
		delete hHookOpenFile;
		hHookOpenFile=NULL;
	}
    if (api[24]==1&&realAdjustTokenPrivileges!=NULL)
	{
		LhUninstallHook(hHookAdjustTokenPrivileges);
		delete hHookAdjustTokenPrivileges;
		hHookAdjustTokenPrivileges=NULL;
	}
    if (api[25]==1&&realAttachThreadInput!=NULL)
	{
		LhUninstallHook(hHookAttachThreadInput);
		delete hHookAttachThreadInput;
		hHookAttachThreadInput=NULL;
	}
    if (api[26]==1&&realCallNextHookEx!=NULL)
	{
		LhUninstallHook(hHookCallNextHookEx);
		delete hHookCallNextHookEx;
		hHookCallNextHookEx=NULL;
	}
    if (api[27]==1&&realCheckRemoteDebuggerPresent!=NULL)
	{
		LhUninstallHook(hHookCheckRemoteDebuggerPresent);
		delete hHookCheckRemoteDebuggerPresent;
		hHookCheckRemoteDebuggerPresent=NULL;
	}
    if (api[28]==1&&realControlService!=NULL)
	{
		LhUninstallHook(hHookControlService);
		delete hHookControlService;
		hHookControlService=NULL;
	}
    if (api[29]==1&&realCreateRemoteThread!=NULL)
	{
		LhUninstallHook(hHookCreateRemoteThread);
		delete hHookCreateRemoteThread;
		hHookCreateRemoteThread=NULL;
	}
    if (api[30]==1&&realCreateToolhelp32Snapshot!=NULL)
	{
		LhUninstallHook(hHookCreateToolhelp32Snapshot);
		delete hHookCreateToolhelp32Snapshot;
		hHookCreateToolhelp32Snapshot=NULL;
	}
    if (api[31]==1&&realEnumProcesses!=NULL)
	{
		LhUninstallHook(hHookEnumProcesses);
		delete hHookEnumProcesses;
		hHookEnumProcesses=NULL;
	}
    if (api[32]==1&&realEnumProcessModules!=NULL)
	{
		LhUninstallHook(hHookEnumProcessModules);
		delete hHookEnumProcessModules;
		hHookEnumProcessModules=NULL;
	}
	/*
    if (api[33]==1&&realGetProcAddress!=NULL)
	{
		LhUninstallHook(hHookGetProcAddress);
		delete hHookGetProcAddress;
		hHookGetProcAddress=NULL;
	}
	*/
    if (api[34]==1&&realGetSystemDefaultLangID!=NULL)
	{
		LhUninstallHook(hHookGetSystemDefaultLangID);
		delete hHookGetSystemDefaultLangID;
		hHookGetSystemDefaultLangID=NULL;
	}
    if (api[35]==1&&realGetThreadContext!=NULL)
	{
		LhUninstallHook(hHookGetThreadContext);
		delete hHookGetThreadContext;
		hHookGetThreadContext=NULL;
	}
    
    if (api[36]==1&&realGetTickCount!=NULL)
	{
		LhUninstallHook(hHookGetTickCount);
		delete hHookGetTickCount;
		hHookGetTickCount=NULL;
	}
    if (api[37]==1&&realIsDebuggerPresent!=NULL)
	{
		LhUninstallHook(hHookIsDebuggerPresent);
		delete hHookIsDebuggerPresent;
		hHookIsDebuggerPresent=NULL;
	}
    if (api[38]==1&&realLoadLibraryEx!=NULL)
	{
		LhUninstallHook(hHookLoadLibraryEx);
		delete hHookLoadLibraryEx;
		hHookLoadLibraryEx=NULL;
	}
    if (api[39]==1&&realLoadResource!=NULL)
	{
		LhUninstallHook(hHookLoadResource);
		delete hHookLoadResource;
		hHookLoadResource=NULL;
	}
    if (api[40]==1&&realModule32FirstW!=NULL)
	{
		LhUninstallHook(hHookModule32FirstW);
		delete hHookModule32FirstW;
		hHookModule32FirstW=NULL;
	}
    if (api[41]==1&&realModule32NextW!=NULL)
	{
		LhUninstallHook(hHookModule32NextW);
		delete hHookModule32NextW;
		hHookModule32NextW=NULL;
	}
	if (api[42]==1&&realOpenProcess!=NULL)
	{
		LhUninstallHook(hHookOpenProcess);
		delete hHookOpenProcess;
		hHookOpenProcess=NULL;
	}
	if (api[43]==1&&realPeekNamedPipe!=NULL)
	{
		LhUninstallHook(hHookPeekNamedPipe);
		delete hHookPeekNamedPipe;
		hHookPeekNamedPipe=NULL;
	}
	if (api[44]==1&&realProcess32First!=NULL)
	{
		LhUninstallHook(hHookProcess32First);
		delete hHookProcess32First;
		hHookProcess32First=NULL;
	}
	if (api[45]==1&&realProcess32Next!=NULL)
	{
		LhUninstallHook(hHookProcess32Next);
		delete hHookProcess32Next;
		hHookProcess32Next=NULL;
	}
	if (api[46]==1&&realQueryPerformanceCounter!=NULL)
	{
		LhUninstallHook(hHookQueryPerformanceCounter);
		delete hHookQueryPerformanceCounter;
		hHookQueryPerformanceCounter=NULL;
	}
	if (api[47]==1&&realQueueUserAPC!=NULL)
	{
		LhUninstallHook(hHookQueueUserAPC);
		delete hHookQueueUserAPC;
		hHookQueueUserAPC=NULL;
	}
	if (api[48]==1&&realReadProcessMemory!=NULL)
	{
		LhUninstallHook(hHookReadProcessMemory);
		delete hHookReadProcessMemory;
		hHookReadProcessMemory=NULL;
	}
	if (api[49]==1&&realResumeThread!=NULL)
	{
		LhUninstallHook(hHookResumeThread);
		delete hHookResumeThread;
		hHookResumeThread=NULL;
	}
	if (api[50]==1&&realSetThreadContext!=NULL)
	{
		LhUninstallHook(hHookSetThreadContext);
		delete hHookSetThreadContext;
		hHookSetThreadContext=NULL;
	}
	if (api[51]==1&&realSuspendThread!=NULL)
	{
		LhUninstallHook(hHookSuspendThread);
		delete hHookSuspendThread;
		hHookSuspendThread=NULL;
	}
	if (api[52]==1&&realThread32First!=NULL)
	{
		LhUninstallHook(hHookThread32First);
		delete hHookThread32First;
		hHookThread32First=NULL;
	}
	if (api[53]==1&&realThread32Next!=NULL)
	{
		LhUninstallHook(hHookThread32Next);
		delete hHookThread32Next;
		hHookThread32Next=NULL;
	}
	if (api[54]==1&&realToolhelp32ReadProcessMemory!=NULL)
	{
		LhUninstallHook(hHookToolhelp32ReadProcessMemory);
		delete hHookToolhelp32ReadProcessMemory;
		hHookToolhelp32ReadProcessMemory=NULL;
	}
	if (api[55]==1&&realVirtualAllocEx!=NULL)
	{
		LhUninstallHook(hHookVirtualAllocEx);
		delete hHookVirtualAllocEx;
		hHookVirtualAllocEx=NULL;
	}
	if (api[56]==1&&realVirtualProtectEx!=NULL)
	{
		LhUninstallHook(hHookVirtualProtectEx);
		delete hHookVirtualProtectEx;
		hHookVirtualProtectEx=NULL;
	}
	if (api[57]==1&&realWinExec!=NULL)
	{
		LhUninstallHook(hHookWinExec);
		delete hHookWinExec;
		hHookWinExec=NULL;
	}
	if (api[58]==1&&realWriteProcessMemory!=NULL)
	{
		LhUninstallHook(hHookWriteProcessMemory);
		delete hHookWriteProcessMemory;
		hHookWriteProcessMemory=NULL;
	}
	if (api[59]==1&&realRegisterHotKey!=NULL)
	{
		LhUninstallHook(hHookRegisterHotKey);
		delete hHookRegisterHotKey;
		hHookRegisterHotKey=NULL;
	}
	if (api[60]==1&&realCreateProcessA!=NULL)
	{
		LhUninstallHook(hHookCreateProcessA);
		delete hHookCreateProcessA;
		hHookCreateProcessA=NULL;
	}
	if (api[61]==1&&realCertOpenSystemStoreW!=NULL)
	{
		LhUninstallHook(hHookCertOpenSystemStoreW);
		delete hHookCertOpenSystemStoreW;
		hHookCertOpenSystemStoreW=NULL;
	}
	if (api[62]==1&&realCreateMutexW!=NULL)
	{
		LhUninstallHook(hHookCreateMutexW);
		delete hHookCreateMutexW;
		hHookCreateMutexW=NULL;
	}
	if (api[63]==1&&realFindResourceW!=NULL)
	{
		LhUninstallHook(hHookFindResourceW);
		delete hHookFindResourceW;
		hHookFindResourceW=NULL;
	}
	if (api[64]==1&&realFindWindowW!=NULL)
	{
		LhUninstallHook(hHookFindWindowW);
		delete hHookFindWindowW;
		hHookFindWindowW=NULL;
	}
	if (api[65]==1&&realGetWindowsDirectoryW!=NULL)
	{
		LhUninstallHook(hHookGetWindowsDirectoryW);
		delete hHookGetWindowsDirectoryW;
		hHookGetWindowsDirectoryW=NULL;
	}
	if (api[66]==1&&realMapVirtualKeyW!=NULL)
	{
		LhUninstallHook(hHookMapVirtualKeyW);
		delete hHookMapVirtualKeyW;
		hHookMapVirtualKeyW=NULL;
	}
	if (api[67]==1&&realOpenMutexW!=NULL)
	{
		LhUninstallHook(hHookOpenMutexW);
		delete hHookOpenMutexW;
		hHookOpenMutexW=NULL;
	}
	if (api[68]==1&&realOpenSCManagerW!=NULL)
	{
		LhUninstallHook(hHookOpenSCManagerW);
		delete hHookOpenSCManagerW;
		hHookOpenSCManagerW=NULL;
	}
	if (api[69]==1&&realCreateProcessW!=NULL)
	{
		LhUninstallHook(hHookCreateProcessW);
		delete hHookCreateProcessW;
		hHookCreateProcessW=NULL;
	}
	if (api[70]==1&&realCreateServiceW!=NULL)
	{
		LhUninstallHook(hHookCreateServiceW);
		delete hHookCreateServiceW;
		hHookCreateServiceW=NULL;
	}
	if (api[71]==1&&realGetModuleFileNameExW!=NULL)
	{
		LhUninstallHook(hHookGetModuleFileNameExW);
		delete hHookGetModuleFileNameExW;
		hHookGetModuleFileNameExW=NULL;
	}
	if (api[72]==1&&realGetModuleHandleW!=NULL)
	{
		LhUninstallHook(hHookGetModuleHandleW);
		delete hHookGetModuleHandleW;
		hHookGetModuleHandleW=NULL;
	}
	if (api[73]==1&&realGetStartupInfoW!=NULL)
	{
		LhUninstallHook(hHookGetStartupInfoW);
		delete hHookGetStartupInfoW;
		hHookGetStartupInfoW=NULL;
	}
	if (api[74]==1&&realGetVersionExW!=NULL)
	{
		LhUninstallHook(hHookGetVersionExW);
		delete hHookGetVersionExW;
		hHookGetVersionExW=NULL;
	}
	if (api[75]==1&&realLoadLibraryW!=NULL)
	{
		LhUninstallHook(hHookLoadLibraryW);
		delete hHookLoadLibraryW;
		hHookLoadLibraryW=NULL;
	}
	if (api[76]==1&&realOutputDebugStringW!=NULL)
	{
		LhUninstallHook(hHookOutputDebugStringW);
		delete hHookOutputDebugStringW;
		hHookOutputDebugStringW=NULL;
	}
	if (api[77]==1&&realSetWindowsHookExW!=NULL)
	{
		LhUninstallHook(hHookSetWindowsHookExW);
		delete hHookSetWindowsHookExW;
		hHookSetWindowsHookExW=NULL;
	}
	if (api[78]==1&&realShellExecuteW!=NULL)
	{
		LhUninstallHook(hHookShellExecuteW);
		delete hHookShellExecuteW;
		hHookShellExecuteW=NULL;
	}
	if (api[79]==1&&realStartServiceCtrlDispatcherW!=NULL)
	{
		LhUninstallHook(hHookStartServiceCtrlDispatcherW);
		delete hHookStartServiceCtrlDispatcherW;
		hHookStartServiceCtrlDispatcherW=NULL;
	}
	if (api[80]==1&&realSetLocalTime!=NULL)
	{
		LhUninstallHook(hHookSetLocalTime);
		delete hHookSetLocalTime;
		hHookSetLocalTime=NULL;
	}
	if (api[81]==1&&realTerminateThread!=NULL)
	{
		LhUninstallHook(hHookTerminateThread);
		delete hHookTerminateThread;
		hHookTerminateThread=NULL;
	}
	if (api[82]==1&&realVirtualFree!=NULL)
	{
		LhUninstallHook(hHookVirtualFree);
		delete hHookVirtualFree;
		hHookVirtualFree=NULL;
	}
	if (api[83]==1&&realSetProcessWorkingSetSize!=NULL)
	{
		LhUninstallHook(hHookSetProcessWorkingSetSize);
		delete hHookSetProcessWorkingSetSize;
		hHookSetProcessWorkingSetSize=NULL;
	}
	if (api[84]==1&&realTerminateProcess!=NULL)
	{
		LhUninstallHook(hHookTerminateProcess);
		delete hHookTerminateProcess;
		hHookTerminateProcess=NULL;
	}
	if (api[85]==1&&realRegOpenKeyEx!=NULL)
	{
		LhUninstallHook(hHookRegOpenKeyEx);
		delete hHookRegOpenKeyEx;
		hHookRegOpenKeyEx=NULL;
	}
	if (api[86]==1&&realRegOpenKeyW!=NULL)
	{
		LhUninstallHook(hHookRegOpenKeyW);
		delete hHookRegOpenKeyW;
		hHookRegOpenKeyW=NULL;
	}
	if (api[87]==1&&realRegCreateKeyExW!=NULL)
	{
		LhUninstallHook(hHookRegCreateKeyExW);
		delete hHookRegCreateKeyExW;
		hHookRegCreateKeyExW=NULL;
	}
	if (api[88]==1&&realRegCreateKeyW!=NULL)
	{
		LhUninstallHook(hHookRegCreateKeyW);
		delete hHookRegCreateKeyW;
		hHookRegCreateKeyW=NULL;
	}
	if (api[89]==1&&realRegQueryValueExW!=NULL)
	{
		LhUninstallHook(hHookRegQueryValueExW);
		delete hHookRegQueryValueExW;
		hHookRegQueryValueExW=NULL;
	}
	if (api[90]==1&&realRegQueryValueW!=NULL)
	{
		LhUninstallHook(hHookRegQueryValueW);
		delete hHookRegQueryValueW;
		hHookRegQueryValueW=NULL;
	}
	if (api[91]==1&&realRegSetValueExW!=NULL)
	{
		LhUninstallHook(hHookRegSetValueExW);
		delete hHookRegSetValueExW;
		hHookRegSetValueExW=NULL;
	}
	if (api[92]==1&&realRegSetValueW!=NULL)
	{
		LhUninstallHook(hHookRegSetValueW);
		delete hHookRegSetValueW;
		hHookRegSetValueW=NULL;
	}
	if (api[93]==1&&realRegDeleteKeyExW!=NULL)
	{
		LhUninstallHook(hHookRegDeleteKeyExW);
		delete hHookRegDeleteKeyExW;
		hHookRegDeleteKeyExW=NULL;
	}
	if (api[94]==1&&realRegDeleteKeyW!=NULL)
	{
		LhUninstallHook(hHookRegDeleteKeyW);
		delete hHookRegDeleteKeyW;
		hHookRegDeleteKeyW=NULL;
	}
	if (api[95]==1&&realRegSetKeySecurity!=NULL)
	{
		LhUninstallHook(hHookRegSetKeySecurity);
		delete hHookRegSetKeySecurity;
		hHookRegSetKeySecurity=NULL;
	}
	if (api[96]==1&&realRegRestoreKey!=NULL)
	{
		LhUninstallHook(hHookRegRestoreKey);
		delete hHookRegRestoreKey;
		hHookRegRestoreKey=NULL;
	}
	if (api[97]==1&&realRegReplaceKey!=NULL)
	{
		LhUninstallHook(hHookRegReplaceKey);
		delete hHookRegReplaceKey;
		hHookRegReplaceKey=NULL;
	}
	if (api[98]==1&&realRegLoadKey!=NULL)
	{
		LhUninstallHook(hHookRegLoadKey);
		delete hHookRegLoadKey;
		hHookRegLoadKey=NULL;
	}
	if (api[99]==1&&realRegUnLoadKey!=NULL)
	{
		LhUninstallHook(hHookRegUnLoadKey);
		delete hHookRegUnLoadKey;
		hHookRegUnLoadKey=NULL;
	}
	if (api[100]==1&&realaccept!=NULL)
	{
		LhUninstallHook(hHookaccept);
		delete hHookaccept;
		hHookaccept=NULL;
	}
	if (api[101]==1&&realsend!=NULL)
	{
		LhUninstallHook(hHooksend);
		delete hHooksend;
		hHooksend=NULL;
	}
	if (api[102]==1&&realbind!=NULL)
	{
		LhUninstallHook(hHookbind);
		delete hHookbind;
		hHookbind=NULL;
	}
	if (api[103]==1&&realconnect!=NULL)
	{
		LhUninstallHook(hHookconnect);
		delete hHookconnect;
		hHookconnect=NULL;
	}
	if (api[104]==1&&realConnectNamedPipe!=NULL)
	{
		LhUninstallHook(hHookConnectNamedPipe);
		delete hHookConnectNamedPipe;
		hHookConnectNamedPipe=NULL;
	}
	/*
	if (api[105]==1&&realGetAdaptersInfo!=NULL)
	{
		LhUninstallHook(hHookGetAdaptersInfo);
		delete hHookGetAdaptersInfo;
		hHookGetAdaptersInfo=NULL;
	}
	*/
	if (api[106]==1&&realgethostname!=NULL)
	{
		LhUninstallHook(hHookgethostname);
		delete hHookgethostname;
		hHookgethostname=NULL;
	}
	if (api[107]==1&&realinet_addr!=NULL)
	{
		LhUninstallHook(hHookinet_addr);
		delete hHookinet_addr;
		hHookinet_addr=NULL;
	}
	if (api[108]==1&&realInternetReadFile!=NULL)
	{
		LhUninstallHook(hHookInternetReadFile);
		delete hHookInternetReadFile;
		hHookInternetReadFile=NULL;
	}
	if (api[109]==1&&realInternetWriteFile!=NULL)
	{
		LhUninstallHook(hHookInternetWriteFile);
		delete hHookInternetWriteFile;
		hHookInternetWriteFile=NULL;
	}
	if (api[110]==1&&realNetShareEnum!=NULL)
	{
		LhUninstallHook(hHookNetShareEnum);
		delete hHookNetShareEnum;
		hHookNetShareEnum=NULL;
	}
	if (api[111]==1&&realrecv!=NULL)
	{
		LhUninstallHook(hHookrecv);
		delete hHookrecv;
		hHookrecv=NULL;
	}
	if (api[112]==1&&realWSAStartup!=NULL)
	{
		LhUninstallHook(hHookWSAStartup);
		delete hHookWSAStartup;
		hHookWSAStartup=NULL;
	}
	if (api[113]==1&&realInternetOpenW!=NULL)
	{
		LhUninstallHook(hHookInternetOpenW);
		delete hHookInternetOpenW;
		hHookInternetOpenW=NULL;
	}
	if (api[114]==1&&realInternetOpenUrlW!=NULL)
	{
		LhUninstallHook(hHookInternetOpenUrlW);
		delete hHookInternetOpenUrlW;
		hHookInternetOpenUrlW=NULL;
	}
	if (api[115]==1&&realURLDownloadToFileW!=NULL)
	{
		LhUninstallHook(hHookURLDownloadToFileW);
		delete hHookURLDownloadToFileW;
		hHookURLDownloadToFileW=NULL;
	}
	if (api[116]==1&&realFtpPutFileW!=NULL)
	{
		LhUninstallHook(hHookFtpPutFileW);
		delete hHookFtpPutFileW;
		hHookFtpPutFileW=NULL;
	}
	if (api[117]==1&&realHttpSendRequest!=NULL)
	{
		LhUninstallHook(hHookHttpSendRequest);
		delete hHookHttpSendRequest;
		hHookHttpSendRequest=NULL;
	}
	if (api[118]==1&&realHttpSendRequestEx!=NULL)
	{
		LhUninstallHook(hHookHttpSendRequestEx);
		delete hHookHttpSendRequestEx;
		hHookHttpSendRequestEx=NULL;
	}
	if (api[119]==1&&realHttpOpenRequest!=NULL)
	{
		LhUninstallHook(hHookHttpOpenRequest);
		delete hHookHttpOpenRequest;
		hHookHttpOpenRequest=NULL;
	}
	if (api[120]==1&&realInternetConnect!=NULL)
	{
		LhUninstallHook(hHookInternetConnect);
		delete hHookInternetConnect;
		hHookInternetConnect=NULL;
	}
	if (api[121]==1&&reallisten!=NULL)
	{
		LhUninstallHook(hHooklisten);
		delete hHooklisten;
		hHooklisten=NULL;
	}
	if (api[122]==1&&realInternetOpenUrlA!=NULL)
	{
		LhUninstallHook(hHookInternetOpenUrlA);
		delete hHookInternetOpenUrlA;
		hHookInternetOpenUrlA=NULL;
	}
	if (api[123]==1&&realHttpOpenRequestA!=NULL)
	{
		LhUninstallHook(hHookHttpOpenRequestA);
		delete hHookHttpOpenRequestA;
		hHookHttpOpenRequestA=NULL;
	}

	LhWaitForPendingRemovals();  
}  

BOOL APIENTRY DllMain( HMODULE hModule,  
					  DWORD  ul_reason_for_call,  
					  LPVOID lpReserved  
					  )  
{  
	//ofstream ftest("C:\\Log\\test.txt",ios::app);
	//MessageBox(0, L"DllMain！", L"好了！", MB_OK); 
	switch (ul_reason_for_call)  
	{  
	case DLL_PROCESS_ATTACH:  
		{  
			OutputDebugString(L"DllMain::DLL_PROCESS_ATTACH\n");  
			//获取当前dll的路径
			char dllpath[MAX_PATH]={0};
			GetModuleFileNameA(hModule,dllpath,MAX_PATH);
			string str1(dllpath);
			string str2=str1.substr(0,strlen(dllpath)-12);
			OutputDebugStringA(str2.c_str());
			strcpy(dlldir,str2.c_str());
			OutputDebugStringA("\n");

			DWORD dwSize = 256;
			int len=200;
			GetUserNameA(strBuffer,&dwSize);//获取用户名
			WSAData wsaData;
			WSAStartup(MAKEWORD(1,1), &wsaData); 
			gethostname(hostname,128);//获取主机名
			GetProcessName(ProcessName,&len);//获取进程名
			cout<<ProcessName<<endl;
			cout<<hostname<<endl;
			cout<<strBuffer<<endl;

			// 准备好原始地址与目的地址  
			int errCode = PrepareRealApiEntry();  
			if (errCode != 0)  
			{  
				OutputDebugString(L"PrepareRealApiEntry() Error\n");  
				return FALSE;  
			}  

			// 开始挂钩  
			DoHook();  

			break;  
		}  
	case DLL_THREAD_ATTACH:  
		{  
			OutputDebugString(L"DllMain::DLL_THREAD_ATTACH\n");  

			break;  
		}  
	case DLL_THREAD_DETACH:  
		{  
			OutputDebugString(L"DllMain::DLL_THREAD_DETACH\n");  

			break;  
		}  

	case DLL_PROCESS_DETACH:  
		{  
			OutputDebugString(L"DllMain::DLL_PROCESS_DETACH\n");  

			// 卸载钩子  
			DoneHook();  

			break;  
		}  
	}  
	return TRUE;  
}  
