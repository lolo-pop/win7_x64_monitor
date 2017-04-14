// ProcessOperation.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "iostream"
#include "windows.h"
#include <TLHELP32.h>
#include "stdio.h"
using namespace std;
HHOOK _hook;
KBDLLHOOKSTRUCT kbdStruct;

int const MAX_REMOTE_DATA = 1024 * 4;  

int EnableDebugPriv(const char* name)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	//打开进程令牌环
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken);
	//获得进程本地唯一ID
	if(!LookupPrivilegeValueA(NULL,name,&luid))
	{
		printf("LookupPrivilegeValueA失败");
	}
	tp.PrivilegeCount=1;
	tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid=luid;
	//调整权限
	if(!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
		printf("AdjustTokenPrivileges失败");
	}
	CloseHandle(hToken);
	return 0;
}

LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode >= 0)
	{
		// the action is valid: HC_ACTION.
		if (wParam == WM_KEYDOWN)
		{
			// lParam is the pointer to the struct containing the data needed, so cast and assign it to kdbStruct.
			kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
			// a key (non-system) is pressed.
			if (kbdStruct.vkCode == VK_F1)
			{
				// F1 is pressed!
				MessageBoxA(NULL, "F1 is pressed!", "key pressed", MB_ICONINFORMATION);
			}
		}
	}

	// call the next hook in the hook chain. This is nessecary or your hook chain will break and the hook stops
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}

int _tmain(int argc, _TCHAR* argv[])
{
	/*HANDLE th,ph;
	th=OpenThread(THREAD_ALL_ACCESS,FALSE,2300);
	if (th==NULL)
	{
		cout<<"失败1"<<endl;
	}*/
	//ph=OpenThread(THREAD_ALL_ACCESS,true,GetCurrentThreadId());
	//if (ph==NULL)
	//{
	//	cout<<"失败2"<<endl;
	//}
	////LPDWORD lpExitCode=0;
	////GetExitCodeThread(th,lpExitCode);
	//TerminateThread(th,0);
	//return 0;
	

	char ch[256]="";
	//设置消息钩子
	cout<<"设置消息钩子操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	_hook=SetWindowsHookExA(WH_KEYBOARD_LL, HookCallback, NULL, 0);
	UnhookWindowsHookEx(_hook);
	_hook=SetWindowsHookExW(WH_KEYBOARD_LL,HookCallback, NULL,0);
	UnhookWindowsHookEx(_hook);
	cout<<"设置消息钩子操作结束\n"<<endl;

	//查找窗口
	cout<<"查找窗口操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	HWND maindHwnd = FindWindowW(L"无标题-记事本",L"无标题-记事本");
	FindWindowExW(maindHwnd, maindHwnd, L"无标题-记事本",L"无标题-记事本");
	FindWindowExA(maindHwnd,maindHwnd,"无标题-记事本","无标题-记事本");
	GetForegroundWindow();
	cout<<"查找窗口操作结束\n"<<endl;

	//注册服务
	cout<<"注册服务操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);  
	//TCHAR szServiceName[] = _T("ServiceTest"); 
	LPCWSTR szServiceName=L"ServiceTest";
	LPSTR szFilePath;
	LPCWSTR szFilePath1;
	//TCHAR szFilePath[MAX_PATH];  
	::GetModuleFileName(NULL, szFilePath, MAX_PATH);
	SC_HANDLE hService = ::CreateServiceW(  
		hSCM, szServiceName, szServiceName,  
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,  
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,  
		szFilePath1, NULL, NULL, L"", NULL, NULL);
	char szServiceName1[]="ServiceTest1";
	char szFilePath2[MAX_PATH];
	GetModuleFileNameA(NULL,szFilePath2,MAX_PATH);
	SC_HANDLE hService1 = ::CreateServiceA(hSCM,szServiceName1,szServiceName1,SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,
								SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,szFilePath2,NULL,NULL,"",NULL,NULL);
	cout<<"注册服务操作结束\n"<<endl;


	//枚举进程
	cout<<"枚举进程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32); 
	HANDLE hprocesssnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , 0);
	BOOL bmore = Process32First(hprocesssnap , &pe32);
	bmore = Process32Next(hprocesssnap , &pe32);
	CloseHandle(hprocesssnap);
	cout<<"枚举进程操作结束\n"<<endl;
	//加载内核模块
	
	//跨进程结束线程
	cout<<"跨进程结束线程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	int tid=0;
	cout<<"请输入Explorer.exe进程的一个线程的线程号（利用ProcessHacker可以查看Explorer.exe的线程号）："<<endl;
	cin>>tid;
	HANDLE th;
	th=OpenThread(THREAD_ALL_ACCESS,FALSE,tid);
	TerminateThread(th,0);
	CloseHandle(th);
	cout<<"跨进程结束线程操作结束\n"<<endl;
	
	
	//跨进程挂起线程
	cout<<"跨进程挂起线程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	cout<<"请输入Explorer.exe进程的一个线程的线程号（利用ProcessHacker可以查看Explorer.exe的线程号）："<<endl;
	cin>>tid;
	th=OpenThread(THREAD_ALL_ACCESS,FALSE,tid);
	SuspendThread(th);
	cout<<"跨进程挂起线程操作结束\n"<<endl;

	//跨进程恢复线程
	cout<<"跨进程恢复线程操作，对上一步中挂起的线程进行恢复，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	ResumeThread(th);
	CloseHandle(th);
	cout<<"跨进程恢复线程操作结束\n"<<endl;

	//跨进程设置线程上下文
	cout<<"跨进程设置线程上下文操作,按任意键开始执行行为！"<<endl;
	gets_s(ch);
	HANDLE ht1;
	ht1=OpenThread(THREAD_ALL_ACCESS,FALSE,tid);
	LPCONTEXT lpc=NULL;
	GetThreadContext(ht1,lpc);
	SetThreadContext(ht1,lpc);
	CloseHandle(ht1);
	cout<<"跨进程设置线程上下文操作结束\n"<<endl;
	
	//创建远程线程
	cout<<"创建远程线程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	int pid=0;
	cout<<"请输入Explorer.exe进程的进程号："<<endl;
	cin>>pid;
	EnableDebugPriv("SeDebugPrivilege");
	HANDLE hProcess;
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	char DllFullPath[]="aaaa";
	LPVOID lpfunc=LoadLibraryA;
	char *pszLibFileRemote;
	pszLibFileRemote=(char *)VirtualAllocEx(hProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	WriteProcessMemory(hProcess,pszLibFileRemote,(void *)DllFullPath,lstrlenA(DllFullPath)+1,NULL);
	DWORD dwID;
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpfunc, pszLibFileRemote, 0, &dwID );
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
	cout<<"创建远程线程操作结束\n"<<endl;

	//跨进程读内存
	cout<<"跨进程读内存操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	int tmp;
	SIZE_T dwNumberOfBytesRead;
	ReadProcessMemory(hProcess,(LPCVOID)0x00401000,&tmp,4,&dwNumberOfBytesRead);
	CloseHandle(hProcess);
	cout<<"跨进程读内存操作结束\n"<<endl;
	
	//跨进程写内存
	cout<<"跨进程写内存操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	pszLibFileRemote=(char *)VirtualAllocEx(hProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	WriteProcessMemory(hProcess,pszLibFileRemote,(void *)DllFullPath,lstrlenA(DllFullPath)+1,NULL);
	cout<<"跨进程写内存操作结束\n"<<endl;

	//跨进程修改内存属性
	cout<<"跨进程修改内存属性操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	DWORD dwPrev;
	VirtualProtectEx(hProcess,pszLibFileRemote,4,PAGE_READWRITE,&dwPrev);
	cout<<"跨进程释放内存属性操作结束\n"<<endl;
	
	//跨进程释放内存
	cout<<"跨进程释放内存操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	VirtualFreeEx(hProcess,pszLibFileRemote,0,MEM_RELEASE);
	CloseHandle(hProcess);
	cout<<"跨进程释放内存操作结束\n"<<endl;
	
	
	
	//创建进程
	cout<<"创建进程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	STARTUPINFOA si = { sizeof(si) };   
	PROCESS_INFORMATION pi;   
	si.dwFlags = STARTF_USESHOWWINDOW;   
	si.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口  
	//TCHAR cmdline[] =TEXT("c://program files//internet explorer//iexplore.exe http://community.csdn.net/"); 
	char cmd[]="c://Windows//system//cmd.exe";
	BOOL bRet = ::CreateProcessA (   
		NULL,  
		cmd, //在Unicode版本中此参数不能为常量字符串，因为此参数会被修改    
		NULL,   
		NULL,   
		FALSE,   
		CREATE_NEW_CONSOLE,   
		NULL,   
		NULL,   
		&si,   
		&pi);
	cout<<"创建进程操作结束\n"<<endl;
	
	//打开进程
	cout<<"打开进程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	cout<<"打开进程操作结束\n"<<endl;
	
	//挂起进程
	
	//恢复进程
	
	//结束进程操作
	cout<<"结束进程操作，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	cout<<"输入一个进程号，即将结束该进程："<<endl;
	cin>>pid;
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	TerminateProcess(hProcess,0);
	cout<<"结束进程操作结束\n"<<endl;
	return 0;
}

