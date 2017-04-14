// Action.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "stdio.h"  
#include "tchar.h"  
#include <windows.h>  
#include<iostream>  
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif
using namespace std;

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

int _tmain(int argc, _TCHAR* argv[])
{
	BYTE    *lpData;
	int mmm=0;
	cin>>mmm;
	//启动自释放文件
	HANDLE hOpenFileA=CreateFileA("C:\\trojan.exe",GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	char *data="http://www.baidu.com/"; 
	DWORD a = 25; 
	unsigned long b; 
	OVERLAPPED   c; 
	WriteFile(hOpenFileA, data, a, &b, NULL);
	STARTUPINFOA si = { sizeof(si) };   
	PROCESS_INFORMATION pi;   
	si.dwFlags = STARTF_USESHOWWINDOW;   
	si.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口  
	//TCHAR cmdline[] =TEXT("c://program files//internet explorer//iexplore.exe http://community.csdn.net/"); 
	char cmd[]="c://trojan.exe";
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

	//注册服务动态库
	//http://blog.csdn.net/chenyujing1234/article/details/8023816
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);  
	TCHAR szServiceName[] = _T("ServiceTest"); 
	TCHAR szFilePath[MAX_PATH];  
	::GetModuleFileName(NULL, szFilePath, MAX_PATH);
	SC_HANDLE hService = ::CreateService(  
		hSCM, szServiceName, szServiceName,  
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,  
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,  
		szFilePath, NULL, NULL, _T(""), NULL, NULL);

	//添加系统防火墙放过列表
	/*
	*可以直接注入regedit收集到行为
	*/
	/*
	HKEY hk;
	RegCreateKeyA(HKEY_LOCAL_MACHINE, 
		"SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", 
		&hk);
	CHAR szBuf[80];
	strcpy(szBuf, "%SystemRoot%\\System\\a.dll"); 
	RegSetValueExA(hk,             // sub key handle 
		"aaaaa",       // value name 
		0,                        // must be zero 
		REG_SZ,            // value type 
		(LPBYTE) szBuf,           // pointer to value data 
		strlen(szBuf) + 1);
		*/
	//禁止服务

	/*
	*可以直接注入regedit收集到行为
	*/

	//降低系统安全性
	/*
	注册表操作监控regedit可以得到
	*/

	//修改注册表自启动项
	/*
	注册表操作监控regedit可以得到
	*/

	//入侵进程
	 char *DllFullPath="aaaaaaaa";
	EnableDebugPriv("SeDebugPrivilege");
	DWORD dwRemoteProcessId=_getpid();
	HANDLE hRemoteProcess;
	hRemoteProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId);
	char *pszLibFileRemote;
	pszLibFileRemote=(char *)VirtualAllocEx(hRemoteProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	if (pszLibFileRemote==NULL)
	{
		//	printf("VirtualAllocEx失败\n");
		BOOL res;
		res=CloseHandle(hRemoteProcess);
		//cout<<"res "<<res<<endl;
		return FALSE;
	}
	WriteProcessMemory(hRemoteProcess,pszLibFileRemote,(void *)DllFullPath,lstrlenA(DllFullPath)+1,NULL);

	return 0;
}

