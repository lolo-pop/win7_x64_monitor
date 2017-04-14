// TestAPI.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include "psapi.h"

using namespace std;
string WideToMutilByte(const wstring& _src)
{
	if (&_src==NULL)
	{
		return "NULL";
	}
	int nBufSize = WideCharToMultiByte(GetACP(), 0, _src.c_str(),-1, NULL, 0, NULL, NULL);
	char *szBuf = new char[nBufSize];
	WideCharToMultiByte(GetACP(), 0, _src.c_str(),-1, szBuf, nBufSize, NULL, NULL);
	string strRet(szBuf);
	delete []szBuf;
	szBuf = NULL;
	return strRet;
}

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//检查参数
	if(!pszDosPath || !pszNtPath )
		return FALSE;

	//获取本地磁盘字符串
	if(GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for(i = 0; szDriveStr[i]; i += 4)
		{
			if(!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if(!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if(_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}			
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

BOOL GetProcessFullPath(HANDLE hProcess, TCHAR pszFullPath[MAX_PATH])
{
	TCHAR		szImagePath[MAX_PATH];
	/*HANDLE		hProcess;

	if(!pszFullPath)
	return FALSE;

	pszFullPath[0] = '\0';
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);*/
	if(!hProcess)
		return FALSE;

	if(!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if(!DosPathToNtPath(szImagePath, pszFullPath))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	/*
	LoadLibraryA("apisetschema.dll");
	int a=0;
	cin>>a;
	*/
	//ShellExecuteA(NULL,"open","calc.exe","","", SW_SHOW );
	/*
	DWORD     dwSize;
	HANDLE    hToken;
	LPVOID    lpvEnv;
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO         si = {0};
	WCHAR               szUserProfile[256] = L"";
	si.cb = sizeof(STARTUPINFO);
	dwSize = sizeof(szUserProfile)/sizeof(WCHAR);
	CreateProcessWithLogonW(L"aaa", NULL, L"aaa", 
		LOGON_WITH_PROFILE, NULL, L"aaaa", 
		CREATE_UNICODE_ENVIRONMENT, NULL, szUserProfile, 
		&si, &pi);
	*/


	//HANDLE hOpenFileA=(HANDLE)CreateFileW(L"C:\\Windows\\system32\\Xfire32.dll",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,NULL,NULL);
	//TCHAR buff[MAX_PATH];
	//GetSystemDirectoryW(buff,100);
	//wprintf(buff);
	//HANDLE fileHandle; 
	//lstrcat(buff,L"\\xfire32.dll");
	//wprintf(buff);
	//fileHandle=CreateFileW(buff, GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	////如果使用OPEN_EXISTING则不会创建文件
	//if(fileHandle == INVALID_HANDLE_VALUE) 
	//	return 1;
	//char *data="http://www.baidu.com/"; 
	//DWORD a = 25; 
	//unsigned long b; 
	//OVERLAPPED   c; 
	//WriteFile(fileHandle, data, a, &b, NULL); 

	/*
	STARTUPINFOA si = { sizeof(si) };   
	PROCESS_INFORMATION pi;   

	si.dwFlags = STARTF_USESHOWWINDOW;   
	si.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口  
	TCHAR cmdline[] =TEXT("c://program files//internet explorer//iexplore.exe http://community.csdn.net/"); 
	char cmd[]="c://program files//internet explorer//iexplore.exe http://community.csdn.net/";
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
	*/
	/*
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	si.cb=sizeof(si);
	si.dwFlags=STARTF_USESHOWWINDOW;
	si.wShowWindow=TRUE; 
	CreateProcessA(NULL,"c://windows//system32//notepad.exe",NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi) ; 
	*/
	/*
	STARTUPINFO si1;
	PROCESS_INFORMATION pi1;
	si1.cb=sizeof(si1);
	si1.dwFlags=STARTF_USESHOWWINDOW;
	si1.wShowWindow=TRUE; 
	CreateProcessW(NULL,TEXT("WWWWWWW"),NULL,NULL,FALSE,0,NULL,NULL,&si1,&pi1) ;
	*/
    /*
	OutputDebugStringA("111");
	LoadLibraryA("kernel32.dll");
	LoadLibraryW(L"kernel32.dll");
	*/
	
	
	
	
	//
	//string dirpath;
	//HANDLE hProcess;
	////CloseHandle(hProcess);
	//hProcess=OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,11472);
	//if (hProcess==NULL)
	//{
	//	cout<<"获取进程句柄失败"<<endl;
	//	return 0;
	//}
	//char processpath[MAX_PATH]="NULL";
	//GetModuleFileNameExA(hProcess,0,processpath,MAX_PATH);
	////K32GetModuleFileNameExA(hProcess,0,processpath,MAX_PATH);
	////GetProcessImageFileNameA(hProcess,processpath,MAX_PATH);
	//cout<<processpath<<endl;

	//TCHAR path1[MAX_PATH];
	//string buf;
	//GetProcessFullPath(hProcess,path1);
	//buf=WideToMutilByte(path1);


	//cout<<buf.c_str()<<endl;
	////wprintf(path1);
	//CloseHandle(hProcess);





	/*
	char exepath[MAX_PATH];
	GetModuleFileNameA(NULL,exepath,MAX_PATH);
	string str(exepath);
	int end=strlen(exepath)-11;
	dirpath=str.substr(0,end);
	char configpath1[1000];
	char configpath2[1000];
	sprintf_s(configpath1,"%sconfig.xml",dirpath.c_str());
	sprintf_s(configpath2,"%supdate.xml",dirpath.c_str());
	DeleteFileA(configpath1);
	MoveFileA(configpath2,configpath1);
	cout<<configpath1<<endl;
	cout<<"move"<<endl;
	*/
	//cin>>a;
	int tid=0;
	cin>>tid;
	HANDLE hthread=OpenThread(THREAD_ALL_ACCESS,FALSE,tid);
	if (hthread==NULL)
	{
		cout<<"hthread为空"<<endl;
		return 0;
	}
	DWORD pid=0;
	pid=GetProcessIdOfThread(hthread);
	cout<<pid<<endl;
	HANDLE hprocess=NULL;
	hprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if (hprocess==NULL)
	{
		cout<<"hprocess为空"<<endl;
		return 0;
	}
	char path[MAX_PATH]={0};
	int ret=1;
	ret=GetModuleFileNameExA(hprocess,NULL,path,sizeof(path));
	if (ret==0)
	{
		cout<<"获取路径失败"<<endl;
		return 0;
	}
	cout<<path<<endl;
	return 0;
}

