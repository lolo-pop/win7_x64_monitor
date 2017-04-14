// UnloadDll32.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include "TLHELP32.H"
#include "fstream"
#include <Psapi.h>
#include <process.h>
#pragma comment(lib,"version.lib")
#pragma comment(lib, "Psapi.lib")
#include "fstream"
#include <time.h>
using namespace std;

char status[MAX_PATH];

void UnInjectDll(const char *szDllName,const DWORD dwPid){
	BOOL flag = FALSE;           
	if ( dwPid == 0 || strlen(szDllName) == 0 )  
	{                   
		return;  
	}           
	//获取系统运行进程、线程等的列表  
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);           
	MODULEENTRY32 Me32 = { 0 };  
	Me32.dwSize = sizeof(MODULEENTRY32);           
	//检索与进程相关联的第一个模块的信息  
	BOOL bRet = Module32First(hSnap, &Me32);           
	while ( bRet )  
	{         
		//查找所注入的DLL  
		string ws=Me32.szModule;
		string str="NULL";
		str=ws;
		if ( strcmp(str.c_str(), szDllName) == 0 )                   
		{  
			flag = TRUE;                           break;  
		}                   //检索下一个模块信息  
		bRet = Module32Next(hSnap, &Me32);           
	}  
	if (flag == FALSE)           
	{  
	//	printf("找不到相应的模块!");     
		return;  
	}     
	CloseHandle(hSnap);     
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);           
	if ( hProcess == NULL )  
	{                   
	//	printf("进程打开失败!");  
		return ;           
	}  
	FARPROC pFunAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"),"FreeLibrary");  
	//cout<<dwPid<<endl;
	HANDLE hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)pFunAddr,Me32.hModule,0,NULL);  
	//cout<<dwPid<<endl;
	if (hThread == NULL)           {  
	//	printf("创建远程线程失败!");                  
		return;  
	}         
	//AfxMessageBox("成功卸载!");           //等待线程退出  
	//WaitForSingleObject(hThread, INFINITE);         
	CloseHandle(hThread);           
	CloseHandle(hProcess);  
}

string dirpath;



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
	//	printf("LookupPrivilegeValueA失败");
	}
	tp.PrivilegeCount=1;
	tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid=luid;
	//调整权限
	if(!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
	//	printf("AdjustTokenPrivileges失败");
	}
	return 0;
}

//判断进程是否是64位
int GetProcessIsWOW64(int pid)
{
	int nRet=-1;
	EnableDebugPriv("SeDebugPrivilege");
	HANDLE hProcess;

	//打开远程线程
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if (hProcess==NULL)
	{
		return -1;
	}

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process; 
	BOOL bIsWow64 = FALSE; 
	BOOL bRet;
	DWORD nError;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle("kernel32"),"IsWow64Process"); 
	if (NULL != fnIsWow64Process) 
	{ 
		bRet=fnIsWow64Process(hProcess,&bIsWow64);
		if (bRet==0)
		{
			nError=GetLastError();
			nRet=-2;
		}
		else
		{
			if (bIsWow64)
			{
				nRet=1;
			}
			else
			{
				nRet=0;
			}
		}
	} 
	CloseHandle(hProcess);
	return nRet;
}


void UnInjectAll()
{
	EnableDebugPriv("SeDebugPrivilege");
	PROCESSENTRY32 pe32;//用来存放快照进程信息的一个结构体。（存放一个进程信息和调用成员输出进程信息）
	//用来 Process32First指向第一个进程信息，
	//并将进程信息抽取到PROCESSENTRY32中。用Process32Next指向下一条进程信息。
	pe32.dwSize = sizeof(pe32);   //这个操作必须要不然获取不到pe32 
	// 给系统内的所有进程拍一个快照
	HANDLE hprocesssnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , 0);
	if (hprocesssnap == INVALID_HANDLE_VALUE) 
	{
	//	printf("INVALID_HANDLE_VALUE\n");
		return ;
	}
	BOOL bmore = Process32First(hprocesssnap , &pe32);
	HANDLE hfilename = NULL ;
	MODULEENTRY32 pes; 
	//这个结构描述了一个条目从一个列表，列举了一个指定的进程所使用的模块。
	pes.dwSize = sizeof(MODULEENTRY32);
	// 遍历进程快照，轮流显示每个进程的信息 
	BOOL flag=TRUE;
	char ch[300];
	char ch1[1000];

	//cout<<mondll32path<<endl;
	//cout<<mondll64path<<endl;
	//cout<<easyhookdll64path<<endl;
	//ofstream f("C:/dll.txt",ios::app);
	while (bmore)
	{
		int r=0;
		r=GetProcessIsWOW64(pe32.th32ProcessID);
		/*
		if (r!=1)//如果不是64位，直接continue
		{
			bmore=Process32Next(hprocesssnap,&pe32);
			continue;
		}
		*/
		//f<<pe32.szExeFile<<endl;

		//printf("%s\n",pe32.szExeFile);
		//printf("%d\n" , pe32.th32ProcessID ); 
		int check=1;//当前进程还没有注入dll
		hfilename = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE , pe32.th32ProcessID );
		BOOL i = Module32First(hfilename , &pes);
		//char dllpath[MAX_PATH]="D:/EasyHook32.dll";//要卸载的DLL的路径
		i=Module32Next(hfilename,&pes);
		while (i)
		{
			//f<<pes.szExePath<<" "<<pes.szModule<<endl;
			//cout<<pes.szModule<<endl;
			//int t1=strcmp(pes.szModule,"MonDll32.dll");
			int t2=strcmp(pes.szModule,"MonDll32.dll");
			int t3=strcmp(pes.szModule,"EasyHook32.dll");

			if (t2==0||t3==0)
			{
				check=0;
			//	cout<<pes.szExePath<<endl;
				break;
			}
			i=Module32Next(hfilename,&pes);
		}
		int t1=strcmp(pe32.szExeFile,"UnloadDll32.exe");
		if(t1==0){
			check=1;
		}
		if (check==0)
		{

		//	cout<<pe32.szExeFile<<endl;
			UnInjectDll("MonDll32.dll",pe32.th32ProcessID);
			//Sleep(500);
			//UnInjectDll("EasyHook32.dll",pe32.th32ProcessID);	
		}
		bmore = Process32Next(hprocesssnap , &pe32);
	}
	//f.close();
	CloseHandle(hfilename);
	CloseHandle(hprocesssnap);
	return;
}

void After(){
	EnableDebugPriv("SeDebugPrivilege");
	char exepath[MAX_PATH];
	GetModuleFileNameA(NULL,exepath,MAX_PATH);
	string str(exepath);
	int end=strlen(exepath)-15;
	dirpath=str.substr(0,end);
	sprintf_s(status,"%sUsMon.exe.status",dirpath.c_str());
	//cout<<exepath<<endl;
	//cout<<dirpath.c_str()<<endl;

}

int _tmain(int argc, _TCHAR* argv[])
/*int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR     lpCmdLine,
	_In_ int       nCmdShow
	)
	*/
{
	/*
	time_t rawtime; 
	struct tm * timeinfo; 
	time ( &rawtime ); 
	timeinfo = localtime ( &rawtime ); 
	printf("当前系统时间: %s", asctime(timeinfo));
	WinExec("taskkill /im MonInject32.exe /f",SW_HIDE);
	UnInjectAll();
	time(&rawtime);
	timeinfo = localtime ( &rawtime ); 
	printf("当前系统时间: %s", asctime(timeinfo));
	return 0;
	ofstream file1(status);
	file1<<"2";
	file1.close();
	while (true)
	{
		Sleep(1000);
		ifstream fin(status);
		char temp[100];
		fin.get(temp,100,'\0');
		fin.close();
		if (strcmp(temp,"1")==0)
		{
			break;
		}
	}
	*/
	After();
	UnInjectAll();
	ofstream file(status);
	file<<"0";
	file.close();
	return 0;
}

