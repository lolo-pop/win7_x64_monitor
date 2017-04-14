// InjectDll.cpp : 定义控制台应用程序的入口点。
//

#include "iostream"
#include "windows.h"
#include "TLHELP32.H"
#include "fstream"
using namespace std;
//ofstream f("C:\\Log\\log.txt");

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
	return 0;
}
BOOL InjectDll(const char *DllFullPath,const DWORD dwRemoteProcessId)
{
	HANDLE hRemoteProcess;
	EnableDebugPriv("SeDebugPrivilege");
	//打开远程线程
	hRemoteProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId);
	char *pszLibFileRemote;
	//使用VirtualAllocEx函数在远程进程的内存地址空间分配DLL文件名空间
	pszLibFileRemote=(char *)VirtualAllocEx(hRemoteProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	if (pszLibFileRemote==NULL)
	{
		printf("VirtualAllocEx失败\n");
	}
	printf("%c",pszLibFileRemote);
	printf("%d\n",GetLastError());
	//使用WriteProcessMemory函数将DLL的路径名写入到远程进程的内存
	WriteProcessMemory(hRemoteProcess,pszLibFileRemote,(void *)DllFullPath,lstrlenA(DllFullPath)+1,NULL);
	/*
	//计算LoadLibraryA的入口地址
	PTHREAD_START_ROUTINE pfnStartAddr=NULL;
	pfnStartAddr=(PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")),"LoadLibraryA");
	//关于GetModuleHandle函数和GetProcAddress函数
	HANDLE hRemoteThread=NULL;
	if((hRemoteThread=CreateRemoteThread(hRemoteThread,NULL,0,pfnStartAddr,pszLibFileRemote,0,NULL))==NULL)
	{
		printf("线程注入失败");
		return FALSE;
	}
	*/
	DWORD dwID;
	LPVOID pFunc = LoadLibraryA;
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc, pszLibFileRemote, 0, &dwID );
	if (hRemoteThread==NULL)
	{
		printf("CreateRemoteThread失败\n");
		printf("%d",GetLastError());
		return FALSE;
	}
	//释放句柄
	CloseHandle(hRemoteProcess);
	CloseHandle(hRemoteThread);
	return TRUE;
}

void InjectAll()
{
	PROCESSENTRY32 pe32;//用来存放快照进程信息的一个结构体。（存放一个进程信息和调用成员输出进程信息）
	//用来 Process32First指向第一个进程信息，
	//并将进程信息抽取到PROCESSENTRY32中。用Process32Next指向下一条进程信息。
	pe32.dwSize = sizeof(pe32);   //这个操作必须要不然获取不到pe32 
	// 给系统内的所有进程拍一个快照
	HANDLE hprocesssnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , 0);
	if (hprocesssnap == INVALID_HANDLE_VALUE) 
	{
		printf("INVALID_HANDLE_VALUE\n");
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
	ofstream f("C:\\process.txt",ios::out);
	f.clear();
	while (bmore)
	{
		wprintf(L"%s\n",pe32.szExeFile);
		wprintf(L"%u\n" , pe32.th32ProcessID ); 
		//flag=InjectDll("C://DllHook.dll",pe32.th32ProcessID);
		WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, wcslen(pe32.szExeFile) + 1, ch, 300, NULL, NULL);
		if (flag==TRUE)
		{
			f<<ch<<" ";
		}
		InjectDll("D://EasyHook64.dll",pe32.th32ProcessID);
		//wprintf(_T("线程数目: %d \n"),pe32.cntThreads);
		hfilename = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE , pe32.th32ProcessID );
		if (hfilename == NULL )
		{
			printf("文件名字访问失败!");
		}
		BOOL i = Module32First(hfilename , &pes);
		wprintf(L"%s \n" , pes.szExePath);
		WideCharToMultiByte(CP_ACP, 0, pes.szExePath, wcslen(pes.szExePath) + 1, ch1, 300, NULL, NULL);
		f<<ch1<<endl;
		//wf<<pes.szExePath<<endl;
		bmore = Process32Next(hprocesssnap , &pe32);
	}
	f.close();
	//关闭内核对象
	CloseHandle(hfilename);
	CloseHandle(hprocesssnap);
	return;
}
int main(int argc, CHAR* argv[])
{
	
	InjectAll();
	//printf("%s %s %s",argv[0],argv[1],argv[2]);
	//InjectDll(argv[1],atoi(argv[2]));
    //cout<<argv[1]<<" "<<argv[2]<<endl;
	//InjectDll("D://EasyHook64.dll",3184);
	return 0;
}

