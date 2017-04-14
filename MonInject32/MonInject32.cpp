// InjectDll.cpp : 定义控制台应用程序的入口点。
//

#include <iostream>
#include <windows.h>
#include <TLHELP32.H>
#include <fstream>
#include <time.h>
#include "MyOutputDebugString.h"
using namespace std;
//ofstream f("C:\\Log\\log.txt");

string dirpath;

char status[MAX_PATH];
typedef struct _LSA_UNICODE_STRING{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS (NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING,PCWSTR);
typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWCHAR,ULONG,PUNICODE_STRING,PHANDLE);

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA,*PTHREAD_DATA;

typedef VOID (WINAPI *fRtlInitUnicodeString)(PUNICODE_STRING DestinationString,PCWSTR ourceString);

typedef NTSTATUS (WINAPI *fLdrLoadDll)(IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, IN PUNICODE_STRING  ModuleFileName, OUT PHANDLE ModuleHandle);

typedef DWORD64 (WINAPI *_NtCreateThreadEx64)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD64 dwStackSize, DWORD64 dw1, DWORD64 dw2, LPVOID Unknown);

typedef DWORD (WINAPI *_NtCreateThreadEx32)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD dwStackSize, DWORD dw1, DWORD dw2, LPVOID Unknown); 

HANDLE WINAPI ThreadProc(PTHREAD_DATA data)
{
	data->fnRtlInitUnicodeString(&data->UnicodeString,data->DllName);
	data->fnLdrLoadDll(data->DllPath,data->Flags,&data->UnicodeString,&data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI ThreadProcEnd()
{
	MyOutputDebugStringA("ThreadProcEnd");
	return 0;
}
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

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;   
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))   
		return( FALSE );
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;   
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
	if (GetLastError() != ERROR_SUCCESS)   
		return FALSE;   

	return TRUE; 
}

//判断进程是否是64位
int Is64BitPorcess(DWORD dwProcessID)
{
	EnableDebugPrivilege();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,dwProcessID);
	if(hProcess == NULL)
		return 3;
	if(hProcess)
    {
		typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandleW(L"kernel32"),"IsWow64Process");
        BOOL bIsWow64 = FALSE;
        fnIsWow64Process(hProcess,&bIsWow64);
        CloseHandle(hProcess);
        if (bIsWow64)
        {
			return 0;
        }
        else
        {
			return 1;
        }
    }
}
/*
int GetProcessIsWOW64(int pid)
{
	int nRet=-1;
	EnableDebugPrivilege();
	HANDLE hProcess;

	//打开远程线程
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if (hProcess==NULL)
	{
		CloseHandle(hProcess);
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
}*/

HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;
	pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if( pFunc == NULL )
	{
		MyOutputDebugStringA("MyCreateRemoteThread() : GetProcAddress(\"NtCreateThreadEx\") 调用失败！错误代码: [%d]",	GetLastError());
		return NULL;
	}
	((_NtCreateThreadEx32)pFunc)(&hThread,0x1FFFFF,NULL,hProcess,pThreadProc,pRemoteBuf,FALSE,NULL,NULL,NULL,NULL);

	if( hThread == NULL )
	{
		MyOutputDebugStringA("MyCreateRemoteThread() : NtCreateThreadEx() 调用失败！错误代码: [%d]", GetLastError());
     	return NULL;
	}
	if( WAIT_FAILED == WaitForSingleObject(hThread, INFINITE) )
	{
		MyOutputDebugStringA("MyCreateRemoteThread() : WaitForSingleObject() 调用失败！错误代码: [%d]", GetLastError());
		return NULL;
	}
	return hThread;
}

//在目标进程中创建线程并注入dll
BOOL InjectDll(DWORD dwProcessId,LPCWSTR lpcwDllPath)
{
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	LPVOID pCode = NULL;
	LPVOID pThreadData = NULL;
	__try
	{
		if(!EnableDebugPrivilege())
		{
			MyOutputDebugStringA("EnableDebugPrivilege Failed!");
			return -1;
		}
		//打开目标进程;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
		DWORD dwError = GetLastError();
		if (hProcess == NULL)
			__leave;
		//申请空间，把我们的代码和数据写入目标进程空间里;
		//写入数据;
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll,"RtlInitUnicodeString");
		data.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtdll,"LdrLoadDll");
		memcpy(data.DllName, lpcwDllPath, (wcslen(lpcwDllPath) + 1)*sizeof(WCHAR));
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		pThreadData = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
			__leave;
		BOOL bWriteOK = WriteProcessMemory(hProcess, pThreadData,&data,sizeof(data), NULL);
		if (!bWriteOK)
			__leave;
		MyOutputDebugStringA("pThreadData = 0x%p",pThreadData);
		//写入代码;
		DWORD SizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		pCode = VirtualAllocEx(hProcess, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
			__leave;
		bWriteOK = WriteProcessMemory(hProcess, pCode, (PVOID)ThreadProc, SizeOfCode, NULL);
		if (!bWriteOK)
			__leave;
		MyOutputDebugStringA("pCode = 0x%p",pCode);
		//创建远程线程，把ThreadProc作为线程起始函数，pThreadData作为参数;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pCode, pThreadData);
		if (hThread == NULL)
			__leave;
		//等待完成;
		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(hProcess, pThreadData, 0, MEM_RELEASE);
		if (pCode != NULL)
			VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return bRet;
}

/*
BOOL InjectDll(const char *DllFullPath,const DWORD dwRemoteProcessId)
{
	EnableDebugPriv("SeDebugPrivilege");
	HANDLE hRemoteProcess;
	//打开远程线程
	hRemoteProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId);
	char *pszLibFileRemote;
	//使用VirtualAllocEx函数在远程进程的内存地址空间分配DLL文件名空间
	pszLibFileRemote=(char *)VirtualAllocEx(hRemoteProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	if (pszLibFileRemote==NULL)
	{
	//	printf("VirtualAllocEx失败\n");
		BOOL res;
		res=CloseHandle(hRemoteProcess);
		//cout<<"res "<<res<<endl;
		return FALSE;
	}
	//printf("%s",pszLibFileRemote);
	//使用WriteProcessMemory函数将DLL的路径名写入到远程进程的内存
	BOOL wres=false;
	wres=WriteProcessMemory(hRemoteProcess,pszLibFileRemote,(void *)DllFullPath,lstrlenA(DllFullPath)+1,NULL);
	if (wres==FALSE)
	{
		VirtualFreeEx(hRemoteProcess,pszLibFileRemote,0,MEM_RELEASE);
		CloseHandle(hRemoteProcess);
		return FALSE;
	}
	DWORD dwID;
	LPVOID pFunc = LoadLibraryA;
	//FARPROC pFunAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"),"FreeLibrary");  
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc, pszLibFileRemote, 0, &dwID );
	if (hRemoteThread==NULL)
	{
		BOOL res1,res2;
		res1=CloseHandle(hRemoteThread);
		VirtualFreeEx(hRemoteProcess,pszLibFileRemote,0,MEM_RELEASE);
		res2=CloseHandle(hRemoteProcess);
		//cout<<"res1 "<<res1<<endl;
		//cout<<"res2 "<<res2<<endl;
		//printf("CreateRemoteThread失败\n");
		//printf("%d",GetLastError());
		return FALSE;
	}
	//释放句柄
	CloseHandle(hRemoteThread);
	CloseHandle(hRemoteProcess);
	return TRUE;
}
*/
void InjectAll()
{
	EnableDebugPrivilege();
	
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
	WCHAR mondll32path[MAX_PATH];
	WCHAR mondll64path[MAX_PATH];
	WCHAR easyhookdll32path[MAX_PATH];
	WCHAR easyhookdll64path[MAX_PATH];
	GetCurrentDirectoryW ( MAX_PATH, mondll64path ) ;
	GetCurrentDirectoryW ( MAX_PATH, mondll32path ) ;
	GetCurrentDirectoryW ( MAX_PATH, easyhookdll64path ) ;
	GetCurrentDirectoryW ( MAX_PATH, easyhookdll32path ) ;
	wcscat_s ( mondll32path, L"\\MonDll32.dll" ) ;
	wcscat_s ( mondll64path, L"\\MonDll64.dll" ) ;
	wcscat_s ( easyhookdll64path, L"\\MonDll64.dll" ) ;
	wcscat_s ( easyhookdll32path, L"\\MonDll32.dll" ) ;
	//cout<<mondll32path<<endl;
	//cout<<mondll64path<<endl;
	//cout<<easyhookdll64path<<endl;
	//ofstream f("C:/dll.txt",ios::app);
	while (bmore)
	{
		if (Is64BitPorcess(pe32.th32ProcessID) == 1)//64位不管
		{
			bmore=Process32Next(hprocesssnap,&pe32);
			continue;
		}
		
		//f<<pe32.szExeFile<<endl;
		if(strcmp(pe32.szExeFile, "MonInject64.exe") == 0
			||strcmp(pe32.szExeFile, "MonInject32.exe") == 0
			||strcmp(pe32.szExeFile, "UsMon.exe") == 0
			)

		{
			bmore=Process32Next(hprocesssnap,&pe32);
			continue;
		}
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
			int t1=strcmp(pes.szModule,"MonDll32.dll");
			int t2=strcmp(pes.szModule,"MonDll64.dll");
			int t3=strcmp(pes.szModule,"EasyHook64.dll");
			int t4=strcmp(pes.szModule,"EasyHook32.dll");
			if (t1==0||t2==0||t3==0||t4==0)
			{
				check=0;
				//cout<<pes.szExePath<<endl;
				break;
			}
			i=Module32Next(hfilename,&pes);
		}
		if (check==1)
		{
		//	printf(easyhookdll32path);
		//	printf("\n");
		//	InjectDll(easyhookdll32path,pe32.th32ProcessID);
			//Sleep(500);
		//	printf(mondll32path);
		//	printf("\n");
			InjectDll(pe32.th32ProcessID, mondll32path);
		}
		CloseHandle(hfilename);
		bmore = Process32Next(hprocesssnap , &pe32);
	}
	//f.close();
	CloseHandle(hprocesssnap);
	
	return;
}

void Prepare(){
	EnableDebugPrivilege();
	char exepath[MAX_PATH];
	GetModuleFileNameA(NULL,exepath,MAX_PATH);
	string str(exepath);
	int end=strlen(exepath)-15;
	dirpath=str.substr(0,end);
	
	sprintf_s(status,"%sUsMon.exe.status",dirpath.c_str());
	ofstream file(status);
	file<<"1";
	file.close();
	//cout<<exepath<<endl;
	//cout<<dirpath.c_str()<<endl;

}
wchar_t* CharToWchar(const char* c)  
{  
   wchar_t *m_wchar;
    int len = MultiByteToWideChar(CP_ACP,0,c,strlen(c),NULL,0);  
    m_wchar=new wchar_t[len+1];  
    MultiByteToWideChar(CP_ACP,0,c,strlen(c),m_wchar,len);  
    m_wchar[len]='\0';  
    return m_wchar;  
}
//int main(int argc, CHAR* argv[])

int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR     lpCmdLine,
	_In_ int       nCmdShow
	)

{
	/*
	time_t rawtime; 
	struct tm * timeinfo; 
	time ( &rawtime ); 
	timeinfo = localtime ( &rawtime ); 
	printf("当前系统时间: %s", asctime(timeinfo));
	Prepare();
	while (true)
	{
		Sleep(5000);
		InjectAll();
	}
	time(&rawtime);
	timeinfo = localtime ( &rawtime ); 
	printf("当前系统时间: %s", asctime(timeinfo));
	return 0;
	*/
	/*
	int a=0;
	cin>>a;
	BOOL res=FALSE;
	IsWow64Process(GetCurrentProcess(),&res);
	int r=0;
	r=GetProcessIsWOW64(a);
	if (r==0)
	{
		cout<<"64"<<endl;
	}else if(r==1)
	{
		cout<<"32"<<endl;
	}
	*/
	//UnInjectDll(argv[1],atoi(argv[2]));

	if (__argc==3)
	{
		InjectDll(atoi(__argv[2]), CharToWchar(__argv[1]));
	}else{
		Prepare();
		while (true)
		{
			/*
			ifstream fin(status);
			char temp[100];
			fin.get(temp,100,'\0');
			fin.close();
			cout<<temp<<endl;
			if (strcmp(temp,"2")==0)
			{
				ofstream of(status);
				of<<"1";
				of.close();
				return 0;
			}else{
				ofstream file(status);
				file<<"1";
				file.close();
			}
			*/
			InjectAll();
			Sleep(3000);
		}
	}
	//printf("%s %s %s",argv[0],argv[1],argv[2]);
	//char exe[100];
	//sprintf(exe,"D:\\MonInject.exe D:\\EasyHook32.dll %d",4648);
	//WinExec(exe,SW_HIDE);
	//InjectDll(argv[1],atoi(argv[2]));
    //cout<<argv[1]<<" "<<argv[2]<<endl;
	//InjectDll("D://EasyHook64.dll",3184);
	return 0;
}

