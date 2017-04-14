// InjectDll.cpp : 定义控制台应用程序的入口点。
//

#include "iostream"
#include "windows.h"
#include "TLHELP32.H"
#include "fstream"
#include <string.h>
#include "sstream"
#include "Psapi.h"
#include "MyOutputDebugString.h"

using namespace std;

ofstream f2("C:/test.txt",ios::app);

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

//操作系统版本判断


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


//OD跟踪，发现最后调用的是NtCreateThreadEx,所以这里手动调用
HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;
	pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if( pFunc == NULL )
	{
	    MyOutputDebugStringA("MyCreateRemoteThread() : GetProcAddress(\"NtCreateThreadEx\") 调用失败！错误代码: [%d]", GetLastError());
		return NULL;
	}
	((_NtCreateThreadEx64)pFunc)(&hThread,0x1FFFFF,NULL,hProcess,pThreadProc,pRemoteBuf,FALSE,NULL,NULL,NULL,NULL);
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
	MyOutputDebugStringA("%d", dwProcessId);
	OutputDebugStringW(lpcwDllPath);
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	LPVOID pCode = NULL;
	LPVOID pThreadData = NULL;
	__try
	{
		if(!EnableDebugPrivilege())
		{
			MyOutputDebugStringA("InjectDll() : EnableDebugPrivilege() 调用失败！错误代码: [%d]", GetLastError());
			return -1;
		}
		//打开目标进程;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
		DWORD dwError = GetLastError();
		if (hProcess == NULL)
			return FALSE;
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
			return FALSE;
		BOOL bWriteOK = WriteProcessMemory(hProcess, pThreadData,&data,sizeof(data), NULL);
		if (!bWriteOK)
			return FALSE;
		//MyOutputDebugStringA("pThreadData = 0x%p", pThreadData);
		f2<<pThreadData<<endl;
		//写入代码;
		//MyOutputDebugStringA("%d\n", (DWORD)ThreadProcEnd);
		f2<<ThreadProcEnd<<endl;
		//MyOutputDebugStringA("%d\n", (DWORD)ThreadProc);
		f2<<ThreadProc<<endl;
		DWORD SizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		//MyOutputDebugStringA("%d\n", (DWORD)SizeOfCode);
		f2<<SizeOfCode<<endl;
		pCode = VirtualAllocEx(hProcess, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
		{
			//MyOutputDebugStringA("InjectDll() : pCode = VirtualAllocEx() 调用失败！错误代码: [%d]", GetLastError());
			f2<<"InjectDll() : pCode = VirtualAllocEx() 调用失败！错误代码:"<<GetLastError()<<endl;
			return FALSE;
		}		
		bWriteOK = WriteProcessMemory(hProcess, pCode, (PVOID)ThreadProc, SizeOfCode, NULL);
		if (!bWriteOK)
			return FALSE;
		//MyOutputDebugStringA("pCode = 0x%p", pCode);
		f2<<pCode<<endl;
		//创建远程线程，把ThreadProc作为线程起始函数，pThreadData作为参数;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pCode, pThreadData);
		if (hThread == NULL)
			return FALSE;
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

//判断进程是否是64位
BOOL Is64BitPorcess(DWORD dwProcessID)
{
	EnableDebugPrivilege();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,dwProcessID);
	if(hProcess)
    {
		typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandleW(L"kernel32"),"IsWow64Process");
        BOOL bIsWow64 = FALSE;
        fnIsWow64Process(hProcess,&bIsWow64);
        CloseHandle(hProcess);
        if (bIsWow64)
        {
			return FALSE;
        }
        else
        {
			return TRUE;
        }
    }
    return TRUE;
}
/*
int GetProcessIsWOW64(int pid)
{
	int nRet=-1;
	//EnableDebugPriv("SeDebugPrivilege");
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
*/
void InjectAll()
{
	//ofstream f1("C:/test.txt",ios::app);
	EnableDebugPrivilege();
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
	WCHAR mondll32path[MAX_PATH];
	WCHAR mondll64path[MAX_PATH];
	WCHAR easyhookdll64path[MAX_PATH];
	GetCurrentDirectoryW ( MAX_PATH, mondll64path ) ;
	GetCurrentDirectoryW ( MAX_PATH, mondll32path ) ;
	GetCurrentDirectoryW ( MAX_PATH, easyhookdll64path ) ;
	wcscat_s ( mondll32path, L"\\MonDll32.dll" ) ;
	wcscat_s ( mondll64path, L"\\MonDll64.dll" ) ;
	wcscat_s ( easyhookdll64path, L"\\MonDll64.dll" ) ;
	//stringstream str;
	//sprintf(mondll32path,"%sMonDll32.dll",dirpath.c_str());
	//sprintf(mondll64path,"%sMonDll64.dll",dirpath.c_str());
	//sprintf(easyhookdll64path,"%sEasyHook64.dll",dirpath.c_str());
	//cout<<mondll32path<<endl;
	//cout<<mondll64path<<endl;
	//cout<<easyhookdll64path<<endl;
	//ofstream f("C:/dll.txt",ios::app);
	while (bmore)
	{
		int r=0;
		if (Is64BitPorcess(pe32.th32ProcessID) == 0)//32位不管
		{
			bmore=Process32Next(hprocesssnap,&pe32);
			continue;
		}
		//f<<pe32.szExeFile<<endl;  ||strcmp(pe32.szExeFile, "svchost.exe") == 0
		if(strcmp(pe32.szExeFile, "MonInject64.exe") == 0
			||strcmp(pe32.szExeFile, "MonInject32.exe") == 0
			||strcmp(pe32.szExeFile, "UsMon.exe") == 0
			)
		{
			bmore=Process32Next(hprocesssnap,&pe32);
			continue;
		}

		//f1<<pe32.szExeFile<<endl;

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
			if (t1==0||t2==0||t3==0)
			{
				check=0;
				cout<<pes.szExePath<<endl;
				break;
			}
			i=Module32Next(hfilename,&pes);
		}
		if (check==1)
		{

			//str<<pes.szExePath;
			//string st = str.str();
			//f1<<pes.szExePath<<endl;
			//str.clear();
			
			bool flag = InjectDll ( pe32.th32ProcessID, mondll64path) ;
			//if(flag)
			//	f1<<"ture"<<endl;
			//else 
			//	f1<<"flase"<<endl;
			
		}
		CloseHandle(hfilename);
		bmore = Process32Next(hprocesssnap , &pe32);
	}
	//f1.close();
	CloseHandle(hprocesssnap);
	return;
}

void Prepare(){
	EnableDebugPrivilege();
	char exepath[MAX_PATH];
	string dirpath;
	GetModuleFileNameA(NULL,exepath,MAX_PATH);
	string str(exepath);
	int end=strlen(exepath)-15;
	dirpath=str.substr(0,end);
	char status[MAX_PATH];
	sprintf_s(status,"%sUsMon.exe.status",dirpath.c_str());
	ofstream file(status);
	file<<"1";
	file<<exepath;
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
	//f2<<"flag"<<endl;
	
	if (__argc==3)
	{
		InjectDll(atoi(__argv[2]), CharToWchar(__argv[1]));
	}
	else
	{
	Prepare();

	while (true)
	{
		InjectAll();
		Sleep(3000);
	}
	}
	//}
	/*
	while (true)
	{
		Sleep(1000*60);
		InjectAll();

	}
	*/
	f2.close();
	return 0;
}

