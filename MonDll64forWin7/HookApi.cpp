#include "HookApi.h"

//int GetFileNameByHandle(HANDLE hFile,LPSTR buff,DWORD size)
//{
//	HANDLE hfilemap = CreateFileMapping(hFile,NULL,PAGE_READWRITE,NULL,NULL,NULL);
//	if(INVALID_HANDLE_VALUE==hfilemap)
//	{
//		//printf("file mapping error");
//		return 0;
//	}
//
//
//	LPVOID lpmap = MapViewOfFile(hfilemap,FILE_MAP_READ|FILE_MAP_WRITE,NULL,NULL,0);
//	if(NULL==lpmap)
//	{
//		//printf("map view file error%d",GetLastError());
//		return 0;
//	}
//
//	//明明添加了Psapi.h 非说我GetMappedFileName没有声明
//	//    DWORD length = GetMappedFileName(GetCurrentProcess(),map,buff,size);
//
//	MyGetMappedFileName GetMappedFileName =(MyGetMappedFileName)GetProcAddress(LoadLibraryA("psapi.dll"),"GetMappedFileNameA");
//
//	if(GetMappedFileName==NULL)
//	{
//		//printf("Get funcaddress error");
//		return 0;
//	}
//	DWORD length = GetMappedFileNameA(GetCurrentProcess(),lpmap,buff,size);
//	if(0==length)
//	{
//		//printf("get mapped file name error");
//		return 0;
//
//	}
//	//    printf("%s",buff);
//
//
//	char DosPath[MAX_PATH]={0};
//	char DriverString[MAX_PATH]={0};
//
//	GetLogicalDriveStringsA(MAX_PATH,DriverString);
//	char * p = (char *)DriverString;  //p用来指向盘符
//	do
//	{
//		*(p+2)='\0'; //由于QuerDosDevice第一个参数必须是c:这种类型的，不能有\所以我把那个\给抹掉了  
//		QueryDosDeviceA(p,DosPath,MAX_PATH);
//		char * q = strstr(buff,DosPath);//检测buff中是否有DosDevice中的DosPath，有的话，p指向的那个字串就是要的盘符
//		if(q!=0)
//		{
//			//找到之后应该把buff中最后一个出现\地方的字串复制过来和盘符组成路径
//
//			q = strrchr(buff,0x5c);
//
//			//再把DriverString路径中其它字符清零，只留下找到的盘符
//			memset(p+2,0,MAX_PATH-2);
//			strcat_s(p,strlen(q),q);  //连接路径
//			strcpy_s(buff,strlen(p),p);
//			return 1;
//		}
//
//
//		p=p+4;  //指针移动到DriverString的下一个盘符处
//	}while(*p!=0);
//	return 0;
//}

char * GetProcessPath(){
	DWORD pid=(DWORD)_getpid();
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
	GetModuleFileNameEx(hProcess,NULL,pathname,MAX_PATH);
	int iLength ;
	iLength = WideCharToMultiByte(CP_ACP, 0, pathname, -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, pathname, -1, path, iLength, NULL, NULL);
	//OpenProcess之后一定要记住close
	CloseHandle(hProcess);
	return path;
}

char * LogTime(){
	time_t t=time(NULL);
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(tim,"%4d-%02d-%02d-%02d-%02d-%02d-%03d:\0",sys.wYear,sys.wMonth,sys.wDay,sys.wHour,sys.wMinute,sys.wSecond,sys.wMilliseconds);
	return tim;
}

//宽字符转化为多字节
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

char * GetDate(){
	time_t t=time(NULL);
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(dat,"%4d%02d%02d",sys.wYear,sys.wMonth,sys.wDay);
	return dat;
}

void GetProcessName(char* szProcessName,int* nLen){
	DWORD dwProcessID = GetCurrentProcessId();  
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,dwProcessID);   
	if(hProcess)  
	{  
		HMODULE hMod;  
		DWORD   dwNeeded;   
		if(EnumProcessModules(hProcess,&hMod,sizeof(hMod),&dwNeeded))  
		{  
			GetModuleBaseNameA(hProcess,hMod,szProcessName,*nLen);  
		}  
	}
	CloseHandle(hProcess);
}

std::string GetKeyPathFromKKEY(HKEY key)
{
	std::wstring keyPath;
	if (key==NULL)
	{
		return "NULL";
	}
	if (key != NULL)
	{
		HMODULE dll = LoadLibrary(L"ntdll.dll");
		if (dll != NULL) {
			typedef DWORD (__stdcall *ZwQueryKeyType)(
				HANDLE  KeyHandle,
				int KeyInformationClass,
				PVOID  KeyInformation,
				ULONG  Length,
				PULONG  ResultLength);

			ZwQueryKeyType func = reinterpret_cast<ZwQueryKeyType>(::GetProcAddress(dll, "ZwQueryKey"));

			if (func != NULL) {
				DWORD size = 0;
				DWORD result = 0;
				result = func(key, 3, 0, 0, &size);
				if (result == STATUS_BUFFER_TOO_SMALL)
				{
					size = size + 2;
					wchar_t* buffer = new (std::nothrow) wchar_t[size];
					if (buffer != NULL)
					{
						result = func(key, 3, buffer, size, &size);
						if (result == STATUS_SUCCESS)
						{
							buffer[size / sizeof(wchar_t)] = L'\0';
							keyPath = std::wstring(buffer + 2);
						}

						delete[] buffer;
					}
				}
			}

			FreeLibrary(dll);
		}
	}
	return WideToMutilByte(keyPath);
}

char * GetIPbySocket(SOCKET s){
	char *sock_ip;
	sockaddr_in sock;
	int socklen=sizeof(sock);
	//char sock_ip[]="NULL";
	//char sock_ip[1000]="NULL";
	getsockname(s,(struct sockaddr*)&sock,&socklen);
	sock_ip=inet_ntoa(sock.sin_addr);
	return sock_ip;
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
		//printf("LookupPrivilegeValueA失败");
	}
	tp.PrivilegeCount=1;
	tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid=luid;
	//调整权限
	if(!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
		//printf("AdjustTokenPrivileges失败");
	}
	CloseHandle(hToken);
	return 0;
}

BOOL InjectDll(const char *DllFullPath,const DWORD dwRemoteProcessId)
{
	HANDLE hRemoteProcess;
	EnableDebugPriv("SeDebugPrivilege");
	//打开远程线程
	hRemoteProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId);
	if (hRemoteProcess==NULL)
	{
		return FALSE;
	}
	char *pszLibFileRemote;
	//使用VirtualAllocEx函数在远程进程的内存地址空间分配DLL文件名空间
	pszLibFileRemote=(char *)VirtualAllocEx(hRemoteProcess,NULL,lstrlenA(DllFullPath)+1,MEM_COMMIT,PAGE_READWRITE);
	if (pszLibFileRemote==NULL)
	{
		CloseHandle(hRemoteProcess);
		return FALSE;
		//ofstream f("C:\\pro.txt",ios::app);
		//printf("VirtualAllocEx失败\n");
		//f<<"VirtualAllocEx失败"<<endl;
		//f.close();
	}
	//printf("%c",pszLibFileRemote);
	//printf("%d\n",GetLastError());
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
		//ofstream f("C:\\pro.txt",ios::app);
		//printf("CreateRemoteThread失败\n");
		//printf("%d",GetLastError());
		//f<<"CreateRemoteThread失败"<<endl;
		//f<<GetLastError()<<endl;
		//f.close();
		CloseHandle(hRemoteProcess);
		return FALSE;
	}
	//释放句柄
	CloseHandle(hRemoteProcess);
	CloseHandle(hRemoteThread);
	return TRUE;
}

//判断进程是否是64位，如果是64位返回0，如果是32位返回1
int GetProcessIsWOW64(DWORD pid)
{
	int nRet=-1;
	EnableDebugPriv("SeDebugPrivilege");
	HANDLE hProcess;

	//打开远程线程
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process; 
	BOOL bIsWow64 = FALSE; 
	BOOL bRet;
	DWORD nError;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle(L"kernel32"),"IsWow64Process"); 
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

//void GetFileNameFromHandle(HANDLE hFile,char myhandlepath[MAX_PATH]) 
//{
//	BOOL bSuccess = FALSE;
//	TCHAR pszFilename[MAX_PATH+1]={0};
//	HANDLE hFileMap;
//
//	// Get the file size.
//	DWORD dwFileSizeHi = 0;
//	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi); 
//	if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
//	{
//		strcpy_s(myhandlepath,5,"NULL");
//		return;
//		//_tprintf(TEXT("Cannot map a file with a length of zero.\n"));
//	}
//
//	// Create a file mapping object.
//	hFileMap = CreateFileMapping(hFile, 
//		NULL, 
//		PAGE_READONLY,
//		0, 
//		1,
//		NULL);
//
//	if (hFileMap) 
//	{
//		// Create a file mapping to get the file name.
//		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
//
//		if (pMem) 
//		{
//			if (GetMappedFileName (GetCurrentProcess(), 
//				pMem, 
//				pszFilename,
//				MAX_PATH)) 
//			{
//
//				// Translate path with device name to drive letters.
//				TCHAR szTemp[512];
//				szTemp[0] = '\0';
//
//				if (GetLogicalDriveStrings(512-1, szTemp)) 
//				{
//					TCHAR szName[MAX_PATH];
//					TCHAR szDrive[3] = TEXT(" :");
//					BOOL bFound = FALSE;
//					TCHAR* p = szTemp;
//
//					do 
//					{
//						// Copy the drive letter to the template string
//						*szDrive = *p;
//
//						// Look up each device name
//						if (QueryDosDevice(szDrive, szName, MAX_PATH))
//						{
//							size_t uNameLen = _tcslen(szName);
//
//							if (uNameLen < MAX_PATH) 
//							{
//								bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
//									&& *(pszFilename + uNameLen) == _T('\\');
//
//								if (bFound) 
//								{
//									// Reconstruct pszFilename using szTempFile
//									// Replace device path with DOS path
//									TCHAR szTempFile[MAX_PATH];
//									StringCchPrintf(szTempFile,
//										MAX_PATH,
//										TEXT("%s%s"),
//										szDrive,
//										pszFilename+uNameLen);
//									StringCchCopyN(pszFilename, MAX_PATH+1, szTempFile, _tcslen(szTempFile));
//								}
//							}
//						}
//
//						// Go to the next NULL character.
//						while (*p++);
//					} while (!bFound && *p); // end of string
//				}
//			}
//			bSuccess = TRUE;
//			UnmapViewOfFile(pMem);
//		}
//		CloseHandle(hFileMap);
//	}
//	//_tprintf(TEXT("File name is %s\n"), pszFilename);
//	if (lstrlen(pszFilename)==0||lstrlen(pszFilename)>MAX_PATH)
//	{
//		strcpy_s(myhandlepath,5,"NULL");
//		return ;
//	}
//	string tempfilepath;
//	//wprintf(pszFilename);
//	tempfilepath=WideToMutilByte(pszFilename);
//	strcpy_s(myhandlepath,strlen(tempfilepath.c_str())+1,tempfilepath.c_str());
//}

void WriteLog(string s){
	s=s+"\n";
	extern HANDLE g_handleMailServer;
	extern LPTSTR g_strInjectMailSlot;
	cout<<s;
	if (g_handleMailServer != INVALID_HANDLE_VALUE)
	{
		DWORD cbWritten = 0;
		BOOL result = realWriteFile?realWriteFile(g_handleMailServer,s.c_str(),s.length(),&cbWritten,NULL):WriteFile(g_handleMailServer,s.c_str(),s.length(),&cbWritten,NULL);
		//成功的话就直接退出
		//////////////////////////////////////////////////////////////////////////
		// to do :不成功的话可以做一次判断，如果邮箱服务端已经退出，则将g_handleMailServer置为无效
		//////////////////////////////////////////////////////////////////////////
		if (result)
			return;
	}
	
	
	ofstream f(g_log_path,ios::app);
	f<<s;
	f.close();
	
}
