// APIHookTest.cpp : 定义控制台应用程序的入口点。
//
//#define _UNICODE

#include "stdafx.h"
//#include <afx.h>>
#include <Windows.h>
#include <WinBase.h>
#include <stdio.h>
#include <iostream>
#include <wincrypt.h>
#include <locale.h>
#include <TlHelp32.h>
#include <Wininet.h>
#include <vector>


using namespace std;
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib,"Urlmon.lib")
#define SERVICE_NAME_W L"1,0,0,1"
//#define _AFXDLL
//FindFirstFileW,FindNextFileW test.

void TraverseFolder(LPCTSTR lpPath)
{
    TCHAR szFind[MAX_PATH] = {_T("\0")};
    WIN32_FIND_DATA findFileData;
    BOOL bRet;
 
    _tcscpy_s(szFind, MAX_PATH, lpPath);
    _tcscat_s(szFind, _T("\\*.*"));     //这里一定要指明通配符，不然不会读取所有文件和目录
 
    HANDLE hFind = ::FindFirstFile(szFind, &findFileData);
	//MessageBoxA(NULL,"FindFirstFile executed","APIHookTest",MB_OK);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        return;
    }
 
    //遍历文件夹
    while (TRUE)
    {
        if (findFileData.cFileName[0] != _T('.'))
        {//不是当前路径或者父目录的快捷方式
            _tprintf(_T("%s\\%s\n"), lpPath, findFileData.cFileName);
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {//这是一个普通目录
                //设置下一个将要扫描的文件夹路径
                _tcscpy_s(szFind, MAX_PATH, lpPath);    
                _tcscat_s(szFind, _T("\\"));    
                _tcscat_s(szFind, findFileData.cFileName);
                ///_tcscat_s(szNextDir, _T("\\*"));
                //遍历该目录
                TraverseFolder(szFind);
            }
        }
        //如果是当前路径或者父目录的快捷方式，或者是普通目录，则寻找下一个目录或者文件
        bRet = ::FindNextFile(hFind, &findFileData);
        if (!bRet)
        {//函数调用失败
            //cout << "FindNextFile failed, error code: " 
            //  << GetLastError() << endl;
            break;
        }
    }
	//MessageBoxA(NULL,"FindNextFile Executed","APIHookTest",MB_OK);
 
    ::FindClose(hFind);
}
//SetWindowsHookExW
HHOOK g_hMouse=NULL;
LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	return 1;
}


int _stdcall _tWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR lpCmdLine,
    int nCmdShow
)
{
	/*
	Sleep(10000);
	cout<<"10s passed"<<endl;
	Sleep(10000);
	cout<<"20s passed";
	Sleep(10000);
	cout<<"30s passed"<<endl;
	*/
	char windire[100]="C:\\Program Files (x86)";
	//GetSystemDirectoryA(windire, 100 );
	getchar();
	BOOL bRetA;
	BOOL bRetW;
	DWORD dwWritenSize;
	LoadLibrary(L"MonDll32.dll");
	//CreateFile
	HANDLE hOpenFileA=(HANDLE)CreateFileA("E:\\testAPIHook\\a.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,NULL,NULL);
	if(hOpenFileA==INVALID_HANDLE_VALUE){ 
		hOpenFileA=NULL;
		//MessageBoxA(NULL,"Open file failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"Open file successfully!","APIHookTest",MB_OK);
	}
	if((bRetA=WriteFile(hOpenFileA,"GOODGOOD",sizeof("GOODGOOD"),&dwWritenSize,NULL))==TRUE){
		//MessageBoxA(NULL,"Write successfull with A!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"Write failed with A!","APIHookTest",MB_OK);
	}

	//CreateFileW
	HANDLE hOpenFileW=(HANDLE)CreateFileW(L"E:\\testAPIHook\\b.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,NULL,NULL);
	if(hOpenFileW==INVALID_HANDLE_VALUE){
		hOpenFileW=NULL;
		//MessageBoxA(NULL,"Open file failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"Open file successfully!","APIHookTest",MB_OK);
	}
	if((bRetA=WriteFile(hOpenFileW,"GOODGOOD",sizeof("GOODGOOD"),&dwWritenSize,NULL))==TRUE){
		//MessageBoxA(NULL,"Write successfull with W!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"Write failed with W!","APIHookTest",MB_OK);
	}

	//MoveFileW
	BOOL bMoveFileW=MoveFileW(L"E:\\a.txt",L"F:\\c.txt");
	DWORD errorCode=GetLastError();
	if(bMoveFileW==0){
		//MessageBoxA(NULL,"MoveFileW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"MoveFileW success","APIHookTest",MB_OK);
	}


	//CopyFileW
	BOOL bCopyFileW=CopyFileW(L"F:\\c.txt",L"E:\\a.txt",FALSE);
	if(bCopyFileW==0){
		//MessageBoxA(NULL,"CopyFileW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"CopyFileW success","APIHookTest",MB_OK);
	}

	//DeleteFileW
	BOOL bDeleteFileW=DeleteFileW(L"F:\\c.txt");
	if(bDeleteFileW==0){
		//MessageBoxA(NULL,"DeleteFileW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"DeleteFileW success","APIHookTest",MB_OK);
	}

	//FindFirstFileW
	//FindNextFileW
	//TraverseFolder(_T("E:"));

    //CertOpenSystemStoreW
	HCERTSTORE    hSystemStore;//system store handle
	if(hSystemStore=CertOpenSystemStoreW(0,L"CA")){
		//printf("The CA system store is open. Continue.\n");
	}else{
		//printf("The CA system store did not open.\n");
        //exit(1);
	}
	//Use the store as needed.
	//...
	if(!CertCloseStore(hSystemStore,0)){
		printf("Unable to close the CA system store.\n");
        //exit(1);
	}
	

	//CreateMutexW
	HANDLE m_hMutex=CreateMutexW(NULL,FALSE,L"Sample07");
	if(GetLastError()==ERROR_ALREADY_EXISTS){
		CloseHandle(m_hMutex);
		m_hMutex=NULL;
		printf("ERROR_ALREADY_EXISTS with CreateMutexW.\n");
		return TRUE;
	}
	printf("CreateMutexW Sucess!.\n");

	//FindResourceW
	HRSRC hRsrc=FindResourceW(NULL,L"loader.html",RT_HTML);
	if(hRsrc==NULL){
		//MessageBoxA(NULL,"FindResourceW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"FindResourceW success","APIHookTest",MB_OK);
	}

	//FindWindowW
	HWND hwnd=FindWindowW(L"Progman",NULL);
	if(hwnd==NULL){
		//MessageBoxA(NULL,"FindWindowW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"FindWindowW Success!","APIHookTest",MB_OK);
	}

	//GetWindowsDirectoryW
	wstring wstr;
	UINT size=GetWindowsDirectory(NULL,0);
	wchar_t *path=new wchar_t[size];
	if(GetWindowsDirectoryW(path,size)!=0){
		wstr=path;
		//MessageBoxA(NULL,"GetWindowsDirectoryW Success!","APIHookTest",MB_OK);
	}
	delete []path;

	//MapVirtualKeyW
	UINT uMapVirtualKeyW=MapVirtualKeyW(VK_CONTROL,0);
	if(uMapVirtualKeyW==0){
		//MessageBoxA(NULL,"MapVirtualKeyW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"MapVirtualKeyW Success!","APIHookTest",MB_OK);
	}

	//OpenMutexW
	HANDLE hOpenMutexW=OpenMutexW(MUTEX_ALL_ACCESS,TRUE,L"Sample07");
	if(hOpenMutexW==NULL){
		//MessageBoxA(NULL,"OpenMutexW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"OpenMutexW Success!","APIHookTest",MB_OK);
	}

	//OpenSCManagerW
	SC_HANDLE hOpenSCManagerW=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(hOpenSCManagerW==NULL){
		//MessageBoxA(NULL,"OpenSCManagerW failed!","APIHookTest",MB_OK);
	}else{
		//MessageBoxA(NULL,"OpenSCManagerW Success!","APIHookTest",MB_OK);
	}

	//CreateServiceW
	TCHAR szFilePath[MAX_PATH];
	GetModuleFileName(NULL,szFilePath,MAX_PATH);
	SC_HANDLE hService =CreateServiceW(
        hOpenSCManagerW, L"szServiceName", L"szServiceName",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        szFilePath, NULL, NULL, L"", NULL, NULL);
 
    if (hService == NULL)
    {
        CloseServiceHandle(hOpenSCManagerW);
		//MessageBoxA(NULL,"CreateServiceW failed!","APIHookTest",MB_OK);
    }else{
		//MessageBoxA(NULL,"CreateServiceW Success!","APIHookTest",MB_OK);
	}

	//GetModuleFileNameEx
	typedef DWORD (WINAPI *GETMODULEFILENAMEEX)(HANDLE hProcess,HMODULE hModule,LPTSTR lpFilename,DWORD nsize);
	HMODULE hMod=LoadLibrary(L"Kernel32.dll");
	GETMODULEFILENAMEEX GetModuleFileNameEx=(GETMODULEFILENAMEEX)GetProcAddress(hMod,"K32GetModuleFileNameExW");
	printf("K32ModuleAddress is 0x%x:",GetModuleFileNameEx);
	HWND hWnd = FindWindow(NULL,L"计算器");
    DWORD Pid;
    GetWindowThreadProcessId(hWnd,&Pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,Pid);
    TCHAR pBuffer[MAX_PATH+1];
    DWORD dwGetModuleFileNameExW=GetModuleFileNameEx(hProcess,NULL,pBuffer,MAX_PATH+1);
	if(0==dwGetModuleFileNameExW){
	    cout<<"GetModuleFileNameExW failed!"<<endl;
    //MessageBoxA(NULL,"GetModuleFileNameExW failed!","APIHookTest",MB_OK);
	}else{
		cout<<"GetModuleFileNameExW success!"<<endl;
          //MessageBoxA(NULL,"GetModuleFileNameExW Success!","APIHookTest",MB_OK);
	}

	//GetModuleHandle
	HMODULE hGetModuleHandleW=GetModuleHandleW(NULL);
	if(hGetModuleHandleW==NULL){
		cout<<"GetModuleHandleW failed"<<endl;
		//MessageBoxA(NULL,"GetModuleHandleW failed!","APIHookTest",MB_OK);
	}else{
		cout<<"GetModuleHandleW success!"<<endl;
		//MessageBoxA(NULL,"GetModuleHandleW Success!","APIHookTest",MB_OK);
	}

	//GetStartupInfoW
	//GetVersionExW
	cout<<"Start GetStartupInfo Test."<<endl;
	STARTUPINFO si;
    GetStartupInfo(&si);

	//GetVersionExW
	cout<<"Start GetStartupInfo Test."<<endl;
	OSVERSIONINFOEX os;  
    os.dwOSVersionInfoSize=sizeof(os);  
    if(!GetVersionEx((OSVERSIONINFO *)&os))  
    {
		cout<<"GetVersionExW failed!"<<endl; 
    }else{
		cout<<"GetVersionExW success!"<<endl;
	}

	//LoadLibraryW
	HMODULE hDllLib=LoadLibrary(L"Kernel32.dll");
	if(hDllLib){
		cout<<"LoadLibraryW success!"<<endl;
		FreeLibrary(hDllLib);
	}else{
		cout<<"LoadLibraryW failed!"<<endl;
	}

	//OutputDebugStringW
	//CString strDebugOutput;
	//strDebugOutput.Format(L"OutputDebugStringW debug info.",18);
	//cout<<"Executing func OutputDebugStringW"<<endl;
	//OutputDebugStringW(L"OutputDebugStringW");

	////SetWindowsHookExW
	g_hMouse=SetWindowsHookExW(WH_MOUSE,MouseProc,GetModuleHandle(L"Hook"),0);
	if(g_hMouse==NULL){
		cout<<"SetWindowsHookExW failed!"<<endl;
	}else{
		cout<<"SetWindowsHookExW success!"<<endl;
	}

	//ShellExecuteW
	cout<<"ShellExecuteW1 executing!"<<endl;
	ShellExecuteW(NULL,L"open",L"iLoveu.bmp",NULL,NULL,SW_SHOWNORMAL);
	cout<<"ShellExecuteW1 executed!"<<endl;
	cout<<"ShellExecuteW2 executing!"<<endl;
	ShellExecute(NULL, L"open", L"http://www.microsoft.com", NULL, NULL, SW_SHOWNORMAL);
	cout<<"ShellExecuteW2 executed!"<<endl;

	//StartServiceCtrlDispatcher
	VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR *lpszArgv);
	SERVICE_TABLE_ENTRYW lpServiceStartTable[] =   
    {  
        {SERVICE_NAME_W, ServiceMain},  
        {NULL, NULL}  
     };
	if(!StartServiceCtrlDispatcherW(lpServiceStartTable))  
    {  
        cout<<"StartServiceCtrlDispatcherW failed!"<<endl;  
    } 

	//RegOpenKeyW
	HKEY hKey=NULL;
	LONG iResult;
	iResult=RegOpenKeyW(HKEY_LOCAL_MACHINE,L"System\\CurrentControlSet\\Control\\ProductOptions",&hKey);
	if(iResult==ERROR_SUCCESS){
		cout<<"RegOpenKeyW success!"<<endl;
	}else{
		cout<<"RegOpenKeyW failed!"<<endl;
	}

	//Module32First
	//Module32Next
	MODULEENTRY32W me32;
	MODULEENTRY32 me321;

	//setlocale(LC_ALL,"chs");
	HANDLE hTlhelpSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
	Module32FirstW(hTlhelpSnapshot,&me32);
	//cout<<"func addr of Module32FirstW in test proc:"<<Module32FirstW<<endl;
	Module32First(hTlhelpSnapshot,&me321);
	//cout<<"func addr of Module32First in test proc:"<<Module32First<<endl;
	Module32NextW(hTlhelpSnapshot,&me32);
    //cout<<"func addr of Module32NextW in test proc:"<<Module32NextW<<endl;
	Module32Next(hTlhelpSnapshot,&me321);
	//cout<<"func addr of CreateFileW in test proc:"<<CreateFileW<<endl;

	//int * module32first_addrW=(int *)GetProcAddress(h_kernel32,"Module32FirstW");

	if(INVALID_HANDLE_VALUE==hTlhelpSnapshot){
		cout<<"CreateToolhelp32Snapshot failed!"<<endl;
	}else{
		me32.dwSize=sizeof(MODULEENTRY32);
		DWORD nCount=0;
		if(!Module32FirstW(hTlhelpSnapshot,&me32)){
			cout<<"获取进程第一个模块信息失败！"<<endl;
		}else{
			do
			{
				++nCount;
				wprintf_s(L"\n ---->  me32.dwSize==%x\n",me32.dwSize);
                wprintf_s(L"\n ---->  me32.GlblcntUsage==%x\n",me32.GlblcntUsage);
                wprintf_s(L"\n ---->  me32.hModule==%x\n",me32.hModule);
                wprintf_s(L"\n ---->  me32.modBaseAddr==%x\n",me32.modBaseAddr);
                wprintf_s(L"\n ---->  me32.ProccntUsage==%x\n",me32.ProccntUsage);
                wprintf_s(L"\n ---->  me32.szExePath==%s\n",me32.szExePath);
                wprintf_s(L"\n ---->  me32.szModule==%s\n",me32.szModule);
                wprintf_s(L"\n ---->  me32.th32ModuleID==%x\n",me32.th32ModuleID);
                wprintf_s(L"\n ---->  me32.th32ProcessID==%x\n",me32.th32ProcessID);
                wprintf_s(L"\n ---->  模块数==%d\n",nCount);
			}while(Module32NextW(hTlhelpSnapshot,&me32));
		}
	}


	//InternetOpenW
	string userAgent="Mozilla";        string nill="";
	HINTERNET hSession=InternetOpenW(L"Mozilla",INTERNET_OPEN_TYPE_PRECONFIG,L"",L"",0);
	if(NULL==hSession){
		cout<<"InternetOpenW error!"<<endl;
	}else{
		cout<<"InternetOpen success!"<<endl;
	}

	//InternetOpenUrlW
	vector<char> v;
	TCHAR szUrl[]=L"http://www.baidu.com/";
	TCHAR szAgent[]=L"";
	HINTERNET hInternet1=InternetOpenW(NULL,INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,NULL);
	if(NULL==hInternet1){
		cout<<"InternetOpenW failed"<<endl;
		InternetCloseHandle(hInternet1);
	}
	HINTERNET hInternet2 = InternetOpenUrlW(hInternet1,szUrl,NULL,NULL,INTERNET_FLAG_NO_CACHE_WRITE,NULL);
	if(NULL==hInternet2){
		cout<<"InternetOpenUrlW failed"<<endl;
		InternetCloseHandle(hInternet2);
		InternetCloseHandle(hInternet1);
	}
	DWORD dwMaxDataLength = 500;
    PBYTE pBuf = (PBYTE)malloc(dwMaxDataLength*sizeof(TCHAR));
    if (NULL == pBuf)
     {
        InternetCloseHandle(hInternet2);
        InternetCloseHandle(hInternet1);
     }
	DWORD dwReadDataLength = NULL;
    BOOL bRet = TRUE;
    do 
    {
        ZeroMemory(pBuf,dwMaxDataLength*sizeof(TCHAR));
        bRet = InternetReadFile(hInternet2,pBuf,dwMaxDataLength,&dwReadDataLength);
        for (DWORD dw = 0;dw < dwReadDataLength;dw++)
         {
            v.push_back(pBuf[dw]);
         }
     } while (NULL != dwReadDataLength);
	vector<char>::iterator i;
    for(i=v.begin(); i!=v.end(); i++)
        printf("%c",*i);


	//URLDownloadToFileW
	HRESULT hResult=URLDownloadToFileW(NULL,L"http://img.baidu.com/img/logo-zhidao.gif",L"E:\\a.gif",0,0);
	if(S_OK==hResult){
		cout<<"URLDownloadToFileW success!"<<endl;
	}else{
		cout<<"URLDownloadToFileW failed!"<<endl;
	}


	//FtpPutFileW(hInternet2, L"D:\\Readme.txt", L".\\a.txt", FTP_TRANSFER_TYPE_BINARY, 0);//这个函数调用容易出错。


	//RegCreateKeyEx
	HKEY hAppKey=NULL;
	HKEY hSoftKey=NULL;
	HKEY hCompanyKey=NULL;
	if (RegOpenKeyExA(HKEY_CURRENT_USER,"software", 0, KEY_WRITE|KEY_READ,&hSoftKey) == ERROR_SUCCESS){
		cout<<"RegOpenKeyExA success!"<<endl;
        DWORD dw;
        //创建并打开HKEY_CURRENT_USER/"Software"/"Wincpp"
        if (RegCreateKeyExA(hSoftKey, "Wincpp", 0, REG_NONE,REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,&hCompanyKey, &dw) == ERROR_SUCCESS)
        {
             //创建并打开HKEY_CURRENT_USER/"Software"/"Wincpp"/"testreg"
             RegCreateKeyExA(hCompanyKey, "testreg", 0, REG_NONE,REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,&hAppKey, &dw);
         }
    }
    //关闭打开的键值。
    if (hSoftKey != NULL){
       RegCloseKey(hSoftKey);
    }   
 
    if (hCompanyKey != NULL){
       RegCloseKey(hCompanyKey);
    }


	HKEY Hkey=NULL;
	LONG ret = RegCreateKeyW(HKEY_CURRENT_USER,L"Software\Microsoft\Internet Explore\Main", &Hkey);
	if(ERROR_SUCCESS==ret){
		cout<<"RegCreateKeyA success!"<<endl;
	}else{
		cout<<"RegCreateKeyA failed!"<<endl;
	}
	HKEY hkey=0;
	LONG ret1=RegCreateKeyW(HKEY_LOCAL_MACHINE,L"Software\\mykey",&hkey);
	if(ERROR_SUCCESS==ret1){
		cout<<"RegCreateKeyA success!"<<endl;
	}else{
		cout<<"RegCreateKeyA failed!"<<endl;
	}


	//RegQueryValueEx
	HKEY hKeynew; 
    DWORD dwType = REG_SZ; 
    DWORD dwSize; 
    wchar_t data[MAX_PATH]; 
    bool retValue;
    retValue = RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE//Microsoft//Windows NT//CurrentVersion", &hKeynew);
    if(ERROR_SUCCESS==RegQueryValueExW(hKey,L"ProductName", NULL,&dwType, (LPBYTE)data, &dwSize)){
		cout<<"RegQueryValueExW success!"<<endl;
	}else{
		cout<<"RegQueryValueExW failed!"<<endl;
	}
    retValue = wcscmp(data, L"Microsoft Windows XP") == 0;


	//RegQueryValue(A/W)
	if(ERROR_SUCCESS==RegQueryValueA(HKEY_CURRENT_USER,"Software\Microsoft\Internet Explore\Main",NULL,NULL)){
		cout<<"RegQueryValueA success!"<<endl;
	}else{
		cout<<"RegQueryValueA failed!"<<endl;
	}
	if(ERROR_SUCCESS==RegQueryValueW(HKEY_CURRENT_USER,L"Software\Microsoft\Internet Explore\Main",NULL,NULL)){
		cout<<"RegQueryValueW success!"<<endl;
	}else{
		cout<<"RegQueryValueW failed!"<<endl;
	}


	//RegSetValueEx(A/W)
	char *szValue="1";
	if(ERROR_SUCCESS==RegOpenKeyExA(HKEY_CURRENT_USER,"Control Panel\\Desktop\\WindowMetrics",0,KEY_WRITE,&hKey)){
		cout<<"RegOpenKeyExA success!"<<endl;
	}else{
		cout<<"RegOpenKeyExA failed!"<<endl;
	}
	if(ERROR_SUCCESS==RegSetValueExA(hKey,"MinAnimate",0,REG_SZ,(CONST BYTE*)&szValue,4)){
		cout<<"RegSetValueExA success!"<<endl;
	}else{
		cout<<"RegSetValueExA failed!"<<endl;
	}
	if(ERROR_SUCCESS==RegSetValueExW(hKey,L"MinAnimate",0,REG_SZ,(CONST BYTE*)&szValue,4)){
		cout<<"RegSetValueExW success!"<<endl;
	}else{
		cout<<"RegSetValueExW failed!"<<endl;
	}


	//RegSetValue(A/W)
	if(ERROR_SUCCESS==RegSetValueA(HKEY_CURRENT_USER,"Software\Microsoft\Internet Explore\Main",REG_SZ,NULL,NULL)){
		cout<<"RegSetValueA success!"<<endl;
	}else{
		cout<<"RegSetValueA failed!"<<endl;
	}
	if(ERROR_SUCCESS==RegSetValueW(HKEY_CURRENT_USER,L"Software\Microsoft\Internet Explore\Main",REG_SZ,NULL,NULL)){
		cout<<"RegSetValueW success!"<<endl;
	}else{
		cout<<"RegSetValueW failed!"<<endl;
	}


	////RegDeleteKeyEx(A/W)
	if(ERROR_SUCCESS==RegDeleteKeyExA(HKEY_CURRENT_USER,"Software\Microsoft\Internet Explore\Main",NULL,NULL)){
		cout<<"RegDeleteKeyExA success!"<<endl;
	}else{
		cout<<"RegDeleteKeyExA failed!"<<endl;
	}
	if(ERROR_SUCCESS==RegDeleteKeyExW(HKEY_CURRENT_USER,L"Software\Microsoft\Internet Explore\Main",NULL,NULL)){
		cout<<"RegDeleteKeyExW success!"<<endl;
	}else{
		cout<<"RegDeleteKeyExW failed!"<<endl;
	}


	////RegDeleteKey(A/W)
	if(ERROR_SUCCESS==RegDeleteKeyA(HKEY_CURRENT_USER,"Software\Microsoft\Internet Explore\Main")){
		cout<<"RegDeleteKeyA success!"<<endl;
	}else{
		cout<<"RegDeleteKeyA failed!"<<endl;
	}
	if(ERROR_SUCCESS==RegDeleteKeyW(HKEY_CURRENT_USER,L"Software\Microsoft\Internet Explore\Main")){
		cout<<"RegDeleteKeyW success!"<<endl;
	}else{
		cout<<"RegDeleteKeyW failed!"<<endl;
	}
	cout<<"while(1){}"<<endl;
	while(1){};
	return 0;
}


VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv) {
	return;
}

