// dllmain.cpp : 定义 DLL 应用程序的入口点。
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#define PSAPI_VERSION 1
#include "stdafx.h"  
#include "HookApi.h"  
#include "easyhook.h"  
#include "ntstatus.h"  
#include <iostream>
#include <Psapi.h>
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
//#include <Ws2tcpip.h> 
#include "time.h"
#include "string.h"
#include "iostream"
#include "fstream"
#include "process.h"
#include "Psapi.h"
#include <wincrypt.h>
#include "Objbase.h"
#include "Shlwapi.h"
#include "winbase.h"
#include "wininet.h"
#include "winuser.h"
#include "winsvc.h"
#include "tlhelp32.h"
#include "psapi.h"
#include "winnls.h"
#include "winternl.h"
#include "shellapi.h"
#include "winwlx.h"
#include "winreg.h"
#include "Iphlpapi.h"
#include "Wininet.h"
#include "Lmshare.h"
#include <UrlMon.h>
#include <Wincrypt.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <shlobj.h>
using namespace std;
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"ws2_32.lib")

DWORD WINAPI MySetFilePointer( _In_ HANDLE hFile, _In_ LONG lDistanceToMove, _Inout_opt_ PLONG lpDistanceToMoveHigh, _In_ DWORD dwMoveMethod ){
	
	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		GetFileNameFromHandle(hFile,hFilepath);
		//GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<SetFilePointer>,func_params=<hFile|"<<hFilepath<<",lDistanceToMove|"<<lDistanceToMove<<",dwMoveMethod|"<<dwMoveMethod<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realSetFilePointer)(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
}

BOOL WINAPI MyMoveFileExW( _In_ LPCWSTR lpExistingFileName, _In_opt_ LPCWSTR lpNewFileName, _In_ DWORD dwFlags ){

	string lpFileNamestr1;
	lpFileNamestr1=WideToMutilByte(lpExistingFileName);
	string lpFileNamestr2="NULL";
	if (lpNewFileName!=NULL)
	{
		lpFileNamestr2=WideToMutilByte(lpNewFileName);
	}

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<MoveFileExW>,func_params=<lpExistingFileName|"<<lpFileNamestr1<<",lpNewFileName|"<<lpFileNamestr2<<",dwFlags|"<<dwFlags<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realMoveFileExW)(lpExistingFileName,lpNewFileName,dwFlags);
}

BOOL WINAPI MyWriteFile( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped ){

	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		GetFileNameFromHandle(hFile,hFilepath);
		//GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}
	if (strcmp(hFilepath,g_log_path)==0)
	{
		return (realWriteFile)(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
	}
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteFile>,func_params=<hFile|"<<hFilepath<<",nNumberOfBytesToWrite|"<<nNumberOfBytesToWrite<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realWriteFile)(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
}

BOOL WINAPI MyWriteFileEx( _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Inout_ LPOVERLAPPED lpOverlapped, _In_opt_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine ){

	stringstream logstream;
	char hFilepath[512]="NULL";

	if (hFile!=NULL)
	{
		GetFileNameFromHandle(hFile,hFilepath);
		//GetFinalPathNameByHandleA(hFile,hFilepath,MAX_PATH,VOLUME_NAME_DOS);
		//GetFileNameByHandle(hFile,hFilepath,MAX_PATH);
	}

	if (strcmp(hFilepath,g_log_path)==0)
	{
		return (realWriteFileEx)(hFile,lpBuffer,nNumberOfBytesToWrite,lpOverlapped,lpCompletionRoutine);
	}

	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<WriteFileEx>,func_params=<hFile|"<<hFilepath<<",nNumberOfBytesToWrite|"<<nNumberOfBytesToWrite<<">";

	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realWriteFileEx)(hFile,lpBuffer,nNumberOfBytesToWrite,lpOverlapped,lpCompletionRoutine);
}

BOOL MyShellExecuteExW(_Inout_ SHELLEXECUTEINFOW *pExecInfo){

	/*
	char str1[512]="NULL";
	string str2="NULL";
	if (pExecInfo!=NULL)
	{
		strcpy_s(str1,strlen(pExecInfo->lpFile),pExecInfo->lpFile);
	}
	*/
	return (realShellExecuteExW)(pExecInfo);
}

VOID WINAPI MyExitProcess( _In_ UINT uExitCode ){

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<ExitProcess>,func_params=<uExitCode|"<<uExitCode<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realExitProcess)(uExitCode);
}

BOOL WINAPI MyVirtualProtect( _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect ){

	stringstream logstream;
	logstream.clear();
	logstream<<hostname<<" "<<spy<<" "<<LogTime()<<"account_name="<<"<"<<strBuffer<<">,proc_id=<"<<_getpid()<<">,proc_name=<"<<ProcessName<<">,proc_thread_id=<"<<GetCurrentThreadId()<<">,proc_img_path=<"<<GetProcessPath()<<">,proc_func_name=<VirtualProtect>,func_params=<lpAddress|"<<lpAddress<<",dwSize|"<<dwSize<<",flNewProtect|"<<flNewProtect<<">";
	string st,sm;
	sm=logstream.str();
	WriteLog(sm);

	return (realVirtualProtect)(lpAddress,dwSize,flNewProtect,lpflOldProtect);
}