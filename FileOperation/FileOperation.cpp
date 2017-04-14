// FileOperation.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
//#include "iostream"
#include <iostream>
#include "stdio.h"
#include "windows.h"
using namespace std;
int _tmain(int argc, _TCHAR* argv[])
{
	char ch[256]="";
	//创建文件 CreateFileW
	cout<<"创建文件操作将在C盘下面创建a.txt,b.txt,c.txt和d.txt文件，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	HANDLE fileHandle1,fileHandle2,fileHandle3,fileHandle4; 
	fileHandle1=CreateFileW(L"C:\\a.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	fileHandle2=CreateFileW(L"C:\\b.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	fileHandle3=CreateFileW(L"C:\\c.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	fileHandle4=CreateFileW(L"C:\\d.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	cout<<"创建文件操作结束\n"<<endl;
	//打开文件
	cout<<"打开文件操作将在C盘下面打开a.txt文件，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	OFSTRUCT ofStruct={ sizeof(OFSTRUCT) };
	OpenFile("C:\\a.txt",&ofStruct, OF_READWRITE|OF_SHARE_EXCLUSIVE);
	cout<<"打开文件操作结束\n"<<endl;

	//写入文件
	cout<<"写入文件操作将在C盘下面的a.txt和b.txt中分别写入字符串“aaaa”,按任意键开始执行行为！"<<endl;
	gets_s(ch);
	char *data="aaaa"; 
	DWORD a = strlen(data); 
	unsigned long b; 
	WriteFile(fileHandle1, data, a, &b, NULL);
	HANDLE h_Event = CreateEvent(NULL, TRUE, FALSE, NULL);
	OVERLAPPED k_Over = {0};
	//&k_Over->hEvent=h_Event;
	WriteFileEx(fileHandle2,data,a,&k_Over,NULL);
	CloseHandle(fileHandle1);
	CloseHandle(fileHandle2);
	cout<<"写入文件操作结束\n"<<endl;

	//读取文件
	cout<<"读取文件操作，将读取C盘下面的a.txt文件中的内容,按任意键开始执行行为！"<<endl;
	gets_s(ch);
	fileHandle1=CreateFileW(L"C:\\a.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	char read[256]="";
	DWORD readsize=0;
	ReadFile(fileHandle1,read,4,&readsize,NULL);
	OVERLAPPED r_Over = {0};
	ReadFileEx(fileHandle1,read,4,&r_Over,NULL);
	//cout<<"从文件中读取的内容："<<read<<endl;
	CloseHandle(fileHandle1);
	cout<<"读取文件操作结束\n"<<endl;
	//截断文件
	cout<<"截断文件操作，将C盘下面的a.txt从开始处偏移为2的地方截断文件，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	long distance=2;
	fileHandle1=CreateFileW(L"C:\\a.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 
	SetFilePointer(fileHandle1, distance, NULL, FILE_BEGIN);
	SetEndOfFile(fileHandle1);
	CloseHandle(fileHandle1);
	cout<<"截断文件操作结束\n"<<endl;

	//重命名文件
	cout<<"重命名文件操作将在C盘下面的a.txt,b.txt,c.txt和d.txt重命名为e.txt,f.txt,g.txt和h.txt,按任意键开始执行行为！"<<endl;
	gets_s(ch);
	CloseHandle(fileHandle1);
	CloseHandle(fileHandle2);
	CloseHandle(fileHandle3);
	CloseHandle(fileHandle4);
	MoveFileW(L"C:\\a.txt",L"C:\\e.txt");
	MoveFileExW(L"C:\\b.txt",L"C:\\f.txt",MOVEFILE_COPY_ALLOWED);
	MoveFileA("C:\\c.txt","C:\\g.txt");
	MoveFileExA("C:\\d.txt","C:\\h.txt",MOVEFILE_COPY_ALLOWED);
	cout<<"重命名文件操作结束\n"<<endl;

	//删除文件
	cout<<"删除文件操作会将C盘下面的g.txt文件和h.txt文件删除，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	DeleteFileA("C:\\g.txt");
	DeleteFileW(L"C:\\h.txt");
	cout<<"删除文件操作结束\n"<<endl;

    //遍历目录
	cout<<"遍历目录操作将会遍历C盘的Windows文件夹的文件，按任意键开始执行行为！"<<endl;
	gets_s(ch);
	WIN32_FIND_DATAA q1;
	HANDLE h1=FindFirstFileA("C:\\Windows\\*.*",&q1);
	FindNextFileA(h1,&q1);
	WIN32_FIND_DATAW q2;
	HANDLE h2=FindFirstFileW(L"C:\\Windows\\*.*",&q2);
	FindNextFileW(h2,&q2);
	cout<<"遍历目录操作结束\n"<<endl;

	return 0;
}

