#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <iostream>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <cstdlib>   
#include <sstream>  
#include <time.h>
using namespace std;
typedef LONG NTSTATUS;
#pragma comment(lib, "Ws2_32.lib")
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT 27015

std::wstring GetKeyPathFromKKEY(HKEY key)
{
	std::wstring keyPath;
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
	return keyPath;
}

void test(){
	std::stringstream stream;  
	string str;     
	//clear()，这个名字让很多人想当然地认为它会清除流的内容。  
	//实际上，它并不清空任何内容，它只是重置了流的状态标志而已！  
		stream.clear();    
		// 去掉下面这行注释，清空stringstream的缓冲，每次循环内存消耗将不再增加!  
		//stream.str("");        
		stream<<"sdfsdfdsfsadfsdafsdfsdgsdgsdgsadgdsgsdagasdgsdagsadgsdgsgdsagsadgs";  
		stream>>str;     
		// 去掉下面两行注释，看看每次循环，你的内存消耗增加了多少！  
		//cout<<"Size of stream = "<<stream.str().length()<<endl;  
		//system("PAUSE");  
}


int main(int argc, CHAR* argv[])
{
	if (argc==1)
	{
		while (true)
		{
			cout<<"aaaaaaaaaaaaaaaaaaaaaaaaa"<<endl;
		}
	}else if (argc==2)
	{
		while (true)
		{
			cout<<"mmmmmmmmmmmmmmmmmmmmmmmmmmmmm"<<endl;
		}
	}
	/*
	int a=0;
	//cin>>a;
	int iResult;
	WSADATA wsaData;

	SOCKET ConnectSocket = INVALID_SOCKET;
	struct sockaddr_in clientService; 

	int recvbuflen = DEFAULT_BUFLEN;
	char *sendbuf = "Client: sending data test";
	char recvbuf[DEFAULT_BUFLEN] = "";
	
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	//----------------------
	// Create a SOCKET for connecting to server
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	cin>>a;
	send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 );
	*/

	/*
	HKEY key = NULL;
	LONG ret = ERROR_SUCCESS;

	ret = RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", &key);
	if (ret == ERROR_SUCCESS)
	{
		wprintf_s(L"Key path for %p is '%s'.", key, GetKeyPathFromKKEY(key).c_str());    
		RegCloseKey(key);
	}
	*/
	return 0;
}