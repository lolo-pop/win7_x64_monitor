// TestAPI32.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include "fstream"
using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{

	char ch[1000];
	cout<<strlen(ch)<<endl;
	int a=0;
	cin>>a;
	ofstream f("C:\\test.txt",ios::app);
	f<<"DDDD"<<endl;
	f.close();
	return 0;
}

