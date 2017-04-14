// ShutDown.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"
#include "wtypes.h"
#include "WinUser.h"
#include "ole2.h"

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)   
{
	 char tmp[10]="hello"; 
	 switch (message)   
  {   
    
  case WM_QUERYENDSESSION:   
  /*如果要注销或关闭系统返回 1 否则返回 0   
  不管WM_QUERYENDSESSION最后的结果是可以顺利结束或不能顺利结束，Windows会再送   
  一个WM_ENDSESSION的信息给所有的Process，而wParam的内容便是指出是否可以顺利结束*/   
   
 // sprintf(tmp,"wParam = 0x%x lParam = 0x%x",wParam,lParam);   
  if(lParam == 0)   
  MessageBoxA(0,"收到关机或重启消息",tmp,MB_OK);   
  else//lParam == 0x80000000   
  MessageBoxA(0,"收到注销消息",tmp,MB_OK);   
  return 0; //如果允许关机,就返回1,不想关机就返回0   
  case WM_ENDSESSION:   
  return 1; //这里返回什么关系不大,能否关机由上面消息决定   
  default:   
  return DefWindowProc(hWnd, message, wParam, lParam);   
  }   
  return 0;   
}
int _tmain(int argc, _TCHAR* argv[])
{
	int a=0;
	Sleep(10000000);
	return 0;
}

