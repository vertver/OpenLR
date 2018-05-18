// main.cpp - entry-point for LR-COC.exe
///////////////////////////////////////
#define WIN32_LEAN_AND_MEAN
#include "windows.h"
#include <string>
#include "../xrCore/xrCore.h"
#define DLL_API __declspec(dllimport)
#pragma comment(lib, "xrEngine.lib")
///////////////////////////////////////

DLL_API int RunApplication(LPSTR lpCmdLine);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (hPrevInstance)
		return 0;

	RunApplication(lpCmdLine);
	MessageBox(NULL, "", "", MB_OK | MB_ICONHAND);
	return 0;
}