// main.cpp - entry-point for LR-COC.exe
///////////////////////////////////////
#define WIN32_LEAN_AND_MEAN
#include "windows.h"
#include "../xrCore/xrCore.h"
#define DLL_API __declspec(dllimport)
#pragma comment(lib, "xrEngine.lib")
///////////////////////////////////////

DLL_API int RunApplication(LPSTR lpCmdLine);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (hPrevInstance)			// welcome to win3.1, baby
		return 0;

	try
	{
		Debug._initialize(false);
		Core._initialize("Legend Returns 1.0", nullptr, TRUE, "fsgame.ltx");
	}
	catch (...)
	{
#ifdef DEBUG
		__debugbreak();
#else
		MessageBoxA(NULL, "Can't load xrCore. Please, restart the game.", "Error", MB_OK | MB_ICONHAND);
#endif 
	}
	RunApplication(lpCmdLine);
	return 0;
}