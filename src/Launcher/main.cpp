// main.cpp - entry-point for LR-COC.exe
///////////////////////////////////////
#define WIN32_LEAN_AND_MEAN
#include "windows.h"
#include <string>
///////////////////////////////////////
HINSTANCE	g_hInstance;
///////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (hPrevInstance)
		return 0;

	g_hInstance = hInstance;
	LPCSTR pathToExe = "bin\\xrEngine.exe";

	// additional information
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	// set the size of the structures
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));

	// start the program up
	CreateProcessA
	(
		pathToExe,				// the path
		lpCmdLine,              // Command line
		NULL,                   // Process handle not inheritable
		NULL,                   // Thread handle not inheritable
		FALSE,                  // Set handle inheritance to FALSE
		DETACHED_PROCESS,		
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&si,					// Pointer to STARTUPINFO structure
		&pi						// Pointer to PROCESS_INFORMATION structure
	);
	// Close process and thread handles.
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}