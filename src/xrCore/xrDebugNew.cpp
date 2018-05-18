#include "stdafx.h"
#pragma hdrstop

#include "xrdebug.h"
#include "os_clipboard.h"

#include <sal.h>
#include <dxerr.h>

#pragma warning(push)
#pragma warning(disable:4995)
#include <malloc.h>
#include <direct.h>
#pragma warning(pop)

#include "../build_config_defines.h"

extern bool shared_str_initialized;

#ifdef __BORLANDC__
# include "d3d9.h"
# include "d3dx9.h"
# include "D3DX_Wrapper.h"
# pragma comment(lib,"EToolsB.lib")
# define DEBUG_INVOKE __debugbreak();
static BOOL bException = TRUE;
# define USE_BUG_TRAP
#else
#ifndef NO_BUG_TRAP
# define USE_BUG_TRAP
#endif //-!NO_BUG_TRAP
# define DEBUG_INVOKE __debugbreak();
static BOOL bException = FALSE;
#endif

#ifndef USE_BUG_TRAP
# include <exception>
#endif

#ifndef _M_AMD64
# ifndef __BORLANDC__
# pragma comment(lib,"dxerr.lib")
# endif
#endif

#include <dbghelp.h> // MiniDump flags

#include <new.h> // for _set_new_mode
#include <signal.h> // for signals

#ifdef NO_BUG_TRAP //DEBUG
# define USE_OWN_ERROR_MESSAGE_WINDOW
#else
# define USE_OWN_MINI_DUMP
#endif //-NO_BUG_TRAP //DEBUG

XRCORE_API xrDebug Debug;

static bool error_after_dialog = false;

extern void BuildStackTrace();
extern char g_stackTrace[100][4096];
extern int g_stackTraceCount;

void LogStackTrace(LPCSTR header)
{
    if (!shared_str_initialized)
        return;

    BuildStackTrace();

    Msg("%s", header);

    for (int i = 1; i < g_stackTraceCount; ++i)
        Msg("%s", g_stackTrace[i]);
}

void xrDebug::gather_info(const char* expression, const char* description, const char* argument0, const char* argument1, const char* file, int line, const char* function, LPSTR assertion_info, u32 const assertion_info_size)
{
    if (!expression)
        expression = "<no expression>";
    LPSTR buffer_base = assertion_info;
    LPSTR buffer = assertion_info;
    int assertion_size = (int) assertion_info_size;
    LPCSTR endline = "\n";
    LPCSTR prefix = "[error]";
    bool extended_description = (description && !argument0 && strchr(description, '\n'));
    for (int i = 0; i < 2; ++i)
    {
        if (!i)
            buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sFATAL ERROR%s%s", endline, endline, endline);
        buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sExpression    : %s%s", prefix, expression, endline);
        buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sFunction      : %s%s", prefix, function, endline);
        buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sFile          : %s%s", prefix, file, endline);
        buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sLine          : %d%s", prefix, line, endline);

        if (extended_description)
        {
            buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%s%s%s", endline, description, endline);
            if (argument0)
            {
                if (argument1)
                {
                    buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%s%s", argument0, endline);
                    buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%s%s", argument1, endline);
                }
                else
                    buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%s%s", argument0, endline);
            }
        }
        else
        {
            buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sDescription   : %s%s", prefix, description, endline);
            if (argument0)
            {
                if (argument1)
                {
                    buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sArgument 0    : %s%s", prefix, argument0, endline);
                    buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sArgument 1    : %s%s", prefix, argument1, endline);
                }
                else
                    buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%sArguments     : %s%s", prefix, argument0, endline);
            }
        }

        buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%s", endline);
        if (!i)
        {
            if (shared_str_initialized)
            {
                Msg("%s", assertion_info);
                FlushLog();
            }
            buffer = assertion_info;
            endline = "\r\n";
            prefix = "";
        }
    }

#ifdef USE_MEMORY_MONITOR
    memory_monitor::flush_each_time(true);
    memory_monitor::flush_each_time(false);
#endif //-USE_MEMORY_MONITOR

    if (!IsDebuggerPresent() && !strstr(GetCommandLine(), "-no_call_stack_assert"))
    {
        if (shared_str_initialized)
            Msg("stack trace:\n");

#ifdef USE_OWN_ERROR_MESSAGE_WINDOW
        buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "stack trace:%s%s", endline, endline);
#endif //-USE_OWN_ERROR_MESSAGE_WINDOW

        BuildStackTrace();

        for (int i = 2; i < g_stackTraceCount; ++i)
        {
            if (shared_str_initialized)
                Msg("%s", g_stackTrace[i]);

#ifdef USE_OWN_ERROR_MESSAGE_WINDOW
            buffer += xr_sprintf(buffer, assertion_size - u32(buffer - buffer_base), "%s%s", g_stackTrace[i], endline);
#endif //-USE_OWN_ERROR_MESSAGE_WINDOW
        }

        if (shared_str_initialized)
            FlushLog();

        os_clipboard::copy_to_clipboard(assertion_info);
    }
}

void xrDebug::do_exit(const std::string& message)
{
    FlushLog();
	MessageBox(nullptr, message.c_str(), "X-ray error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);

	DEBUG_INVOKE;

    TerminateProcess(GetCurrentProcess(), 1);
}

#include <mutex>

//AVO: simplified function
void xrDebug::backend(const char* expression, const char* description, const char* argument0, const char* argument1, const char* file, int line, const char* function, bool& ignore_always)
{
	static std::recursive_mutex CS;
	std::lock_guard<decltype(CS)> lock(CS);

	error_after_dialog = true;

    string4096 assertion_info;

	gather_info(expression, description, argument0, argument1, file, line, function, assertion_info, sizeof(assertion_info));

    if (handler)
        handler();

	HWND wnd = GetActiveWindow();
	if (!wnd) wnd = GetForegroundWindow();

	//Sometimes if we crashed not in main thread, we can stuck at ShowWindow
	while (ShowCursor(TRUE) < 0);

#if !defined(DEBUG) && !defined(MIXED_NEW)
	do_exit("Please, see log-file for details.");
#else
	DebugBreak();
#endif

}
//-AVO

LPCSTR xrDebug::error2string(long code)
{
	char* desc_storage = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, code, 0, desc_storage, sizeof(desc_storage) - 1, 0);

	return desc_storage;
}

void xrDebug::error(long hr, const char* expr, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(expr, error2string(hr), 0, 0, file, line, function, ignore_always);
}

void xrDebug::error(long hr, const char* expr, const char* e2, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(expr, error2string(hr), e2, 0, file, line, function, ignore_always);
}

void xrDebug::fail(const char* e1, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(e1, "assertion failed", 0, 0, file, line, function, ignore_always);
}

void xrDebug::fail(const char* e1, const std::string& e2, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(e1, e2.c_str(), 0, 0, file, line, function, ignore_always);
}

void xrDebug::fail(const char* e1, const char* e2, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(e1, e2, 0, 0, file, line, function, ignore_always);
}

void xrDebug::fail(const char* e1, const char* e2, const char* e3, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(e1, e2, e3, 0, file, line, function, ignore_always);
}

void xrDebug::fail(const char* e1, const char* e2, const char* e3, const char* e4, const char* file, int line, const char* function, bool& ignore_always)
{
    backend(e1, e2, e3, e4, file, line, function, ignore_always);
}

//AVO: print, dont crash
void xrDebug::soft_fail(LPCSTR e1, LPCSTR file, int line, LPCSTR function)
{
    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s", file, line, function, e1);
}
void xrDebug::soft_fail(LPCSTR e1, const std::string &e2, LPCSTR file, int line, LPCSTR function)
{
    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s", file, line, function, e1, e2.c_str());
}
void xrDebug::soft_fail(LPCSTR e1, LPCSTR e2, LPCSTR file, int line, LPCSTR function)
{
    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s", file, line, function, e1, e2);
}
void xrDebug::soft_fail(LPCSTR e1, LPCSTR e2, LPCSTR e3, LPCSTR file, int line, LPCSTR function)
{
    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s %s", file, line, function, e1, e2, e3);
}
void xrDebug::soft_fail(LPCSTR e1, LPCSTR e2, LPCSTR e3, LPCSTR e4, LPCSTR file, int line, LPCSTR function)
{
    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s %s %s", file, line, function, e1, e2, e3, e4);
}
void xrDebug::soft_fail(LPCSTR e1, LPCSTR e2, LPCSTR e3, LPCSTR e4, LPCSTR e5, LPCSTR file, int line, LPCSTR function)
{
    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s %s %s %s", file, line, function, e1, e2, e3, e4, e5);
}
//-AVO

void __cdecl xrDebug::fatal(const char* file, int line, const char* function, const char* F, ...)
{
	string1024	buffer;

	va_list p;
	va_start			(p, F);
	vsprintf			(buffer, F, p);
	va_end				(p);

	bool ignore_always	= true;

	backend("Fatal error", "<no expression>", buffer, 0, file, line, function, ignore_always);
}

typedef void(*full_memory_stats_callback_type) ();
XRCORE_API full_memory_stats_callback_type g_full_memory_stats_callback = 0;

int out_of_memory_handler(size_t size)
{
    if (g_full_memory_stats_callback)
        g_full_memory_stats_callback();
    else
    {
        Memory.mem_compact();
        size_t process_heap = Memory.mem_usage();
        int eco_strings = (int) g_pStringContainer->stat_economy();
        int eco_smem = (int) g_pSharedMemoryContainer->stat_economy();
        Msg("* [x-ray]: process heap[%u K]", process_heap / 1024, process_heap / 1024);
        Msg("* [x-ray]: economy: strings[%d K], smem[%d K]", eco_strings / 1024, eco_smem);
    }

    Debug.fatal(DEBUG_INFO, "Out of memory. Memory request: %d K", size / 1024);
    return 1;
}

extern LPCSTR log_name();

XRCORE_API string_path g_bug_report_file;

extern void BuildStackTrace(struct _EXCEPTION_POINTERS* pExceptionInfo);
typedef LONG WINAPI UnhandledExceptionFilterType(struct _EXCEPTION_POINTERS* pExceptionInfo);
typedef LONG(__stdcall* PFNCHFILTFN) (EXCEPTION_POINTERS* pExPtrs);
extern "C" BOOL __stdcall SetCrashHandlerFilter(PFNCHFILTFN pFn);

static UnhandledExceptionFilterType* previous_filter = 0;

void format_message(LPSTR buffer, const u32& buffer_size)
{
 	LPSTR message = nullptr;
	DWORD error_code = GetLastError();

	if (!error_code) 
	{
		*buffer = 0;
		return;
	}

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), message, 0, 0);

	xr_sprintf(buffer, buffer_size, "[error][%8d]    : %s", error_code, message);
	LocalFree(message);
}

#ifndef _EDITOR
#include <errorrep.h>
#pragma comment( lib, "faultrep.lib" )
#endif //-!_EDITOR

#include <DbgHelp.h>
#include <exception>
//AVO: simplify function

typedef BOOL(WINAPI* MINIDUMPWRITEDUMP)(HANDLE hProcess, DWORD dwPid, HANDLE hFile, MINIDUMP_TYPE DumpType,
	CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);


LONG WINAPI UnhandledFilter(_EXCEPTION_POINTERS* pExceptionInfo)
{
	Log("* ####[UNHANDLED EXCEPTION]####");
	Log("* X-Ray Oxygen crash handler ver. 1.2.f");
	//#VERTVER: Welcome to OXY, baby


	crashhandler* pCrashHandler = Debug.get_crashhandler();
	if (pCrashHandler != nullptr)
	{
		pCrashHandler();
	}

	// Flush, after crashhandler. We include log file in a minidump
	FlushLog();

	long retval = EXCEPTION_CONTINUE_SEARCH;
	bException = true;

	HMODULE hDll = NULL;
	string_path szDbgHelpPath;

	if (GetModuleFileName(NULL, szDbgHelpPath, _MAX_PATH))
	{
		char* pSlash = strchr(szDbgHelpPath, '\\');
		if (pSlash)
		{
			const char dbgHelpStr[] = "DBGHELP.DLL";
			xr_strcpy(pSlash + 1, sizeof(dbgHelpStr), dbgHelpStr);
			hDll = ::LoadLibrary(szDbgHelpPath);
		}
	}

	if (!hDll)
	{
		// load any version we can
		hDll = ::LoadLibrary("DBGHELP.DLL");
	}

	LPCTSTR szResult = nullptr;

	if (hDll)
	{
		MINIDUMPWRITEDUMP pDump = (MINIDUMPWRITEDUMP)::GetProcAddress(hDll, "MiniDumpWriteDump");
		if (pDump)
		{
			string_path szDumpPath;
			string_path szScratch;
			string64 t_stemp;

			// work out a good place for the dump file
			timestamp(t_stemp);

			FS.update_path(szDumpPath, "$dump$", "");

			//			xr_strcpy(szDumpPath, "logs\\");
			xr_strcat(szDumpPath, Core.ApplicationName);
			xr_strcat(szDumpPath, "_");
			xr_strcat(szDumpPath, Core.UserName);
			xr_strcat(szDumpPath, "_");
			xr_strcat(szDumpPath, t_stemp);
			xr_strcat(szDumpPath, ".mdmp");

			// create the file
			HANDLE hFile = ::CreateFile(szDumpPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (INVALID_HANDLE_VALUE == hFile)
			{
				// try to place into current directory
				MoveMemory(szDumpPath, szDumpPath + 5, strlen(szDumpPath));
				hFile = ::CreateFile(szDumpPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			if (hFile != INVALID_HANDLE_VALUE)
			{
				_MINIDUMP_EXCEPTION_INFORMATION ExInfo;

				ExInfo.ThreadId = ::GetCurrentThreadId();
				ExInfo.ExceptionPointers = pExceptionInfo;
				ExInfo.ClientPointers = NULL;

				// write the dump
				MINIDUMP_TYPE dump_flags = MINIDUMP_TYPE(MiniDumpNormal | MiniDumpFilterMemory | MiniDumpScanMemory);

				//try include LogFile
				char* logFileContent = nullptr;
				DWORD logFileContentSize = 0;

				__try
				{
					do
					{
						const char* logFileName = log_name();
						if (logFileName == nullptr) break;

						// Don't use X-Ray FS - it can be corrupted at this point
						HANDLE hLogFile = CreateFile(logFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
						if (hLogFile == INVALID_HANDLE_VALUE) break;

						LARGE_INTEGER FileSize;
						bool bResult = (bool)GetFileSizeEx(hLogFile, &FileSize);
						if (!bResult)
						{
							CloseHandle(hLogFile);
							break;
						}

						logFileContent = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize.LowPart);
						if (logFileContent == nullptr)
						{
							CloseHandle(hLogFile);
							break;
						}

						logFileContentSize = FileSize.LowPart;

						DWORD TotalBytesReaded = 0;

						do
						{
							DWORD BytesReaded = 0;
							bResult = (bool)ReadFile(hLogFile, logFileContent, FileSize.LowPart, &BytesReaded, NULL);
							if (!bResult)
							{
								CloseHandle(hLogFile);
								break;
							}
							TotalBytesReaded += BytesReaded;
						} while (TotalBytesReaded < FileSize.LowPart);

						CloseHandle(hLogFile);
					} while (false);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					// better luck next time
				}

				MINIDUMP_USER_STREAM_INFORMATION UserStreamsInfo;
				MINIDUMP_USER_STREAM LogFileUserStream;

				std::memset(&UserStreamsInfo, 0, sizeof(UserStreamsInfo));
				std::memset(&LogFileUserStream, 0, sizeof(LogFileUserStream));
				if (logFileContent != nullptr)
				{
					UserStreamsInfo.UserStreamCount = 1;
					LogFileUserStream.Buffer = logFileContent;
					LogFileUserStream.BufferSize = logFileContentSize;
					LogFileUserStream.Type = MINIDUMP_STREAM_TYPE::CommentStreamA;
					UserStreamsInfo.UserStreamArray = &LogFileUserStream;
				}

				BOOL bOK = pDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, dump_flags, &ExInfo, &UserStreamsInfo, NULL);
				if (bOK)
				{
					xr_sprintf(szScratch, "Saved dump file to '%s'", szDumpPath);
					szResult = szScratch;
					retval = EXCEPTION_EXECUTE_HANDLER;
				}
				else
				{
					xr_sprintf(szScratch, "Failed to save dump file to '%s' (error %d)", szDumpPath, GetLastError());
					szResult = szScratch;
				}
				::CloseHandle(hFile);
			}
			else
			{
				xr_sprintf(szScratch, "Failed to create dump file '%s' (error %d)", szDumpPath, GetLastError());
				szResult = szScratch;
			}
		}
		else
		{
			szResult = "DBGHELP.DLL too old";
		}
	}
	else
	{
		szResult = "DBGHELP.DLL not found";
	}


	Log(szResult);
	FlushLog();

    return retval;
}
//-AVO

//////////////////////////////////////////////////////////////////////


static void handler_base(LPCSTR reason_string)
{
	bool alw_ignored = false;
	Debug.backend("Error handler is invoked!", reason_string, 0, 0, DEBUG_INFO, alw_ignored);
}

static void invalid_parameter_handler(const wchar_t *expression, const wchar_t *function, const wchar_t *file, unsigned int line, uintptr_t reserved)
{
	bool ignore_always = false;

	string4096	expression_,
		function_,
		file_;

	size_t converted_chars = 0;

	if (expression)
		wcstombs_s(&converted_chars, expression_, sizeof(expression_), expression, (wcslen(expression) + 1) * 2 * sizeof(char));
	else
		xr_strcpy(expression_, "");

	if (function)
		wcstombs_s(&converted_chars, function_, sizeof(function_), function, (wcslen(function) + 1) * 2 * sizeof(char));
	else
		xr_strcpy(function_, __FUNCTION__);

	if (file)
		wcstombs_s(&converted_chars, file_, sizeof(file_), file, (wcslen(file) + 1) * 2 * sizeof(char));
	else
	{
		line = __LINE__;
		xr_strcpy(file_, __FILE__);
	}

	Debug.backend("Error handler is invoked!", expression_, 0, 0, file_, line, function_, ignore_always);
}

static void pure_call_handler()
{
    handler_base("pure virtual function call");
}

#ifdef XRAY_USE_EXCEPTIONS
static void unexpected_handler()
{
    handler_base("unexpected program termination");
}
#endif // XRAY_USE_EXCEPTIONS

static void abort_handler(int signal)
{
    handler_base("application is aborting");
}

static void floating_point_handler(int signal)
{
    handler_base("floating point error");
}

static void illegal_instruction_handler(int signal)
{
    handler_base("illegal instruction");
}

static void termination_handler(int signal)
{
    handler_base("termination with exit code 3");
}


void debug_on_thread_spawn()
{

    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    signal(SIGABRT, abort_handler);
    signal(SIGABRT_COMPAT, abort_handler);
    signal(SIGFPE, floating_point_handler);
    signal(SIGILL, illegal_instruction_handler);
    signal(SIGINT, 0);
    signal(SIGTERM, termination_handler);

    _set_invalid_parameter_handler(&invalid_parameter_handler);

    _set_new_mode(1);
    _set_new_handler(&out_of_memory_handler);

    _set_purecall_handler(&pure_call_handler);
}

void xrDebug::_initialize(const bool& dedicated)
{
	*g_bug_report_file = 0;
	debug_on_thread_spawn();
	previous_filter = ::SetUnhandledExceptionFilter(UnhandledFilter);	// exception handler to all "unhandled" exceptions
}