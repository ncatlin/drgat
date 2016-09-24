#include "wrapkernel32.h"
#include "utilities.h"

static void wrapWritefile(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	DWORD bytesToWrite = (DWORD)drwrap_get_arg(wrapcxt, 2);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%ld@", 2, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, bytesToWrite);
}

static void wrapReadfile(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	DWORD bytesToWrite = (DWORD)drwrap_get_arg(wrapcxt, 2);

	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%ld@", 2, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, bytesToWrite);

	#ifdef BREAK_LOOP_ON_BLOCK
		printTagCache(thread);
	#endif
}


static void wrapGetStdHandle(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	DWORD arg = (DWORD)drwrap_get_arg(wrapcxt, 0);
	switch(arg)
	{
	case STD_INPUT_HANDLE:
		dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%s@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, "STDIN");
		break;
	case STD_OUTPUT_HANDLE:
		dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%s@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, "STDOUT");
		break;
	case STD_ERROR_HANDLE:
		dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%s@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, "STDERR");
		break;
	default:
		dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%s(%d)@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, "INVALID", arg);
		break;
	}
}

static void wrapGetprocaddr(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCSTR procname = (LPCSTR)drwrap_get_arg(wrapcxt, 1);
	if ((unsigned long)procname < 0xffff) 
	{
		dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%d@", 1, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, procname);
		return;
	}
	else
	{
		b64_string_arg(procname, thread->stringbuf);
		dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 1, drwrap_get_func(wrapcxt), 
			thread->sourceInstruction, thread->stringbuf);
	}
}

static void wrapGetmodulehandlea(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	const char *modname = (const char*)drwrap_get_arg(wrapcxt, 0);
	b64_string_arg(modname, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 0, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, thread->stringbuf);
}

static void wrapGetmodulehandlew(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	
	const wchar_t *modname = (wchar_t *)drwrap_get_arg(wrapcxt, 0);
	b64_wstring_arg(modname, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 0, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, thread->stringbuf);
}

//we care if this is 0
static void wrapGetmodulefilenamea(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	HMODULE mod = (HMODULE)drwrap_get_arg(wrapcxt, 0);
	
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%lx@", 0, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, mod);
}

static void wrapCreatefilea(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCTSTR filename = (LPCTSTR)drwrap_get_arg(wrapcxt, 0);
	b64_string_arg(filename, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,%s@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static void wrapCreateprocessinternalw(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPWSTR cmdline = (LPWSTR)drwrap_get_arg(wrapcxt, 1);
	b64_wstring_arg(cmdline, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static void wrapCreateprocessA(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCSTR cmdline = (LPCSTR)drwrap_get_arg(wrapcxt, 1);
	b64_string_arg(cmdline, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}


static void wrapSleep(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	DWORD timeout = (DWORD)drwrap_get_arg(wrapcxt, 0);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%ld@", 0, drwrap_get_func(wrapcxt), 
		thread->sourceInstruction, timeout);
	dr_flush_file(thread->f);

	if(traceClientptr->hidetime)
		drwrap_set_arg(wrapcxt, 0, 0);
	#ifdef BREAK_LOOP_ON_BLOCK
	else if(timeout > 1000)
		printTagCache(thread);
	#endif
}

static void wrapCompareStrA(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	LPCTSTR arg1 = (LPTSTR)drwrap_get_arg(wrapcxt, 2);
	b64_string_arg(arg1, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,M,1,%s@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);

	LPCTSTR arg2 = (LPTSTR)drwrap_get_arg(wrapcxt, 4);
	b64_string_arg(arg2, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 4, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);

}

static void wrapGettickcount(void *wrapcxt, OUT void *user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	if (!thread->lastTick) 
		thread->lastTick = (DWORD64)drwrap_get_retval(wrapcxt);
	else
	{
		thread->lastTick += dr_get_random_value(10);
		drwrap_set_retval(wrapcxt,(void *)thread->lastTick);
	}

}

static void wrapLoadlibraryW(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCWSTR path = (LPCWSTR)drwrap_get_arg(wrapcxt, 0);
	b64_wstring_arg(path, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static void wrapLoadlibraryA(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCSTR path = (LPCSTR)drwrap_get_arg(wrapcxt, 0);
	b64_string_arg(path, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 0, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static char* protectionToString(DWORD protect)
{
	switch (protect)
	{
	case PAGE_EXECUTE: return "--X";
	case PAGE_EXECUTE_READ: return "R-X";
	case PAGE_EXECUTE_READWRITE: return "RWX";
	case PAGE_EXECUTE_WRITECOPY: return "-WXcp";
	case PAGE_NOACCESS: return "NO ACCESS";
	case PAGE_READONLY: return "R--";
	case PAGE_READWRITE: return "RW-";
	case PAGE_WRITECOPY: return "-W-cp";
	case 0x40000000: return "TARG INVAL_NOUPDATE";
	default:
		return "";
	}
}

static void wrapVirtualprotect(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	DWORD newprotect = (DWORD)drwrap_get_arg(wrapcxt, 2);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%x:%s@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, newprotect,  protectionToString(newprotect));
}

static void wrapVirtualprotectEx(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	DWORD newprotect = (DWORD)drwrap_get_arg(wrapcxt, 3);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%x:%s@", 3, drwrap_get_func(wrapcxt), thread->sourceInstruction, newprotect,  protectionToString(newprotect));
}

static void wrapVirtualalloc(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	DWORD protect = (DWORD)drwrap_get_arg(wrapcxt, 2);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%x@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, protect);
}

void wrap_kernel32(module_handle_t handle)
{
	app_pc towrap = (app_pc)dr_get_proc_address(handle, "GetProcAddress");
		if (towrap != NULL) {
			drwrap_wrap(towrap, wrapGetprocaddr, NULL);
		}

		towrap = (app_pc)dr_get_proc_address(handle, "GetModuleHandleA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapGetmodulehandlea, NULL);

		towrap = (app_pc)dr_get_proc_address(handle, "GetModuleFileNameA");
		if (towrap != NULL)
			drwrap_wrap(towrap, wrapGetmodulefilenamea, NULL);

		towrap = (app_pc)dr_get_proc_address(handle, "GetModuleHandleW");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapGetmodulehandlew, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "CreateFileA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapCreatefilea, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "CreateProcessInternalW");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapCreateprocessinternalw, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "CreateProcessA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapCreateprocessA, NULL);

		towrap = (app_pc)dr_get_proc_address(handle, "VirtualProtect");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapVirtualprotect, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "VirtualProtectEx");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapVirtualprotectEx, NULL);
		

		towrap = (app_pc)dr_get_proc_address(handle, "VirtualAlloc");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapVirtualalloc, NULL);
		

		towrap = (app_pc)dr_get_proc_address(handle, "LoadLibraryW");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapLoadlibraryW, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "LoadLibraryA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapLoadlibraryA, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "Sleep");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapSleep, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "CompareStringA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapCompareStrA, NULL);
	
		towrap = (app_pc)dr_get_proc_address(handle, "WriteFile");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapWritefile, NULL);
		

		towrap = (app_pc)dr_get_proc_address(handle, "ReadFile");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapReadfile, NULL);
		

		towrap = (app_pc)dr_get_proc_address(handle, "GetStdHandle");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapGetStdHandle, NULL);
		
		if (traceClientptr->hidetime)
		{
			towrap = (app_pc)dr_get_proc_address(handle, "GetTickCount");
			if (towrap != NULL) 
				drwrap_wrap(towrap, NULL, wrapGettickcount);
			
			towrap = (app_pc)dr_get_proc_address(handle, "GetTickCount64");
			if (towrap != NULL) 
				drwrap_wrap(towrap, NULL, wrapGettickcount);
			
		}
}
