#include "headers\wrapadvapi32.h"
#include "headers\utilities.h"

void wrapRegQValExA(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCTSTR path = (LPCTSTR)drwrap_get_arg(wrapcxt, 1);
	b64_string_arg(path, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

void wrapRegOpenKeyExA(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCTSTR path = (LPCTSTR)drwrap_get_arg(wrapcxt, 1);
	b64_string_arg(path, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

void wrap_advapi32(module_handle_t handle)
{
		app_pc towrap = (app_pc)dr_get_proc_address(handle, "RegQueryValueExA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapRegQValExA, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "RegQueryValueA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapRegQValExA, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "RegOpenKeyA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapRegOpenKeyExA, NULL);
		
		
		towrap = (app_pc)dr_get_proc_address(handle, "RegOpenKeyExA");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapRegOpenKeyExA, NULL);
		
}

