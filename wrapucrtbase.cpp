#include "headers\wrapucrtbase.h"
#include "headers\utilities.h"

static void wrapWcscpy(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	wchar_t *source = (wchar_t *)drwrap_get_arg(wrapcxt, 1);
	b64_wstring_arg(source, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,1,%s@", 1, drwrap_get_func(wrapcxt),  thread->sourceInstruction, thread->stringbuf);
}

static void wrapWcsncpy(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	wchar_t *source = (wchar_t *)drwrap_get_arg(wrapcxt, 1);
	b64_wstring_arg(source, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static void wrapWcscat(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	wchar_t *source = (wchar_t *)drwrap_get_arg(wrapcxt, 1);
	b64_wstring_arg(source, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static void wrapFgets(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	int num = (int)drwrap_get_arg(wrapcxt, 1);

	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,0,%d@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, num);
	
	#ifdef BREAK_LOOP_ON_BLOCK
	printTagCache(thread);
	#endif
}

void wrap_ucrtbase(module_handle_t handle)
{
		app_pc towrap = (app_pc)dr_get_proc_address(handle, "wcscpy");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapWcscpy, NULL);
		

		towrap = (app_pc)dr_get_proc_address(handle, "wcsncpy");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapWcsncpy, NULL);
		

		towrap = (app_pc)dr_get_proc_address(handle, "wcscat");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapWcscat, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "fgets");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapFgets, NULL);

}