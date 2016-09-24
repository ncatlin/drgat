#include "headers\wrapwininet.h"
#include "headers\utilities.h"

static void wrapInternetConnectW(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPCWSTR path = (LPCWSTR)drwrap_get_arg(wrapcxt, 1);
	DWORD port = (DWORD)drwrap_get_arg(wrapcxt, 2);
	
	b64_wstring_arg(path, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,M,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%d@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, port);
}

static void wrapHTTPOpenReqW(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	LPCWSTR verb = (LPCWSTR)drwrap_get_arg(wrapcxt, 1);
	LPCWSTR objname = (LPCWSTR)drwrap_get_arg(wrapcxt, 2);

	if (!verb) 
		dr_fprintf(thread->f, "ARG,%d,%x,%x,M,0,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, "GET");
	else
	{
		b64_wstring_arg(verb, thread->stringbuf);
		dr_fprintf(thread->f, "ARG,%d,%x,%x,M,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
	}

	b64_wstring_arg(objname, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);

}

void wrap_wininet(module_handle_t handle)
{
		app_pc towrap = (app_pc)dr_get_proc_address(handle, "InternetConnectW");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapInternetConnectW, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "HttpOpenRequestW");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapHTTPOpenReqW, NULL);
		

}