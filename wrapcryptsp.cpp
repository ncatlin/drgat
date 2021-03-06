#include "headers\wrapuser32.h"
#include "headers\utilities.h"

static void wrapCryptcreatehash(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	UINT algid = (UINT)drwrap_get_arg(wrapcxt, 1);
	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,0,%x@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, algid);
}

static void wrapCrypthashdata(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	BYTE *data = (BYTE*)drwrap_get_arg(wrapcxt, 1);
	b64_string_arg((char *)data, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, data);
}


void wrap_cryptsp(module_handle_t handle)
{
		app_pc towrap = (app_pc)dr_get_proc_address(handle, "CryptCreateHash");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapCryptcreatehash, NULL);

		towrap = (app_pc)dr_get_proc_address(handle, "CryptHashData");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapCrypthashdata, NULL);
		
}
