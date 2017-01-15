#include "headers\wrapuser32.h"
#include "headers\utilities.h"


static void wrapCharlowerA(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	LPTSTR arg = (LPTSTR)drwrap_get_arg(wrapcxt, 0);

	if ((unsigned long)arg < 0xffff)
		b64_char_arg((char)arg, thread->stringbuf);
	else
		b64_string_arg(arg, thread->stringbuf);

	dr_fprintf(thread->f, "ARG,%d,"ADDR_FMT","ADDR_FMT",E,1,%s@", 0, drwrap_get_func(wrapcxt), thread->lastBlock->appc, thread->stringbuf);
}

void wrap_user32(module_handle_t handle)
{
		app_pc towrap = (app_pc)dr_get_proc_address(handle, "CharLowerA");
		if (towrap != NULL)
			drwrap_wrap(towrap, wrapCharlowerA, NULL);
}
