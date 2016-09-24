#include "wrapntdll.h"
#include "utilities.h"


static void
wrapZWCreateFile(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	POBJECT_ATTRIBUTES objatts = (POBJECT_ATTRIBUTES)drwrap_get_arg(wrapcxt, 2);
	b64_wstring_arg(objatts->ObjectName->Buffer, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);

}

static void wrapLdrLoadDll(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	PUNICODE_STRING modname = (PUNICODE_STRING)drwrap_get_arg(wrapcxt, 2);
	b64_wstring_arg(modname->Buffer, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 2, drwrap_get_func(wrapcxt), thread->sourceInstruction, thread->stringbuf);
}

static void wrapRTLQueryEnvvu(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	PUNICODE_STRING variableUC = (PUNICODE_STRING)drwrap_get_arg(wrapcxt, 1);
	b64_wstring_arg(variableUC->Buffer, thread->stringbuf);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,1,%s@", 1, drwrap_get_func(wrapcxt), thread->sourceInstruction, variableUC->Buffer);
}

void wrap_ntdll(module_handle_t handle)
{
		app_pc towrap = (app_pc)dr_get_proc_address(handle, "ZwCreateFile");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapZWCreateFile, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "LdrLoadDll");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapLdrLoadDll, NULL);
		
		towrap = (app_pc)dr_get_proc_address(handle, "RtlQueryEnvironmentVariable_U");
		if (towrap != NULL) 
			drwrap_wrap(towrap, wrapRTLQueryEnvvu, NULL);
		

		/*
		towrap = (app_pc)dr_get_proc_address(handle, "ZwAllocateVirtualMemory");
		if (towrap != NULL) {
			drwrap_wrap(towrap, wrapZwallocvm, NULL);
		}*/

}



/*
static void
get_zwcreatefilepath_from_stackptr(int position, void *pc)
{

	dr_mcontext_t mcontext = { sizeof(mcontext),DR_MC_CONTROL };
	void *drcontext = dr_get_current_drcontext();
	dr_get_mcontext(drcontext, &mcontext);

	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->f, "INWIDESTRING\n");

	size_t qty;
	//get address of argument, stored on stack
	int i = 4 + (4 * position);
	void *argaddr;
	dr_safe_read((byte *)(mcontext.esp + i), 4, &argaddr, &qty);

	if (qty < 4)
		DR_ASSERT("LESS THAN 4 BYTES STACK READ");
	dr_safe_read((void *)((long long)argaddr + sizeof(LONG) + sizeof(HANDLE)), 4, &argaddr, &qty);

	//follow address to get arg
	wchar_t wideargbuf[512] = L"";
	dr_safe_read(argaddr, 512, wideargbuf, &qty);
	//ARG@arg number@pc@value
	char charargbuf[258];
	wcstombs(charargbuf, wideargbuf, qty);

	dr_fprintf(thread->f, "ARG@%d@%x@%s@\n", position, pc, charargbuf);
	dr_fprintf(thread->f, "FARM@%d@%x@%s@\n", position, pc, charargbuf);

}

//i used this at some point to extract data from pointers
//keeping here in case of future need
static void
get_wstr_from_stackptr(int position, void *pc)
{

	dr_mcontext_t mcontext = { sizeof(mcontext),DR_MC_CONTROL };
	void *drcontext = dr_get_current_drcontext();
	dr_get_mcontext(drcontext, &mcontext);

	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->f, "INWIDESTRING\n");

	size_t qty;
	//get address of argument, stored on stack
	int i = 4 + (4 * position);
	void *argaddr;
	dr_safe_read((byte *)(mcontext.esp + i), 4, &argaddr, &qty);

	if (qty < 4)
		DR_ASSERT("LESS THAN 4 BYTES STACK READ");

	//follow address to get arg
	wchar_t wideargbuf[512] = L"";
	dr_safe_read((void *)argaddr, 512, wideargbuf, &qty);
	//ARG@arg number@pc@value
	char charargbuf[258];
	wcstombs(charargbuf, wideargbuf, qty);
	
	//TODO: base64 encode arg...
	dr_fprintf(thread->f, "WSARG,%d,%x,%s", position, pc, charargbuf);

}

*/