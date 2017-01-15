#include "headers\windowstrace.h"
#include "headers\utilities.h"
#include "headers\b64encode.h"

#include "headers\wrapkernel32.h"
#include "headers\wrapuser32.h"
#include "headers\wrapadvapi32.h"
#include "headers\wrapntdll.h"
#include "headers\wrapucrtbase.h"
#include "headers\wrapcryptsp.h"
#include "headers\wrapwininet.h"

void windows_event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	//we need the executable to be module[0], but it's not always the first presented
	//so we handle it in client_init and skip it when this is called
	if (info->start == traceClientptr->modStarts[0])
		return;

	std::string path(info->full_path);
	std::transform(path.begin(), path.end(), path.begin(), ::tolower);
	
	bool isInstrumented = false;
	if (traceClientptr->defaultInstrument)
	{
		if(!traceClientptr->excludedModuleStrings.count(path)) 
			isInstrumented = true;
	}
	else 
	{
		if(traceClientptr->includedModuleStrings.count(path)) 
			isInstrumented = true;
	}

	int modindex = traceClientptr->numMods++;
	char b64path[STRINGBUFMAX];
	b64_string_arg(info->full_path,b64path);

	traceClientptr->includedModules.push_back(isInstrumented);
	traceClientptr->write_sync_mod("mn@%s@%d@"ADDR_FMT"@"ADDR_FMT"@%x", 
		b64path, modindex, info->start, info->end, !traceClientptr->includedModules[modindex]);


	traceClientptr->modStarts.push_back(info->start);
	traceClientptr->modEnds.push_back(info->end);

	//can we rely on these paths? think it's safer than relying on filename alone
	if (path == "c:\\windows\\system32\\kernel32.dll")
		wrap_kernel32(info->handle);

	else if (path == "c:\\windows\\system32\\advapi32.dll")
		wrap_advapi32(info->handle);

	else if (path == "c:\\windows\\system32\\ntdll.dll")
		wrap_ntdll(info->handle);
	
	else if (path == "c:\\windows\\system32\\cryptsp.dll")
		wrap_cryptsp(info->handle);
	
	else if (path == "c:\\windows\\system32\\wininet.dll")
		wrap_wininet(info->handle);
	
	else if (path == "c:\\windows\\system32\\user32.dll")
		wrap_user32(info->handle);
	
	else if (path == "c:\\windows\\system32\\ucrtbase.dll" || path == "c:\\windows\\system32\\ucrtbased.dll")
		wrap_ucrtbase(info->handle);

	dr_sleep(5);//visualiser crashes if a symbol gets to it before the module path
	start_sym_processing(modindex, info->full_path);
}


/*
//todo: variable arguments are tricky
static void wrapSwprintf(void *wrapcxt, OUT void **user_data)
{
THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
POBJECT_ATTRIBUTES objatts = (POBJECT_ATTRIBUTES)drwrap_get_arg(wrapcxt, 2);
dr_fprintf(thread->f, "ARG@%d@%x@%S\n", 2, drwrap_get_func(wrapcxt), objatts->ObjectName->Buffer);
}

static void wrapZwallocvm(void *wrapcxt, OUT void **user_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	PSIZE_T size = (PSIZE_T)drwrap_get_arg(wrapcxt, 3);
	ULONG protect = (ULONG)drwrap_get_arg(wrapcxt, 5);
	app_pc retaddr = thread->lastBlock->appc;
	dr_fprintf(thread->f, "ARG,%d,%llx,%llx,M,0,%d@", 3, drwrap_get_func(wrapcxt), retaddr, size);
	dr_fprintf(thread->f, "ARG,%d,%llx,%llx,E,0,%d@", 5, drwrap_get_func(wrapcxt), retaddr, protect);
}
*/




