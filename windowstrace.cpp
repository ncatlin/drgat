#include "windowstrace.h"
#include "utilities.h"
#include "b64encode.h"

#include "wrapkernel32.h"
#include "wrapuser32.h"
#include "wrapadvapi32.h"
#include "wrapntdll.h"
#include "wrapucrtbase.h"
#include "wrapcryptsp.h"
#include "wrapwininet.h"

void windows_event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	//we need the executable to be module[0], but it's not always the first presented
	//so we handle it in client_init and skip it when this is called
	if (info->start == traceClientptr->modStarts[0])
		return;

	//dr_printf("1Loading module %s base:%lx\n", info->full_path, info->start);
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
	traceClientptr->includedModules.push_back(isInstrumented);

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

	//todo add kernbase?, any other interesting modules

#if defined _WIN64
	traceClientptr->write_sync_mod("mn@%s@%d@%x@%x@%x", info->full_path, modindex, info->start, info->end, !includedModules[modindex]);
#elif defined _WIN32
	traceClientptr->write_sync_mod("mn@%s@%d@%lx@%lx@%x", info->full_path, modindex,
		info->start, info->end, !traceClientptr->includedModules[modindex]);
#endif

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
	app_pc retaddr = thread->sourceInstruction;
	dr_fprintf(thread->f, "ARG,%d,%x,%x,M,0,%d@", 3, drwrap_get_func(wrapcxt), retaddr, size);
	dr_fprintf(thread->f, "ARG,%d,%x,%x,E,0,%d@", 5, drwrap_get_func(wrapcxt), retaddr, protect);
}
*/



