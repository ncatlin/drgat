#pragma once
#include "stdafx.h"
// Windows Header Files:
#include <windows.h>
#include "tracestructs.h"


#define WIN32_LEAN_AND_MEAN   // Exclude rarely-used stuff from Windows headers


/*DLLS*/
//kernel32.dll
#define KERNDLLMOD 0
//ntdll.dll
#define ADVAPIMOD NTDLLMOD+1
//msvcrt.dll
#define MSVCRTMOD ADVAPIMOD+1
///
#define MODLISTEND MSVCRTMOD+1

/*symbols*/
//kernel.dll symbols
#define sGETPROCADDR 0
#define sGETMODHANDLEA sGETPROCADDR+1
#define sCREATEPROCESSINTERNALW sGETMODHANDLEA+1
#define sVIRTUALPROTECT sCREATEPROCESSINTERNALW+1
#define sVIRTUALALLOC sVIRTUALPROTECT+1
#define sGETTICKCOUNT sVIRTUALALLOC+1
#define KERNMODEND sGETTICKCOUNT+1

//ADVAPI32.dll symbols
#define sCRYPTHASHDATA 0
#define sCRYPTCREATEHASH sCRYPTHASHDATA+1
#define ADVAPIMODEND sCRYPTCREATEHASH+1


//todo new file
//can do arg in post processing
//ARG@arg position@symbol address@caller@value
static void
wrapZWCreateFile(void *wrapcxt, OUT void **user_data);


static void wrapLdrLoadDll(void *wrapcxt, OUT void **user_data);
static void wrapRTLQueryEnvvu(void *wrapcxt, OUT void **user_data);
static void wrapWcscpy(void *wrapcxt, OUT void **user_data);
static void wrapWcscat(void *wrapcxt, OUT void **user_data);
static void wrapWcsncpy(void *wrapcxt, OUT void **user_data);
/*
//todo: variable arguments are tricky
static void wrapSwprintf(void *wrapcxt, OUT void **user_data)
{
THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
POBJECT_ATTRIBUTES objatts = (POBJECT_ATTRIBUTES)drwrap_get_arg(wrapcxt, 2);
dr_fprintf(thread->f, "ARG@%d@%x@%S\n", 2, drwrap_get_func(wrapcxt), objatts->ObjectName->Buffer);
}*/
void wrapZwallocvm(void *wrapcxt, OUT void **user_data);


void wrapCryptcreatehash(void *wrapcxt, OUT void **user_data);
void wrapCrypthashdata(void *wrapcxt, OUT void **user_data);

static void wrapLoadlibraryW(void *wrapcxt, OUT void **user_data);


//todo add base64encode() stuff
void wrapInternetConnectW(void *wrapcxt, OUT void **user_data);

void wrapCharlowerA(void *wrapcxt, OUT void **user_data);
void wrapCompareStrA(void *wrapcxt, OUT void **user_data);

void wrapHTTPOpenReqW(void *wrapcxt, OUT void **user_data);

void wrapFgets(void *wrapcxt, OUT void **user_data);

void windows_event_module_load(void *drcontext, const module_data_t *info, bool loaded);

void get_zwcreatefilepath_from_stackptr(int position, void *pc);
void get_wstr_from_stackptr(int position, void *pc);

/*
static void wrapGettickcount(void *wrapcxt, OUT void **user_data)
{
THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
dr_fprintf(thread->f, "In wrapGettickcount\n");
BYTE *p = (BYTE*)drwrap_get_arg(wrapcxt, 3);
dr_fprintf(thread->f, "ARG@%d@%x@%x@%s\n", 3, drwrap_get_func(wrapcxt), thread->sourceInstruction, data);
}*/

