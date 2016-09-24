#pragma once
#include "stdafx.h"

#define MAXMODULES 255
#define MAXBBBYTES 1024*40
#define TAGCACHESIZE 5256

#define UNKNOWN 91999
#define STRINGBUFMAX 512

typedef struct {
	unsigned int modnum;
} callback_data;

#define NO_LOOP 0
#define COND_BASE_LOOP 1
#define UNCOND_BASE_LOOP 2

static int glob_pid;

typedef struct {
	file_t f; //trace pipe
	thread_id_t tid;
	
	char *BBBuf; //per thread basic block buffer
	app_pc sourceInstruction;
	app_pc tagCache[TAGCACHESIZE];
	app_pc targetAddresses[TAGCACHESIZE];
	UINT32 blockID_counts[TAGCACHESIZE];
	char stringbuf[STRINGBUFMAX];

	uint cacheRepeats;
	int tagIdx;
	int loopMax;

	//result of last call to gettickcount
	DWORD64 lastTick;
	
} THREAD_STATE;



typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;