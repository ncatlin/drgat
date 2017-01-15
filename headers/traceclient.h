#include "stdafx.h"
#include "targetver.h"
#include "tracestructs.h"
#pragma once

//if a call blocks it could be in middle of a tag cache
//if we want to see the red line waiting on it during runtime we have to dump the cache
//bad for performance in big loops though, so it should be optional
#define BREAK_LOOP_ON_BLOCK 1

typedef struct {
	void *addr;
	size_t size;
	void *next;
} ALLOCLL;

#define OPTIMISED_TRACING 0
#define DEBUG_TRACING 1

#define AT_CBR 0
#define AT_UBR 1
#define AT_MBR 2
#define AT_CALL 3

#define MAXINCLUDES 128

//magic performance number. adjust to taste
#define DEINSTRUMENTATION_LIMIT 10

//todo: put stuff protected/private
class TRACECLIENT {
public:
	 unsigned int tls_idx;
	 int numMods;
	 unsigned int currentMod;
	 bool ignoreWinDll;
	 bool inIgnored;
	 //shorten sleeps, timers
	 bool hidetime;
	 //send tags to visualiser as soon as block executed
	 char processingMode;

	 TRACECLIENT(std::string path)
	 {
		 tls_idx = 0;
		 numMods = 0;
		 currentMod = 0;
		 ignoreWinDll = false;
		 inIgnored = false;
		 processingMode = OPTIMISED_TRACING;
		 defaultInstrument = false;
		 file_t modpipe = 0;
		 file_t bbpipe = 0;
		 numIncludes = 0;
		 int pid = -1;
		 hidetime = false;
		 //pipename = 0;
	 }

	 std::map<std::string, bool> includedModuleStrings;
	 std::map<std::string, bool> excludedModuleStrings;

	 //by default we treat an unknown dll as external
	 bool defaultInstrument;
	 uint numIncludes;
	 std::vector <bool>includedModules;
	 std::vector<std::string> modNameArray; //module names
	 std::vector<app_pc> modStarts; //module start addresses
	 std::vector<app_pc> modEnds; //module end addresses
	 std::vector<THREAD_STATE *> threadList;

	void *modMutx, *parentMutx, *allocMutx;

	file_t modpipe;
	file_t bbpipe;

	process_id_t pid;

	ALLOCLL *loggedMemoryLLStart;
	ALLOCLL *latestAllocNode;
	void load_modinclude_strings(char *commaSepPaths);
	void load_modexclude_strings(char *commaSepPaths);
	void write_sync_bb(char* buf, uint strsize);
	void write_sync_mod(char *logText, ...);
};

extern TRACECLIENT *traceClientptr;