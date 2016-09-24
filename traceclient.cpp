/*
Trace requirements:
Every instruction of target (internal) code, in order
The first address of non-target (external) code
Need to record target of every jump in case it hits external + can check conditional completion offline
*/



#define _WIN32
//I tried to compile this using VS2015 but no matter what options or defines I used 
//it wouldn't run on windows 10 these are a monument to my failure
#define _WIN32_WINNT _WIN32_WINNT_WIN7  
#define WINVER _WIN32_WINNT_WIN7  
#define NTDDI_VERSION _WIN32_WINNT_WIN7  
#include "targetver.h"



#include "windowstrace.h"
#include "traceclient.h"
#include "tracestructs.h"
#include "utilities.h"
#include "stdafx.h"

//todo: sort crash if target buffer full (ie: paused w/debugger)

//#define VERBOSE_VERBOSE

//todo: memset as well as the other interesting ones

TRACECLIENT *traceClientptr;

static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
void event_exit();
static bool event_pre_syscall(void *drcontext, int);
static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag,
	instrlist_t *bb,
	bool for_trace, bool translating,
	void **user_data);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag,
	instrlist_t *bb, instr_t *inst,
	bool for_trace, bool translating,
	void *user_data);

#define MAXTHREADID 65000

bool threadInInstrumentedArr[MAXTHREADID];
uint threadModArr[MAXTHREADID];

#define MAXDISLEN 4096 
char lineStr[MAXDISLEN];

void printTagCache(THREAD_STATE *thread);

void
TRACECLIENT::write_sync_bb(char* buf, uint strsize)
{
	dr_write_file(bbpipe, buf, strsize); //fprintf truncates to internal buffer size!
	dr_flush_file(bbpipe);
}

void
TRACECLIENT::write_sync_mod(char *logText, ...)
{
	
	char str[1024];
	uint total = 0;
	va_list args;

	va_start(args, logText);
	total += dr_vsnprintf(str, 1024, logText, args);
	va_end(args);
	str[total] = 0;

	DR_ASSERT_MSG(total < 1024, "w_s_m buf too small");
	dr_fprintf(modpipe, "%s", str);
	dr_flush_file(modpipe);
}


static bool
event_exception(void *drcontext, dr_exception_t *excpt)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->f, "EXC,%x,%x@", excpt->mcontext->eip, excpt->record->ExceptionCode);
	return true;
}

//take comma separated string, place in suplied string buf
void TRACECLIENT::load_modinclude_strings(char *commaSepPaths)
{
	std::string pathString(commaSepPaths);
	std::stringstream ss(pathString);

	while (includedModuleStrings.size() < MAXINCLUDES) {
		std::string path;
		std::getline(ss, path, ',');
		if (path.empty()) return;
		#ifdef WINDOWS
		std::transform(path.begin(), path.end(), path.begin(), ::tolower);
		#endif

		includedModuleStrings[path] = true;
	}
}

//take comma separated string, place in suplied string buf
void TRACECLIENT::load_modexclude_strings(char *commaSepPaths)
{
	std::string pathString(commaSepPaths);
	std::stringstream ss(pathString);

	while (excludedModuleStrings.size() < MAXINCLUDES) {
		std::string path;
		std::getline(ss, path, ',');
		if (path.empty()) return;
		#ifdef WINDOWS
		std::transform(path.begin(), path.end(), path.begin(), ::tolower);
		#endif

		excludedModuleStrings[path] = true;
	}
}

void processArgs(const char **ask_argv, int ask_argc, TRACECLIENT * client)
{
	dr_printf("Client starting with %d options: \n",ask_argc);
	for (int x = 0; x < ask_argc; ++x)
	{
		dr_printf("option:%s\n", ask_argv[x]);
		std::string arg(ask_argv[x]);

		if (arg == "-defaultinstrument")
		{
			client->defaultInstrument = true;
			continue;
		}

		//hide sleeps/shorten tick counts
		if (arg == "-caffine")
		{
			client->hidetime = true;
			continue;
		}

		if (arg == "-defaultinstrument")
		{
			client->defaultInstrument = true;
			continue;
		}

		if (arg == "-include")
		{
			client->load_modinclude_strings((char *)ask_argv[++x]);
			continue;
		}

		if (arg == "-exclude")
		{
			client->load_modexclude_strings((char *)ask_argv[++x]);
			continue;
		}

	}


		
	/*
	char *pipename = NULL;
	if (dr_get_string_option("pipename:",pipename,32))
		client->pipename = pipename;
	else
	{
		client->pipename = (char *)malloc(10);
		dr_snprintf(client->pipename, 10, "rgatipc");
	}


	const size_t INCBUFSIZE = 1024*MAXINCLUDES;
	char *pathBuf = NULL;
	pathBuf = (char *)malloc(INCBUFSIZE);
	memset(pathBuf, 0, INCBUFSIZE);

	if (dr_get_string_option("include:",pathBuf,INCBUFSIZE))
	{
		client->load_modinclude_strings(pathBuf);
	}
	memset(pathBuf, 0, INCBUFSIZE);

	if (dr_get_string_option("exclude:",pathBuf,INCBUFSIZE))
	{
		if(!pathBuf) 
			pathBuf = (char *)malloc(INCBUFSIZE);
		else
			memset(pathBuf, 0, INCBUFSIZE);
		client->load_modexclude_strings(pathBuf);
	}

	if(pathBuf) free(pathBuf);
		*/
}


inline void process_block(app_pc pc, app_pc target, userd *block_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	thread->sourceInstruction = pc;
	int tagIdx = thread->tagIdx++; //do increment here to avoid extra read
	
	#ifdef VERBOSE_VERBOSE
	dr_printf("block insaddr %lx bb [tagidx %d addr %lx targ %lx]\n",pc,tagIdx,block_data->appc,target);
	#endif

	if (tagIdx > TAGCACHESIZE-1)
	{
		printTagCache(thread);
		tagIdx = 0;
	}

	if (!thread->loopMax)
	{
		//not in loop, record new block info in cache
		thread->tagCache[tagIdx] = block_data->appc;
		thread->targetAddresses[tagIdx] = target;
		thread->blockID_counts[tagIdx] = block_data->blockID_numins;

		//not a back edge so no further processing
		if ((unsigned long)target > (unsigned long)pc) 
			return;

		#ifdef VERBOSE_VERBOSE
		dr_printf("not in loop insaddr %lx bb [tagidx %d addr %lx targ %lx]\n",pc,tagIdx,block_data->appc,target);
		#endif
		
		if (thread->tagCache[0] == target)//back to start of cache
		{
			#ifdef VERBOSE_VERBOSE
			dr_printf("targ %lx == cache0 %lx -> starting loop",target, thread->tagCache[0]);
			#endif
			//record cache as first iteration of a loop
			thread->loopMax = tagIdx;
			thread->cacheRepeats++;
			thread->tagIdx = 0;
		}
		else
		{
			#ifdef VERBOSE_VERBOSE
			dr_printf("unknown backedge idx %d, targ %lx!, cache[0] %lx\n",tagIdx,
					target,thread->tagCache[0]);
			#endif
			//back to something else, dump cache
			printTagCache(thread);
		}
		return;
	}


	if (tagIdx == thread->loopMax) //end of loop
	{
		#ifdef VERBOSE_VERBOSE
		dr_printf("end of loop idx %d, checking targ %lx! =  cache[0] %lx\n",tagIdx,
					target,thread->tagCache[0]);
		#endif

		//back to start of loop
		if (target == thread->tagCache[0])
		{
			//record another iteration of cache
			++thread->cacheRepeats;
			thread->tagIdx = 0;
			return;
		}
			
		//leaving loop. print loops up til now + progress on current loop
		--thread->tagIdx;
		printTagCache(thread);

		tagIdx = 0;
		thread->tagCache[tagIdx] = block_data->appc;
		thread->blockID_counts[tagIdx] = block_data->blockID_numins;
		thread->targetAddresses[tagIdx] = target;
		thread->tagIdx = 1;
		return;
	}

	//continuing in cached loop but not at end, ensure this block matches cached block
	if ((thread->tagCache[tagIdx] != block_data->appc) || //different BB?
		(thread->blockID_counts[tagIdx] != block_data->blockID_numins) || //same BB start, different end?
				(thread->targetAddresses[tagIdx] != target)) //leaving mid loop?
	{
		#ifdef VERBOSE_VERBOSE
		dr_printf("loop mismatch dumpcache idx %d, %lx!=%lx,numins:%d, %lx!=%lx\n",tagIdx,
					thread->tagCache[tagIdx],(uint)block_data->appc,	
					block_data->numInstructions,thread->targetAddresses[tagIdx], target);
		#endif

		//they don't match! print loops up til now + progress on current loop
		--thread->tagIdx;
		printTagCache(thread);

		tagIdx = 0;
		thread->tagCache[tagIdx] = block_data->appc;
		thread->blockID_counts[tagIdx] = block_data->blockID_numins;
		thread->targetAddresses[tagIdx] = target;
		thread->tagIdx = 1;
	}
}

/*
basic loop compression happens here for loops controlled by a conditional at the end
if not in a loop and we jump back, we are setting cache[0] to start of loop
next iteration we notice the target is cache[0] and start loop increments

it looks like a lot of crap to be added to every conditional instruction, but most
will not execute much of it
*/
static void at_cbr(app_pc pc, app_pc target, int taken)
{
	userd *block_data = (userd *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);

	#ifdef VERBOSE_VERBOSE
	dr_printf("at_cbr pc%lx targ %lx bb%lx falladdr:%lx taken:%d\n",pc,target,block_data->appc,block_data->fallthrough,taken);
	#endif

	if (taken)
		process_block(pc, target, block_data);
	else
		process_block(pc, block_data->fallthrough, block_data);
}


static void at_ubr(app_pc pc, app_pc target)
{
	#ifdef VERBOSE_VERBOSE
	dr_printf("at_ubr %lx->%lx\n",pc,target);
	#endif

	userd *block_data = (userd *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	process_block(pc, target, block_data);
}

static void
at_mbr(app_pc pc, app_pc target)
{
	#ifdef VERBOSE_VERBOSE
	dr_printf("at_mbr %lx -> %lx\n",pc, target);
	#endif

	userd *block_data = (userd *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	process_block(pc, target, block_data);
}

//like ubr
static void at_call(app_pc pc, app_pc target)
{
	#ifdef VERBOSE_VERBOSE
	dr_printf("at_call addr %lx targ %lx\n",pc,target);
	#endif

	userd *block_data = (userd *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	process_block(pc, target, block_data);
}





DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{

	dr_printf("[drgat]Starting Instrumentation\n");
	dr_set_client_name("rgat instrumentation client", "https://github.com/ncatlin/rgat");
	
	drmgr_init();
	drwrap_init();
	void *clientContext = dr_get_current_drcontext();
	
	int ask_argc;
	const char **ask_argv;
	bool ok = dr_get_option_array(id, &ask_argc, &ask_argv);
	
	if (argc == 0) 
	{
		//dead code?
		dr_printf("[drgat]Could not determine target path\n");
		return;
	}

	std::string appPath(dr_get_main_module()->full_path);
	#ifdef WINDOWS
		std::transform(appPath.begin(), appPath.end(), appPath.begin(), ::tolower);
	#endif
	module_data_t * mainmodule = dr_get_main_module();

	traceClientptr = new TRACECLIENT(appPath);

	processArgs(ask_argv, ask_argc, traceClientptr);

	//dr_messagebox("Set %s to true",appPath.c_str());

	traceClientptr->allocMutx = dr_mutex_create();
	traceClientptr->latestAllocNode = (ALLOCLL *)dr_thread_alloc(clientContext, sizeof(ALLOCLL));

	traceClientptr->tls_idx = drmgr_register_tls_field();
	DR_ASSERT(traceClientptr->tls_idx != -1);

	traceClientptr->pid = dr_get_process_id();
	dr_printf("[drgat init main] Created process %d\n", traceClientptr->pid);
	char pipeName[255];

	//dr_snprintf(pipeName, 254, "\\\\.\\pipe\\%s",traceClientptr->pipename);
	traceClientptr->modpipe = dr_open_file("\\\\.\\pipe\\BootstrapPipe", DR_FILE_WRITE_OVERWRITE);

	if (traceClientptr->modpipe == INVALID_FILE)
	{
		//todo: take custom mutex names as an argument
		dr_snprintf(pipeName, 254, "\\\\.\\pipe\\BootstrapPipe");
		dr_printf("[drgat]Client connecting to bootstrap pipe %s\n",pipeName);
		traceClientptr->modpipe = dr_open_file(pipeName, DR_FILE_WRITE_OVERWRITE);
		if (traceClientptr->modpipe == INVALID_FILE)
		{
			dr_printf("[drgat]ERROR: Failed to connect to bootstrap pipe! Exiting...\n");
			return;
		}
	}

	int sz = dr_fprintf(traceClientptr->modpipe, "PID%d", traceClientptr->pid);
	traceClientptr->modpipe = INVALID_FILE;
	while (traceClientptr->modpipe == INVALID_FILE)
	{
		dr_snprintf(pipeName, 254, "\\\\.\\pipe\\rioThreadMod%d", traceClientptr->pid);
		dr_printf("[drgat]Waiting to open %s\n",pipeName);
		dr_sleep(600);
		traceClientptr->modpipe = dr_open_file(pipeName, DR_FILE_WRITE_OVERWRITE);
	}


	dr_sleep(100);

	traceClientptr->write_sync_mod("Opened mod pipe!\n");

	dr_snprintf(pipeName, 254, "\\\\.\\pipe\\rioThreadBB%d", traceClientptr->pid);
	traceClientptr->bbpipe = dr_open_file(pipeName, DR_FILE_WRITE_OVERWRITE);
	DR_ASSERT_MSG(traceClientptr->bbpipe != INVALID_FILE, "No rioThreadBB!");
		
	traceClientptr->write_sync_mod("Opened BB pipe!\n");

	//load executable into module list
	if(!traceClientptr->excludedModuleStrings.count(appPath))
	{
		traceClientptr->includedModuleStrings[appPath] = true;
		traceClientptr->includedModules.push_back(true);
	}
	else
	{
		traceClientptr->includedModules.push_back(false);
	}
	traceClientptr->modStarts.push_back(mainmodule->start);
	traceClientptr->modEnds.push_back(mainmodule->end);
	

	#if defined WIN64
	traceClientptr->write_sync_mod("mn@%s@%d@%x@%x@%x", mainmodule->full_path, 0, mainmodule->start, 
		mainmodule->end, !includedModules[0]);
	#elif defined WIN32
	traceClientptr->write_sync_mod("mn@%s@%d@%lx@%lx@%x", mainmodule->full_path, 0,
		mainmodule->start, mainmodule->end, !traceClientptr->includedModules[0]);
	#endif

	start_sym_processing(0, mainmodule->full_path);
	traceClientptr->numMods = 1;

	
	//start instrumentation
	dr_register_exit_event(event_exit);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);
		drmgr_register_exception_event(event_exception);
	drmgr_register_bb_instrumentation_event(event_bb_analysis,
		NULL,//event_app_instruction,
		NULL);
	#ifdef WINDOWS
	drmgr_register_module_load_event(windows_event_module_load);
	#elif LINUX
	drmgr_register_module_load_event(linux_event_module_load);
	#endif

	dr_printf("[drgat]dr_client_main completed...\n");

}


void event_exit()
{
	dr_printf("[drgat]Ready to exit PID%d, waiting for writes to finish\n", dr_get_process_id());
	dr_sleep(1000); //might not be needed
	traceClientptr->write_sync_mod("[CLIENT]EVENT: Exit\n");

	file_t closer = dr_open_file("\\\\.\\pipe\\riomodpipe", DR_FILE_WRITE_OVERWRITE);
	dr_fprintf(closer, "DIE");
	dr_flush_file(closer);
	dr_close_file(closer);

	//should probably free some stuff
	drmgr_exit();
	dr_printf("[drgat]exit called for process %d\n", dr_get_process_id());
}

static void
event_thread_init(void *threadcontext)
{
	thread_id_t tid = dr_get_thread_id(threadcontext);
	
	DR_ASSERT_MSG(tid < MAXTHREADID, "Raise threadIDmax");

	static dr_time_t dt;
	dr_get_time(&dt);

	traceClientptr->write_sync_mod("TI%d", tid);

	char pipeName[255];
	dr_snprintf(pipeName, 254, "\\\\.\\pipe\\rioThread%d", tid);

	file_t threadoutpipe = INVALID_FILE;

	//this has been a bottleneck in the past, be wary of it
	while (threadoutpipe == INVALID_FILE)
	{
		dr_sleep(10);
		threadoutpipe = dr_open_file(pipeName, DR_FILE_WRITE_OVERWRITE);
	}

	THREAD_STATE *thread;
	thread = (THREAD_STATE *)dr_thread_alloc(threadcontext, sizeof(THREAD_STATE));
	thread->tid = tid;
	thread->f = threadoutpipe;
	thread->BBBuf = (char *)dr_thread_alloc(threadcontext, MAXBBBYTES);
	thread->tagIdx = 0;
	thread->cacheRepeats = 0;
	thread->loopMax = 0;
	thread->lastTick = 0;

	drmgr_set_tls_field(threadcontext, traceClientptr->tls_idx, (THREAD_STATE *)thread);
	dr_flush_file(thread->f);
}

static void
event_thread_exit(void *threadcontext)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(threadcontext, traceClientptr->tls_idx);

	int tid = dr_get_thread_id(threadcontext);
	printTagCache(thread);
	dr_close_file(thread->f);

	dr_sleep(200); //hopefully stop the memory free from screwing up pending BB writes
	dr_thread_free(threadcontext, thread->BBBuf, MAXBBBYTES);
	dr_thread_free(threadcontext, thread, sizeof(THREAD_STATE));

	traceClientptr->write_sync_mod("texit @%d\n", tid);
}

static uint lastPrintedMod = 999999;

dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag,
	instrlist_t *bb,	bool for_trace, bool translating,	void **user_data)
{
	thread_id_t tid = dr_get_thread_id(drcontext);
	uint threadMod = threadModArr[tid];
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(drcontext, traceClientptr->tls_idx);
	
	char *BBBuf = thread->BBBuf;
	
	instr_t *firstIns = instrlist_first_app(bb);
	app_pc firstiPC = instr_get_app_pc(firstIns);
	bool isInstrumented = false;
	int mno = -1;

	
	uint bufIdx = 0;
	UINT32 blockID_count = dr_get_random_value(INT_MAX) & 0xffff;

	//might do better with dr_lookup_module but it causes error :( 
	//					 + dr_free_module_data(exe_data);
	//need to know where this code is, compare with module list

	if (//in same module as last BB for this thread
		(firstiPC >= traceClientptr->modStarts.at(threadMod)) && (firstiPC <= traceClientptr->modEnds.at(threadMod))
		)
	{
		isInstrumented = traceClientptr->includedModules.at(threadMod);
		mno = threadMod;
		bufIdx = dr_snprintf(BBBuf, 512, "B@%x@%d@%d@%x", firstiPC, threadMod, isInstrumented, blockID_count);
	}
	else
	{
		//have to find which module BB is in
		for (mno = 0; mno < traceClientptr->numMods; ++mno)
		{
			if ((firstiPC < traceClientptr->modStarts.at(mno)) || 
				(firstiPC > traceClientptr->modEnds.at(mno))) continue;
			
			threadMod = mno;
			threadModArr[tid] = mno;
			isInstrumented = traceClientptr->includedModules.at(threadMod);
			bufIdx = dr_snprintf(BBBuf, 512, "B@%x@%d@%d@%x", firstiPC, mno, isInstrumented, blockID_count);
			break;
		}

		if (mno >= traceClientptr->numMods)
		{	
			//failed to find. self modifying code?
			//may be good idea to make this instrumented = true
			printTagCache(thread);
			dr_mem_info_t meminfo;
			dr_query_memory_ex(firstiPC, &meminfo);
			if (meminfo.type == DR_MEMTYPE_DATA)
			{
				isInstrumented = true;
				mno = 0;
				bufIdx = dr_snprintf(BBBuf, 512, "B@%x@%d@1@%x", firstiPC, mno, blockID_count);
			}
			else
			{
				dr_printf("Searched %d mods but could not find address %lx Code may have modified mapped image\n", mno, firstiPC);
				dr_printf("Base: %lx, size:%d, prot:%d type:%d\n", meminfo.base_pc, meminfo.size, meminfo.prot, meminfo.type);
				for (mno = 0; mno < traceClientptr->numMods; mno++)
				{
					dr_printf("Mod %d: %lx -> %lx\n", mno, 
						traceClientptr->modStarts.at(mno), 
						traceClientptr->modEnds.at(mno));
				}
				dr_printf("-------------\n");

				mno = 0;
				bufIdx = dr_snprintf(BBBuf, 512, "B@%x@%d@1@%x", firstiPC, mno, blockID_count);
			}
		}
	}

	
	if(!isInstrumented) 
	{
		if (instr_is_meta(firstIns))
		{
			dr_printf("func %lx is wrapped!\n",firstiPC);
		}
		BBBuf[bufIdx] = 0;
		userd *bb_u_d = 0;
		traceClientptr->write_sync_bb(BBBuf, bufIdx);
		return DR_EMIT_DEFAULT;
	}

	userd *bb_u_d = (userd *)logged_memalloc(sizeof(userd));
	bb_u_d->appc = firstiPC; //tag not always == rip

	unsigned instructionCount = 0;
	int lineIdx = 0, ilen, opcIdx;
	
	//opcodes for each instruction
	for (instr_t *ins = firstIns; ins != NULL; ins = instr_get_next(ins)) 
	{
		++instructionCount;
		lineIdx = dr_snprintf(lineStr + lineIdx, 1, "@");

		ilen = instr_length(drcontext, ins);
		for (opcIdx = 0; opcIdx < ilen; ++opcIdx)
		{
			lineIdx += dr_snprintf(lineStr + lineIdx, MAXDISLEN - lineIdx, "%02x", instr_get_raw_byte(ins, opcIdx));
		}

		bufIdx += dr_snprintf(BBBuf + bufIdx, lineIdx, "%s", lineStr);
		DR_ASSERT_MSG(bufIdx < MAXBBBYTES, "[drgat]BB string larger than MAXBBBYTES!");
	}
	bb_u_d->blockID_numins = (blockID_count << 16)+instructionCount;

	BBBuf[bufIdx] = 0;
	traceClientptr->write_sync_bb(BBBuf, bufIdx);

	instr_t *lasti = instrlist_last_app(bb);

	//block processing is done at the end of the block, but we need to know first instruction of block there
	//put BB data pointer in spill slot 2 (via XAX which we save/restore using slot 1)
	dr_save_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_1);
	instr_t *in = INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(DR_REG_XAX), OPND_CREATE_INT32(bb_u_d));
	instrlist_meta_preinsert(bb,lasti,in);
	dr_save_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_2);
	dr_restore_reg(drcontext,bb,lasti,DR_REG_XAX,SPILL_SLOT_1);

	
	if (instr_is_cbr(lasti))
	{
		bb_u_d->fallthrough = instr_get_app_pc(lasti) + opnd_size_in_bytes(instr_get_opcode(lasti));
		dr_insert_cbr_instrumentation(drcontext, bb, lasti, (void*)at_cbr);
	}

	else if (instr_is_ubr(lasti))
		dr_insert_ubr_instrumentation(drcontext, bb, lasti, (void*)at_ubr);
		
	//far calls are hit here, must evaluate before is_call
	else if(instr_is_mbr(lasti))
		dr_insert_mbr_instrumentation(drcontext, bb, lasti, (app_pc)at_mbr,SPILL_SLOT_1);
                        
	else if (instr_is_call(lasti)) //is_call_direct?
		dr_insert_call_instrumentation(drcontext, bb, lasti, (void*)at_call);

	else
	{
		std::stringstream badterm;
		badterm << "[drgat]Unhandled block terminator: " << std::hex << instr_get_opcode(lasti);
		DR_ASSERT_MSG(0,badterm.str().c_str());
	}
	
	return DR_EMIT_DEFAULT;
}









