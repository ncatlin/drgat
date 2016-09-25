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

#include "headers\windowstrace.h"
#include "headers\traceclient.h"
#include "headers\utilities.h"

//todo: sort crash if target buffer full (ie: paused w/debugger)

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
#define MAXDISLEN 4096 

#ifdef DEBUG_LOGGING
file_t dbgfile;
#endif

TRACECLIENT *traceClientptr;
//quick and dirty way of reducing our time spent looking which module a given address belongs to
uint threadModArr[MAXTHREADID];

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
	dr_printf("[drgat]Client starting with %d options: \n",ask_argc-1);
	for (int x = 1; x < ask_argc; ++x)
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

		//instrument all libraries by default, de-instrument uwanted with exclude
		if (arg == "-defaultinstrument")
		{
			client->defaultInstrument = true;
			continue;
		}

		//specify libraries to instrument
		if (arg == "-include")
		{
			client->load_modinclude_strings((char *)ask_argv[++x]);
			continue;
		}

		//used with -defaultinstrument
		if (arg == "-exclude")
		{
			client->load_modexclude_strings((char *)ask_argv[++x]);
			continue;
		}

	}
}

/*
basic loop compression happens here
if not in a loop and we jump back, we are setting cache[0] to start of loop
next iteration we notice the target is cache[0] and start loop increments
*/
inline void process_block(app_pc pc, app_pc target, BLOCKDATA *block_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	thread->sourceInstruction = pc;
	int tagIdx = thread->tagIdx++; //do increment here to avoid extra read
	
	#ifdef DEBUG_LOGGING
	dr_fprintf(thread->dbgfile,"process_block insaddr 0x%lx bb [tagidx %d addr 0x%lx targ 0x%lx]\n",pc,tagIdx,block_data->appc,target);
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
		//ideally the processing for most blocks ends here
		if ((void *)target > (void *)pc) 
			return;

		#ifdef DEBUG_LOGGING
		dr_fprintf(thread->dbgfile,"\tnot in loop insaddr 0x%lx bb [tagidx %d addr 0x%lx targ 0x%lx]\n",pc,tagIdx,block_data->appc,target);
		#endif
		
		if (thread->tagCache[0] == target)//back to start of cache
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"\ttarg 0x%lx == cache0 0x%lx -> starting loop",target, thread->tagCache[0]);
			#endif
			//record cache as first iteration of a loop
			thread->loopMax = tagIdx;
			thread->cacheRepeats++;
			thread->tagIdx = 0;
		}
		else
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"\tunknown backedge idx %d, targ 0x%lx!, cache[0] 0x%lx\n",tagIdx,
					target,thread->tagCache[0]);
			#endif
			//back to something else, dump cache
			printTagCache(thread);
		}
		return;
	}


	if (tagIdx == thread->loopMax) //end of loop
	{
		#ifdef DEBUG_LOGGING
		dr_fprintf(thread->dbgfile,"\tend of loop idx %d, checking targ 0x%lx! =  cache[0] 0x%lx\n",tagIdx,
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
			
		//leaving loop. print loops up until now + progress on current loop
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
		#ifdef DEBUG_LOGGING
		dr_fprintf(thread->dbgfile,"\tloop mismatch dumpcache idx %d, 0x%lx!=0x%lx,numins:%d, 0x%lx!=0x%lx\n",tagIdx,
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


static void at_cbr(app_pc pc, app_pc target, app_pc fallthrough, int taken, void *u_d)
{
	BLOCKDATA *block_data = (BLOCKDATA *)u_d;

	#ifdef DEBUG_LOGGING
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->dbgfile,"at_cbr pc 0x%lx target 0x%lx blockhead 0x%lx fallthroughaddr:0x%lx taken:%d\n",
		pc,target,block_data->appc,fallthrough,taken);
	#endif

	if (taken)
		process_block(pc, target, block_data);
	else
		process_block(pc, fallthrough, block_data);
}


static void at_ubr(app_pc pc, app_pc target)
{
	#ifdef DEBUG_LOGGING
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->dbgfile,"at_ubr 0x%lx->0x%lx\n",pc,target);
	#endif

	BLOCKDATA *block_data = (BLOCKDATA *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	process_block(pc, target, block_data);
}

static void at_mbr(app_pc pc, app_pc target)
{
	#ifdef DEBUG_LOGGING
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->dbgfile, "at_mbr address 0x%lx -> 0x%lx\n",pc, target);
	#endif

	BLOCKDATA *block_data = (BLOCKDATA *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	process_block(pc, target, block_data);
}

static void at_call(app_pc pc, app_pc target)
{
	#ifdef DEBUG_LOGGING
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(thread->dbgfile, "at_call address 0x%lx -> 0x%lx\n",pc,target);
	#endif

	BLOCKDATA *block_data = (BLOCKDATA *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	process_block(pc, target, block_data);
}


DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
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

	traceClientptr->allocMutx = dr_mutex_create();
	traceClientptr->latestAllocNode = (ALLOCLL *)dr_thread_alloc(clientContext, sizeof(ALLOCLL));
	traceClientptr->tls_idx = drmgr_register_tls_field();
	DR_ASSERT(traceClientptr->tls_idx != -1);
	traceClientptr->pid = dr_get_process_id();

#ifdef DEBUG_LOGGING
	char filebuf[MAX_PATH];
	dr_get_current_directory(filebuf, MAX_PATH);
	std::string threadDbgFile = filebuf+std::string("\\")+"BBlog"+std::to_string(traceClientptr->pid)+".txt";
	dbgfile = dr_open_file(threadDbgFile.c_str(), DR_FILE_WRITE_OVERWRITE);
#endif
	dr_printf("[drgat]Starting instrumentation of %s (PID:%d)\n",appPath.c_str(),traceClientptr->pid);

	std::string pipeName;
	traceClientptr->modpipe = dr_open_file("\\\\.\\pipe\\BootstrapPipe", DR_FILE_WRITE_OVERWRITE);
	while (traceClientptr->modpipe == INVALID_FILE)
	{
		dr_sleep(600);
		dr_printf("[drgat]Warning: Waiting to connect to bootstrap pipe!\n");
		traceClientptr->modpipe = dr_open_file("\\\\.\\pipe\\BootstrapPipe", DR_FILE_WRITE_OVERWRITE);
	}

	//notify rgat to create threads for this process
	dr_fprintf(traceClientptr->modpipe, "PID%d", traceClientptr->pid);
	dr_sleep(600);

	traceClientptr->modpipe = INVALID_FILE;
	pipeName = "\\\\.\\pipe\\rioThreadMod";
	pipeName.append(std::to_string(traceClientptr->pid));

	traceClientptr->modpipe = dr_open_file(pipeName.c_str(), DR_FILE_WRITE_OVERWRITE);
	while (traceClientptr->modpipe == INVALID_FILE)
	{
		dr_sleep(600);
		dr_printf("[drgat]Waiting to open %s\n",pipeName.c_str());
		traceClientptr->modpipe = dr_open_file(pipeName.c_str(), DR_FILE_WRITE_OVERWRITE);
	}

	dr_sleep(500);
	pipeName = "\\\\.\\pipe\\rioThreadBB";
	pipeName.append(std::to_string(traceClientptr->pid));
	traceClientptr->bbpipe = dr_open_file(pipeName.c_str(), DR_FILE_WRITE_OVERWRITE);
	DR_ASSERT_MSG(traceClientptr->bbpipe != INVALID_FILE, "No rioThreadBB pipe!");

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
	
	traceClientptr->write_sync_mod("mn@%s@%d@%lx@%lx@%x", mainmodule->full_path, 0,
		mainmodule->start, mainmodule->end, !traceClientptr->includedModules[0]);

	start_sym_processing(0, mainmodule->full_path);
	traceClientptr->numMods = 1;

	//start instrumentation
	dr_register_exit_event(event_exit);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);
		drmgr_register_exception_event(event_exception);
	drmgr_register_bb_instrumentation_event(event_bb_analysis, NULL, NULL);

	#ifdef WINDOWS
	drmgr_register_module_load_event(windows_event_module_load);
	#elif LINUX
	drmgr_register_module_load_event(linux_event_module_load);
	#endif
}


static void event_exit()
{
	dr_printf("[drgat]Ready to exit PID%d, waiting for writes to finish\n", dr_get_process_id());
	dr_sleep(1000); //might not be needed
	traceClientptr->write_sync_mod("[CLIENT]EVENT: Exit\n");

	file_t closer = dr_open_file("\\\\.\\pipe\\riomodpipe", DR_FILE_WRITE_OVERWRITE);
	dr_fprintf(closer, "DIE");
	dr_flush_file(closer);
	dr_close_file(closer);

	//should probably free some stuff - meh
	drmgr_exit();
	dr_printf("[drgat]exit called for process %d\n", dr_get_process_id());
}

static void event_thread_init(void *threadcontext)
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
#ifdef DEBUG_LOGGING
	char filebuf[MAX_PATH];
	dr_get_current_directory(filebuf, MAX_PATH);
	std::string threadDbgFile = filebuf+std::string("\\")+"tracelog"+std::to_string(traceClientptr->pid)+std::to_string(tid)+".txt";
	thread->dbgfile = dr_open_file(threadDbgFile.c_str(), DR_FILE_WRITE_OVERWRITE);
#endif
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

/* 
this: determines whether a block should be instrumented
	  inserts code to make the address of the basic block data structure available to analysis code
	  adds analysis code to conditionals where needed
	  pipes the basic block opcode data to rgats basicblock thread
*/
dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag,
	instrlist_t *bb,	bool for_trace, bool translating,	void **user_data)
{
	char lineStr[MAXDISLEN];
	thread_id_t tid = dr_get_thread_id(drcontext);
	uint threadMod = threadModArr[tid];
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(drcontext, traceClientptr->tls_idx);
	
	char *BBBuf = thread->BBBuf;
	instr_t *firstIns = instrlist_first_app(bb);
	app_pc firstiPC = instr_get_app_pc(firstIns);

	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"basic block head: %lx\n",firstiPC);
	#endif

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

		//this is near enough untested and i make no guarantees about its robustness
		//external libraries creating code outside the initial ranges will probably cause huge problems
		if (mno >= traceClientptr->numMods)
		{	
			//failed to find. self modifying code?
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
		BBBuf[bufIdx] = 0;
		BLOCKDATA *bb_u_d = 0;
		traceClientptr->write_sync_bb(BBBuf, bufIdx);
		return DR_EMIT_DEFAULT;
	}

	BLOCKDATA *bb_u_d = (BLOCKDATA *)logged_memalloc(sizeof(BLOCKDATA));
	bb_u_d->appc = firstiPC; //tag not always == rip

	unsigned instructionCount = 0;
	int lineIdx = 0, ilen, opcIdx;
	
	//opcodes for each instruction
	for (instr_t *ins = firstIns; ins != NULL; ins = instr_get_next(ins)) 
	{
		#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile,"\t instrumented block instruction: %lx\n",instr_get_app_pc(ins));
		#endif
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
	
	//finally add appropriate analysis code to the block terminator
	if (instr_is_cbr(lasti))
		dr_insert_cbr_instrumentation_ex(drcontext, bb, lasti, (void*)at_cbr, OPND_CREATE_INT32(bb_u_d));
	else 
	{
		//the other instrumentation methods don't allow passing of a user argument
		//so we have to transfer it via spill slots instead
		dr_save_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_1);
		instr_t *in = INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(DR_REG_XAX), OPND_CREATE_INT32(bb_u_d));
		instrlist_meta_preinsert(bb,lasti,in);
		dr_save_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_2);
		dr_restore_reg(drcontext,bb,lasti,DR_REG_XAX,SPILL_SLOT_1);

		if (instr_is_ubr(lasti))
			dr_insert_ubr_instrumentation(drcontext, bb, lasti, (void*)at_ubr);
		
		//order is important here as far calls are hit by this and instr_is_call
		else if(instr_is_mbr(lasti))
			dr_insert_mbr_instrumentation(drcontext, bb, lasti, (app_pc)at_mbr,SPILL_SLOT_1);
                        
		else if (instr_is_call(lasti))
			dr_insert_call_instrumentation(drcontext, bb, lasti, (void*)at_call);

		else
			{
			std::stringstream badterm;
			badterm << "[drgat]Unhandled block terminator: " << std::hex << instr_get_opcode(lasti);
			DR_ASSERT_MSG(0,badterm.str().c_str());
			}
	}
	return DR_EMIT_DEFAULT;
}









