/*
Trace requirements:
Every instruction of target (internal) code, in order
The first address of non-target (external) code
Need to record target of every jump in case it hits external + can check conditional completion offline
*/


#define _WIN32
//I tried to compile this using VS2015 but no matter what options or defines I used 
//it wouldn't run on windows 10. these are a monument to my failure
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


static void at_cbr(app_pc pc, app_pc target, app_pc fallthrough, int taken, void *u_d);
static void at_ubr(app_pc pc, app_pc target);
static void at_mbr(app_pc pc, app_pc target);
static void at_call(app_pc pc, app_pc target);

static void at_cbr_dbg(app_pc pc, app_pc target, app_pc fallthrough, int taken, void *u_d);
static void at_ubr_dbg(app_pc pc, app_pc target);
static void at_mbr_dbg(app_pc pc, app_pc target);
static void at_call_dbg(app_pc pc, app_pc target);
void *instrumentationTable[2][4];

#ifdef DEBUG_LOGGING
file_t dbgfile;
#endif

unsigned long memcount = 0;
unsigned long tmemcount = 0;
extern unsigned long *globmemcount = &memcount;
extern unsigned long * threadmemcount = &tmemcount;
std::vector<std::unordered_set<TARG_BLOCKID_PAIR>*> setAddrs;

TRACECLIENT *traceClientptr;

//quick and dirty way of reducing our time spent looking which module a given address belongs to
std::unordered_map<thread_id_t, unsigned int> threadModArr;

//write to the basic block handler thread
void TRACECLIENT::write_sync_bb(char* buf, uint strsize)
{
	if(!dr_write_file(bbpipe, buf, strsize)) //fprintf truncates to internal buffer size!
	{
		dr_printf("[drgat]Abort called in write_sync_bb\n");
		dr_abort();
	}

	dr_flush_file(bbpipe);
}

//write to the module_handler_thead
void TRACECLIENT::write_sync_mod(char *logText, ...)
{
	char str[MAXMODMSGSIZE];
	ssize_t total = 0;
	va_list args;
	va_start(args, logText);
	total += dr_vsnprintf(str, MAXMODMSGSIZE, logText, args);
	va_end(args);
	DR_ASSERT_MSG(total,str);
	str[total] = 0;
	DR_ASSERT_MSG(total < MAXMODMSGSIZE, "MAXMODMSGSIZE too small");
	total = dr_fprintf(modpipe, "%s", str);
	if (total <= 0)
	{
		dr_printf("[drgat]Abort called in write_sync_mod\n");
		dr_abort();
	}

	dr_flush_file(modpipe);
}


static bool event_exception(void *drcontext, dr_exception_t *excpt)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	#ifdef DEBUG_LOGGING
	dr_fprintf(thread->dbgfile,"In exception event\n");
	dr_flush_file(thread->dbgfile);
	#endif

	printTagCache(thread);
	dr_fprintf(thread->f, "EXC,"ADDR_FMT",%lx,%lx@", excpt->record->ExceptionAddress, excpt->record->ExceptionCode, excpt->record->ExceptionFlags);
	return true;
}

//take comma separated string, place in suplied string buf
void TRACECLIENT::load_modinclude_strings(char *commaSepPaths)
{
	std::string pathString(commaSepPaths);
	std::stringstream ss(pathString);

	while (includedModuleStrings.size() < MAXINCLUDES) 
	{
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

		//hide sleeps/shorten tick counts
		if (arg == "-blkdebug")
		{
			client->processingMode = DEBUG_TRACING;
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
uses thread and block activity counters to decide when to unchain blocks on a sliding scale
looks something like this:

b1 b2 b3 b4 b5
1   1  1  1 
       2  2 
       3  3 
2   2  2  2 
       3  3 
	   4  4 
3   3  3  3 
       4  4 
	   5  5
	        1
1   1  1  1
	   
*/


inline void process_block_chain(app_pc pc, app_pc target, BLOCKDATA *block_data)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	#ifdef DEBUG_LOGGING
	dr_fprintf(thread->dbgfile,"<>process_block_chain: %d, block: "ADDR_FMT", blockbusy:%d, threadbusy:%d\n",
		thread->tid, block_data->appc, block_data->busyCounter, thread->busyCounter);
	dr_flush_file(thread->dbgfile);
	#endif

	//thread in an area of high workload above deinstrumentation threshold
	if (thread->unchainedExist)
	{

		//this block (or its target) is new to the work area
		//rechain everything (start processing slowly)
		if((block_data->busyCounter == 0) || (thread->lastestBlockIDs.count(target) == 0))
		{
			#ifdef DEBUG_LOGGING
			if(block_data->busyCounter == 0) 
				dr_fprintf(thread->dbgfile,"chain reattached by 0 activity block "ADDR_FMT", caller had executed %d times\n",
				block_data->appc, thread->lastBlock->unchainedRepeats);
			if (thread->lastestBlockIDs.count(target) == 0)
				dr_fprintf(thread->dbgfile,"chain reattached by new target "ADDR_FMT", caller had executed %d times\n",
				target, thread->lastBlock->unchainedRepeats);
			#endif

			printTagCache(thread);

			std::vector<void *>::iterator unchainedIt = thread->unchainedBlocks.begin();
			for (; unchainedIt != thread->unchainedBlocks.end(); ++unchainedIt)
			{
				BLOCKDATA *chainedBlock = ((BLOCKDATA *)*unchainedIt);
				std::unordered_set<TARG_BLOCKID_PAIR>::iterator targetsIt = chainedBlock->targets->begin();

				/*
				std::stringstream outpt;
				outpt << "BX,"<<std::hex<<(unsigned long)chainedBlock->appc<<","<<chainedBlock->blockID_numins<<","<<std::hex<<chainedBlock->unchainedRepeats;
				for(; targetsIt != chainedBlock->targets->end(); ++targetsIt)
					outpt<<","<<std::hex<<(unsigned long)targetsIt->first<<","<<targetsIt->second;
				dr_fprintf(thread->f,"%s@",outpt.str().c_str());
				*/
				
				//not noticing any significant differences in speed between them but this avoids mem allocations
				unsigned int outputcount = 0;
				outputcount += dr_snprintf(thread->BXbuffer,TAGCACHESIZE, "BX,"ADDR_FMT",%llx,%lx",chainedBlock->appc,chainedBlock->blockID_numins,chainedBlock->unchainedRepeats);
				for(; targetsIt != chainedBlock->targets->end(); ++targetsIt)
					outputcount += dr_snprintf(thread->BXbuffer+outputcount,TAGCACHESIZE-outputcount,","ADDR_FMT",%lx",targetsIt->first, targetsIt->second);
				dr_fprintf(thread->f,"%s@",thread->BXbuffer);
				
				
				dr_flush_file(thread->f);

				chainedBlock->unchained = false;
				chainedBlock->busyCounter = 0;
			}
			thread->unchainedBlocks.clear();
			thread->unchainedExist = false;

			//make link between unchained nodes and new appearance
			//this also inserts current block onto graph
			dr_fprintf(thread->f, "UL,"ADDR_FMT",%llx,"ADDR_FMT",%llx@", thread->lastBlock->appc,thread->lastBlock->blockID_numins, 
				block_data->appc, block_data->blockID_numins);
			dr_flush_file(thread->f);
			thread->busyCounter = ++block_data->busyCounter;
		}

		//in an area of high workload, this block is part of it so unchain it too
		else
		{
			printTagCache(thread); //just in case

			block_data->unchainedRepeats = 1;
			block_data->unchained = true;
			block_data->lastTarget = target;

			BLOCK_IDENTIFIER targBlockID = thread->lastestBlockIDs.at(target);
			block_data->lastTargetID = targBlockID;
			block_data->targets->clear();
			block_data->targets->insert(std::make_pair(target, targBlockID));

			thread->unchainedBlocks.push_back((void *) block_data);
			thread->lastBlock = block_data;
			thread->lastBlock_expected_targID = targBlockID;

			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"UC0 Entry-- "ADDR_FMT",%lx,"ADDR_FMT",%lx@",block_data->appc, block_data->blockID, target, targBlockID);
			#endif
			//notify visualiser that this area is going to be busy and won't report back until done
			dr_fprintf(thread->f, "UC,"ADDR_FMT",%lx,"ADDR_FMT",%lx@",block_data->appc, block_data->blockID, target, targBlockID);
			dr_flush_file(thread->f);

		}
		return;
	}

	//if here then thread is below unchaining threshold

	//area of increased activity, increase block activity counter
	if ((block_data->busyCounter == thread->busyCounter) || 
		(block_data->busyCounter == (thread->busyCounter-1)))
	{

		//increase thread activity counter if all blocks aside from from this one
		if (++block_data->busyCounter > thread->busyCounter)
			++thread->busyCounter;

		if(block_data->busyCounter >= DEINSTRUMENTATION_LIMIT)
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"Deinstrumentation limit reached at block "ADDR_FMT", unchaining\n",block_data->appc);
			#endif

			printTagCache(thread);

			block_data->unchainedRepeats = 1;
			block_data->unchained = true;
			block_data->lastTarget = target;

			BLOCK_IDENTIFIER targBlockID;
			BLOCKIDMAP::iterator blockIDIt = thread->lastestBlockIDs.find(target);
			if(blockIDIt == thread->lastestBlockIDs.end())
			{
				thread->unsatisfiedBlockIDs = true;
				thread->unsatisfiedBlockIDAddress = target;
				targBlockID = 0;
				#ifdef DEBUG_LOGGING
				dr_fprintf(thread->dbgfile,"Unsatisfied block registered. Target: "ADDR_FMT"\n", target);
				#endif
			}
			else
				targBlockID = blockIDIt->second;

			block_data->lastTargetID = targBlockID;
			block_data->targets->clear();
			block_data->targets->insert(std::make_pair(target, targBlockID));
			thread->unchainedBlocks.push_back(((void *) block_data));
			thread->unchainedExist = true;
			thread->lastBlock = block_data;
			thread->lastBlock_expected_targID = targBlockID;

			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"UC1 Entry-- "ADDR_FMT",%lx,"ADDR_FMT",%lx\n",block_data->appc, block_data->blockID, target, targBlockID);
			#endif

			dr_fprintf(thread->f, "UC,"ADDR_FMT",%lx,"ADDR_FMT",%lx@",block_data->appc, block_data->blockID, target, targBlockID);
			dr_flush_file(thread->f);
			return;
		}
	}
	
	else //block busier than recent thread actvity - lower block activity to match
		if (block_data->busyCounter > thread->busyCounter)
		block_data->busyCounter = thread->busyCounter; 
	else 
		//active block with less activity than thread - lower thread activity to match
		thread->busyCounter = ++block_data->busyCounter;

	thread->sourceInstruction = pc; //not set in unchained --- hasn't been a problem yet
	thread->lastBlock = block_data;

	unsigned int tagIdx = thread->tagIdx++;
	if (tagIdx > TAGCACHESIZE-1)
	{
		printTagCache(thread);
		tagIdx = 0;
	}

	if (!thread->cacheRepeats)
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
		dr_fprintf(thread->dbgfile,"\tnot in loop insaddr 0x"ADDR_FMT" bb [tagidx %d addr 0x"ADDR_FMT" targ 0x"ADDR_FMT"]\n",pc,tagIdx,block_data->appc,target);
		#endif
		
		if (thread->tagCache[0] == target)//back to start of cache
		{
			//record cache as first iteration of a loop
			thread->loopEnd = tagIdx;
			thread->cacheRepeats++;
			thread->tagIdx = 0;

			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"starting new loop of %d blocks from "ADDR_FMT" (cachrepeats set to %d)",thread->loopEnd, target,
				thread->cacheRepeats);
			#endif
		}
		else
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"\tunknown backedge idx %d, targ 0x"ADDR_FMT"!, cache[0] 0x"ADDR_FMT"\n",tagIdx,
					target,thread->tagCache[0]);
			#endif
			//back to something else, dump cache
			printTagCache(thread);
		}
		return;
	}


	if (tagIdx == thread->loopEnd) //end of loop
	{

		#ifdef DEBUG_LOGGING
		dr_fprintf(thread->dbgfile,"\tend of loop idx %d, checking targ 0x"ADDR_FMT"! =  cache[0] 0x"ADDR_FMT"\n",tagIdx,
					target,thread->tagCache[0]);
		#endif

		//back to start of loop
		if (target == thread->tagCache[0])
		{
			//record another iteration of cache
			++thread->cacheRepeats;
			thread->tagIdx = 0;

			#ifdef DEBUG_LOGGING
			dr_fprintf(thread->dbgfile,"\tback to start of loop head "ADDR_FMT", loop now %d iterations\n",target,thread->cacheRepeats);
			#endif
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
		dr_fprintf(thread->dbgfile,"\tloop mismatch dumpcache idx %d, 0x"ADDR_FMT"!=0x"ADDR_FMT",numins:%d, 0x"ADDR_FMT"!=0x"ADDR_FMT"\n",tagIdx,
					thread->tagCache[tagIdx],(uint)block_data->appc,	
					block_data->numInstructions,thread->targetAddresses[tagIdx], target);
		dr_flush_file(thread->dbgfile);
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

static void at_cbr(app_pc pc, app_pc target, app_pc fallthrough, int taken, void *blk_d)
{
	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"at_cbr called\n");
	#endif
	app_pc actualTarget = taken ? target : fallthrough;
	BLOCKDATA * block_data = ((BLOCKDATA *)blk_d);

	#ifdef DEBUG_LOGGING
	THREAD_STATE *dbgthread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(dbgthread->dbgfile,"at_cbr pc 0x"ADDR_FMT" target 0x"ADDR_FMT" blockhead 0x"ADDR_FMT" fallthroughaddr:0x"ADDR_FMT" taken:%d\n",
		pc,target,block_data->appc,fallthrough,taken);
	dr_flush_file(dbgthread->dbgfile);
	#endif

	if (!block_data->unchained)
	{
		process_block_chain(pc, actualTarget, block_data);
		return;
	}
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	
	//increase count of executions for this block
	++block_data->unchainedRepeats;
		
	//check to see if we arrived at the expected target
	if (block_data->blockID != thread->lastBlock_expected_targID)
	{
		//nope, add a new target to previous block so it can be added to graph
		thread->lastBlock->targets->insert(std::make_pair(block_data->appc, block_data->blockID));
		thread->lastBlock->lastTargetID = block_data->blockID;
	}

	//update state so next block can do the same check
	thread->lastBlock_expected_targID = block_data->lastTargetID;

	//check if the next target is the one block expects
	//if not then update the expected target and add it to target list
	//this avoids expensive set lookup every execution
	if (actualTarget != block_data->lastTarget)
	{
		block_data->lastTarget = actualTarget;

		BLOCKIDMAP::iterator latestIDIt = thread->lastestBlockIDs.find(actualTarget);
		//if not found then BB hasn't been created yet. this causes value to be set when it is created
		if (latestIDIt == thread->lastestBlockIDs.end())
			{
				thread->unsatisfiedBlockIDs = true;
				thread->unsatisfiedBlockIDAddress = actualTarget;
				block_data->lastTargetID = 0;
			}
		else
			{
				block_data->lastTargetID = latestIDIt->second;
				block_data->targets->insert(std::make_pair(actualTarget, latestIDIt->second));
			}
	}

	//update state so we know which member of unchained area executed an inactive block, if target is inactive
	thread->lastBlock = block_data;

	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgthread->dbgfile,"cbr done targ->0x"ADDR_FMT"\n",actualTarget);
	dr_flush_file(dbgthread->dbgfile);
	#endif
}


static void at_ubr(app_pc pc, app_pc target)
{
	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"at_ubr called\n");
	dr_flush_file(dbgfile);
	#endif

	BLOCKDATA *block_data = (BLOCKDATA *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
	
	#ifdef DEBUG_LOGGING
	THREAD_STATE *dbgthread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(dbgthread->dbgfile,"at_ubr 0x"ADDR_FMT"->0x"ADDR_FMT"\n",pc,target);
	dr_flush_file(dbgthread->dbgfile);
	#endif

	if (!block_data->unchained)
	{
		process_block_chain(pc, target, block_data);
		return;
	}

	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	++block_data->unchainedRepeats;
		
	//check to see if we arrived at the expected target
	if (block_data->blockID != thread->lastBlock_expected_targID)
	{
		//nope, add a new target to previous block so it can be added to graph
		thread->lastBlock->targets->insert(std::make_pair(block_data->appc, block_data->blockID));
		thread->lastBlock->lastTargetID = block_data->blockID;
	}

	//update state so next block can do the same check
	thread->lastBlock_expected_targID = block_data->lastTargetID;

	//check if the next target is the one block expects
	//if not then update the expected target and add it to target list
	//this avoids expensive set lookup every execution
	if (target != block_data->lastTarget)
	{
		block_data->lastTarget = target;
		BLOCKIDMAP::iterator blockIDit = thread->lastestBlockIDs.find(target);
		if (blockIDit != thread->lastestBlockIDs.end())
		{
			thread->unsatisfiedBlockIDs = true;
			thread->unsatisfiedBlockIDAddress = target;
			block_data->lastTargetID = 0;
		}
		else
		{
			block_data->lastTargetID = blockIDit->second;
			block_data->targets->insert(std::make_pair(target, block_data->lastTargetID));
		}	
	}

	//update state so drgat knows which member of unchained area executed an inactive block
	thread->lastBlock = block_data;

	#ifdef DEBUG_LOGGING
	dr_fprintf(thread->dbgfile,"ubr done targ->0x"ADDR_FMT"\n",target);
	dr_flush_file(thread->dbgfile);
	#endif


}

static void at_mbr(app_pc pc, app_pc target)
{
	BLOCKDATA *block_data = (BLOCKDATA *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);

	#ifdef DEBUG_LOGGING
	THREAD_STATE *dbgthread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(dbgthread->dbgfile, "at_mbr address 0x"ADDR_FMT" -> 0x"ADDR_FMT"\n",pc, target);
	dr_flush_file(dbgthread->dbgfile);
	#endif

	if (!block_data->unchained)
	{
		process_block_chain(pc, target, block_data);
		return;
	}

	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	++block_data->unchainedRepeats;
		
	//check to see if we arrived at the expected target
	if (block_data->blockID != thread->lastBlock_expected_targID)
	{
		//nope, add a new target to previous block so it can be added to graph
		thread->lastBlock->targets->insert(std::make_pair(block_data->appc, block_data->blockID));
		thread->lastBlock->lastTargetID = block_data->blockID;
	}

	//update state so next block can do the same check
	thread->lastBlock_expected_targID = block_data->lastTargetID;

	//check if the next target is the one block expects
	//if not then update the expected target and add it to target list
	//this avoids expensive set lookup every execution
	if (target != block_data->lastTarget)
	{
		BLOCKIDMAP::iterator blockIDit = thread->lastestBlockIDs.find(target);
		if (blockIDit != thread->lastestBlockIDs.end())
		{
			thread->unsatisfiedBlockIDs = true;
			thread->unsatisfiedBlockIDAddress = target;
			block_data->lastTargetID = 0;
		}
		else
		{
			block_data->lastTargetID = blockIDit->second;
			block_data->targets->insert(std::make_pair(target, block_data->lastTargetID));
		}
	}

	//update state so drgat knows which member of unchained area executed an inactive block
	thread->lastBlock = block_data;

	#ifdef DEBUG_LOGGING
	dr_fprintf(thread->dbgfile,"mbr done targ->0x"ADDR_FMT"\n",target);
	dr_flush_file(thread->dbgfile);
	#endif
}

static void at_call(app_pc pc, app_pc target)
{
	BLOCKDATA *block_data = (BLOCKDATA *)dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);

	#ifdef DEBUG_LOGGING
	THREAD_STATE *dbgthread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);
	dr_fprintf(dbgthread->dbgfile, "at_call address 0x"ADDR_FMT" -> 0x"ADDR_FMT"\n",pc,target);
	dr_flush_file(dbgthread->dbgfile);
	#endif

	if (!block_data->unchained)
	{
		process_block_chain(pc, target, block_data);
		return;
	}

	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(dr_get_current_drcontext(), traceClientptr->tls_idx);

	++block_data->unchainedRepeats;
		
	//check to see if we arrived at the expected target
	if (block_data->blockID != thread->lastBlock_expected_targID)
	{
		//nope, add a new target to previous block so it can be added to graph
		thread->lastBlock->targets->insert(std::make_pair(block_data->appc, block_data->blockID));
		thread->lastBlock->lastTargetID = block_data->blockID;
	}

	//update state so next block can do the same check
	thread->lastBlock_expected_targID = block_data->lastTargetID;

	//check if the next target is the one block expects
	//if not then update the expected target and add it to target list
	//this avoids expensive set lookup every execution
	if (target != block_data->lastTarget)
	{
		BLOCKIDMAP::iterator blockIDit = thread->lastestBlockIDs.find(target);
		if (blockIDit != thread->lastestBlockIDs.end())
		{
			thread->unsatisfiedBlockIDs = true;
			thread->unsatisfiedBlockIDAddress = target;
			block_data->lastTargetID = 0;
		}
		else
		{
			block_data->lastTargetID = blockIDit->second;
			block_data->targets->insert(std::make_pair(target, block_data->lastTargetID));
		}
	}

	//update state so drgat knows which member of unchained area executed an inactive block
	thread->lastBlock = block_data;

	#ifdef DEBUG_LOGGING
	dr_fprintf(thread->dbgfile,"cabr done targ->0x"ADDR_FMT"\n",target);
	dr_flush_file(thread->dbgfile);
	#endif
}




DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
	dr_set_client_name("rgat instrumentation client", "https://github.com/ncatlin/rgat");
	
	drmgr_init();
	drwrap_init();

	instrumentationTable[OPTIMISED_TRACING][AT_CBR] = at_cbr;
	instrumentationTable[OPTIMISED_TRACING][AT_UBR] = at_ubr;
	instrumentationTable[OPTIMISED_TRACING][AT_MBR] = at_mbr;
	instrumentationTable[OPTIMISED_TRACING][AT_CALL] = at_call;
	//instrumentationTable[DEBUG_TRACING][AT_CBR] = at_cbr_dbg;
	//instrumentationTable[DEBUG_TRACING][AT_UBR] = at_ubr_dbg;
	//instrumentationTable[DEBUG_TRACING][AT_MBR] = at_mbr_dbg;
	//instrumentationTable[DEBUG_TRACING][AT_CALL] = at_call_dbg;

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

	module_data_t * mainmodule = dr_get_main_module();
	std::string appPath(mainmodule->full_path);
	#ifdef WINDOWS
		std::transform(appPath.begin(), appPath.end(), appPath.begin(), ::tolower);
	#endif
	

	traceClientptr = new TRACECLIENT(appPath);

	processArgs(ask_argv, ask_argc, traceClientptr);

	traceClientptr->allocMutx = dr_mutex_create();
	traceClientptr->latestAllocNode = (ALLOCLL *)dr_global_alloc(sizeof(ALLOCLL));
	traceClientptr->loggedMemoryLLStart = traceClientptr->latestAllocNode;

	traceClientptr->tls_idx = drmgr_register_tls_field();
	DR_ASSERT(traceClientptr->tls_idx != -1);
	traceClientptr->pid = dr_get_process_id();

#ifdef DEBUG_LOGGING
	char filebuf[MAX_PATH];
	dr_get_current_directory(filebuf, MAX_PATH);
	std::string threadDbgFile = filebuf+std::string("\\")+"processlog"+std::to_string(traceClientptr->pid)+".txt";
	dbgfile = dr_open_file(threadDbgFile.c_str(), DR_FILE_WRITE_OVERWRITE);

	dr_printf("[drgat]This is the debug drgat dll! Writing logs to %s with a *significant* performance impact\n",filebuf);
#endif
	dr_printf("[drgat]Starting instrumentation of %s (PID:%d)\n",appPath.c_str(),traceClientptr->pid);

	std::string pipeName = "\\\\.\\pipe\\BootstrapPipe";
	traceClientptr->modpipe = dr_open_file("\\\\.\\pipe\\BootstrapPipe", DR_FILE_WRITE_OVERWRITE);
	int failLimit = 3;
	while (traceClientptr->modpipe == INVALID_FILE)
	{
		if(!--failLimit)
			{
				dr_printf("[drgat]ERROR: Failed on opening pipe %s\n",pipeName.c_str());
				dr_close_file(traceClientptr->modpipe);
				dr_abort();
				return;
			}
		dr_sleep(600);
		traceClientptr->modpipe = dr_open_file(pipeName.c_str(), DR_FILE_WRITE_OVERWRITE);
	}


	//notify rgat to create threads for this process
	#ifdef X86_64
	dr_fprintf(traceClientptr->modpipe, "PID6%d", traceClientptr->pid);
	#else
	dr_fprintf(traceClientptr->modpipe, "PID3%d", traceClientptr->pid);
	#endif
	dr_sleep(600);

	process_id_t pidt = traceClientptr->pid;
	dr_close_file(traceClientptr->modpipe);
	traceClientptr->modpipe = INVALID_FILE;
	pipeName = "\\\\.\\pipe\\rioThreadMod";
	pipeName.append(std::to_string(traceClientptr->pid));

	traceClientptr->modpipe = dr_open_file(pipeName.c_str(), DR_FILE_WRITE_OVERWRITE);
	failLimit = 3;
	while (traceClientptr->modpipe == INVALID_FILE)
	{
		if(!--failLimit)
			{
				dr_printf("[drgat]ERROR: Failed on opening pipe %s\n",pipeName.c_str());
				dr_close_file(traceClientptr->modpipe);
				dr_abort();
				return;
			}
		dr_sleep(600);
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
		traceClientptr->includedModules.push_back(false);

	traceClientptr->modStarts.push_back(mainmodule->start);
	traceClientptr->modEnds.push_back(mainmodule->end);
	
	char b64path[STRINGBUFMAX];
	b64_string_arg(mainmodule->full_path,b64path);
	traceClientptr->write_sync_mod("mn@%s@%d@"ADDR_FMT"@"ADDR_FMT"@%x", b64path, 0,
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

	dr_free_module_data(mainmodule);

	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile, "dr_client_main completed\n");
	#endif
}


static void event_exit()
{
	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"event_exit called for process %d\n", dr_get_process_id());
	#endif
	//no real point doing this cleanup but i guess it's good practice
	//the logged allocation makes new BB allocation take a bit longer but probably not meaningfully.
	//try without and see if worth dropping
	dr_mutex_lock(traceClientptr->allocMutx);
	ALLOCLL *nextNode, *freeThisNode = (ALLOCLL *)traceClientptr->loggedMemoryLLStart->next;

	while (freeThisNode)
	{
		dr_global_free(freeThisNode->addr, freeThisNode->size);

		nextNode = (ALLOCLL *)freeThisNode->next;
		dr_global_free(freeThisNode,sizeof(ALLOCLL));
		freeThisNode = nextNode;
	}
	dr_mutex_unlock(traceClientptr->allocMutx);
	dr_mutex_destroy(traceClientptr->allocMutx);
	
	dr_global_free(traceClientptr->loggedMemoryLLStart,sizeof(ALLOCLL));

	std::vector<std::unordered_set<TARG_BLOCKID_PAIR>*>::iterator setAdIt = setAddrs.begin();
	for (; setAdIt!= setAddrs.end(); ++setAdIt)
		delete *setAdIt;

	dr_printf("[drgat]Ready to exit PID%d, waiting for writes to finish\n", dr_get_process_id());
	traceClientptr->write_sync_mod("[CLIENT]EVENT: Exit\n");

	dr_close_file(traceClientptr->modpipe);
	dr_close_file(traceClientptr->bbpipe);
	drmgr_unregister_tls_field(traceClientptr->tls_idx);
	delete traceClientptr;

	file_t closer = dr_open_file("\\\\.\\pipe\\riomodpipe", DR_FILE_WRITE_OVERWRITE);
	dr_fprintf(closer, "DIE");
	dr_flush_file(closer);
	dr_close_file(closer);

	drwrap_exit();
	drmgr_exit();

	dr_printf("[drgat]exit completed for process %d\n", dr_get_process_id());
}

static void event_thread_init(void *threadcontext)
{

	thread_id_t tid = dr_get_thread_id(threadcontext);
	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"Thread init called for thread %ld\n",tid);
	#endif

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

	THREAD_STATE *thread = new THREAD_STATE;
	thread->tid = tid;
	thread->f = threadoutpipe;
	thread->BBBuf = (char *)dr_thread_alloc(threadcontext, MAXBBBYTES);
	thread->tagIdx = 0;
	thread->cacheRepeats = 0;
	thread->loopEnd = 0;
	thread->lastTick = 0;
	thread->busyCounter = 0;
	thread->unchainedExist = false;
	thread->unsatisfiedBlockIDAddress = 0;
	thread->unsatisfiedBlockIDs = false;
	traceClientptr->threadList.push_back(thread);

#ifdef DEBUG_LOGGING
	char filebuf[MAX_PATH];
	dr_get_current_directory(filebuf, MAX_PATH);
	std::string threadDbgFile = filebuf+std::string("\\")+"\\threadlog"+std::to_string(traceClientptr->pid)+"-"
		+std::to_string(tid)+".txt";

	dr_printf("[drgat] New thread debug logging to %s\n", threadDbgFile.c_str());
	thread->dbgfile = dr_open_file(threadDbgFile.c_str(), DR_FILE_WRITE_OVERWRITE);
#endif
	drmgr_set_tls_field(threadcontext, traceClientptr->tls_idx, (THREAD_STATE *)thread);
	dr_flush_file(thread->f);
}

static void
event_thread_exit(void *threadcontext)
{
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(threadcontext, traceClientptr->tls_idx);

	thread_id_t tid = dr_get_thread_id(threadcontext);

	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"Thread exit called for thread %ld\n",tid);
	#endif

	printTagCache(thread);
	dr_close_file(thread->f);

	dr_sleep(200); //hopefully stop the memory free from screwing up pending BB writes
	dr_thread_free(threadcontext, thread->BBBuf, MAXBBBYTES);

	delete thread;
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
	thread_id_t tid = dr_get_thread_id(drcontext);
	uint threadMod = threadModArr[tid];
	THREAD_STATE *thread = (THREAD_STATE *)drmgr_get_tls_field(drcontext, traceClientptr->tls_idx);
	
	char *BBBuf = thread->BBBuf;

	instr_t *firstIns = instrlist_first_app(bb);
	app_pc firstiPC = dr_fragment_app_pc(tag);

	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"basic block head: "ADDR_FMT"\n",firstiPC);
	#endif

	bool isInstrumented = false;
	int mno = -1;
	uint bufIdx = 0;
	BLOCK_IDENTIFIER blockID = dr_get_random_value(INT_MAX);


	if (thread->unsatisfiedBlockIDs)
	{
		#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile,"Current unsatisfied block addr: "ADDR_FMT"\n",thread->unsatisfiedBlockIDAddress);
		#endif

		if (thread->unsatisfiedBlockIDAddress == firstiPC)
		{
			thread->lastBlock_expected_targID = blockID;
		}
		else
		{
			BLOCKIDMAP::iterator blockIDIt = thread->lastestBlockIDs.find(thread->unsatisfiedBlockIDAddress);
			if (blockIDIt != thread->lastestBlockIDs.end())
			{
				thread->lastBlock_expected_targID = blockIDIt->second;
			}
			else
			{
				thread->unsatisfiableBlockIDs[thread->unsatisfiedBlockIDAddress].push_back(thread->lastBlock);
				thread->lastBlock_expected_targID = 0;
			}
		}
		thread->unsatisfiedBlockIDAddress = 0;
		thread->unsatisfiedBlockIDs = false;
	}

	//sometimes a block requests the ID for a target BB but it doesn't appear for ages
	//this watches for it and sends rgat an update to it can draw the edge for it
	if (!thread->unsatisfiableBlockIDs.empty())	
	{
		std::unordered_map<app_pc, std::vector<BLOCKDATA *>>::iterator unsatIt = thread->unsatisfiableBlockIDs.find(firstiPC);
		if (unsatIt != thread->unsatisfiableBlockIDs.end())
		{
			std::vector<BLOCKDATA *>::iterator requestorIt = unsatIt->second.begin();
			for (; requestorIt != unsatIt->second.end(); ++requestorIt)
			{
				BLOCKDATA *requestor = *requestorIt;
				#ifdef DEBUG_LOGGING
				dr_fprintf(thread->dbgfile,"Unsatisfied block satisfied. Requestor:"ADDR_FMT",%lx Block:"ADDR_FMT",%lx@",requestor->appc, requestor->blockID,firstiPC,blockID);
				#endif
				dr_fprintf(thread->f, "SAT,"ADDR_FMT",%lx,"ADDR_FMT",%lx@",requestor->appc, requestor->blockID,firstiPC,blockID);
			}
			unsatIt = thread->unsatisfiableBlockIDs.erase(unsatIt);
		}
	}

	/*
	might do better with dr_lookup_module but it causes error :( 
						 + dr_free_module_data(exe_data);
	need to know where this code is, compare with module list
	*/
	//in same module as last BB looked at for this thread

	if (
		(firstiPC >= traceClientptr->modStarts.at(threadMod)) && (firstiPC <= traceClientptr->modEnds.at(threadMod))
		)
	{
		isInstrumented = traceClientptr->includedModules.at(threadMod);
		bufIdx = dr_snprintf(BBBuf, 512, "B@"ADDR_FMT"@%d@%d@%lx", firstiPC, threadMod, isInstrumented, blockID);
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
			bufIdx = dr_snprintf(BBBuf, 512, "B@"ADDR_FMT"@%d@%d@%lx", firstiPC, mno, isInstrumented, blockID);
			break;
		}

		//block not found in known module address allocations
		//this is near enough untested and i make no guarantees about its robustness
		//external libraries doing this will probably cause huge problems
		if (mno >= traceClientptr->numMods)
		{	
			
			//failed to find. self modifying code?
			printTagCache(thread);
			dr_mem_info_t meminfo;
			dr_query_memory_ex(firstiPC, &meminfo);
			if (meminfo.type == DR_MEMTYPE_DATA)
			{
				#ifdef DEBUG_LOGGING
				dr_fprintf(dbgfile,"\tFailed to find instruction "ADDR_FMT" in modules, (it's in data memory) falling back to module 0\n",firstiPC);
				#endif

				isInstrumented = true;
				mno = 0;
				bufIdx = dr_snprintf(BBBuf, 512, "B@"ADDR_FMT"@%d@1@%lx", firstiPC, mno, blockID);
			}
			else
			{
				#ifdef DEBUG_LOGGING
				dr_fprintf(dbgfile,"\tFailed to find instruction "ADDR_FMT" in modules, (it's not even in data memory!) falling back to module 0\n",firstiPC);
				#endif

				dr_printf("Searched %d mods but could not find address "ADDR_FMT" Code may have modified mapped image\n", mno, firstiPC);
				dr_printf("Base: "ADDR_FMT", size:%d, prot:%d type:%d\n", meminfo.base_pc, meminfo.size, meminfo.prot, meminfo.type);
				for (mno = 0; mno < traceClientptr->numMods; mno++)
				{
					dr_printf("Mod %d: "ADDR_FMT" -> "ADDR_FMT"\n", mno, 
						traceClientptr->modStarts.at(mno), 
						traceClientptr->modEnds.at(mno));
				}
				dr_printf("-------------\n");

				mno = 0;
				bufIdx = dr_snprintf(BBBuf, 512, "B@"ADDR_FMT"@%d@1@%lx", firstiPC, mno, blockID);
			}
		}
	}

	//no instrumentation done on external code, just report it exists and leave
	if(!isInstrumented) 
	{
		#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile,"\tblock external, done\n",firstiPC);
		#endif
		BBBuf[bufIdx] = 0;
		traceClientptr->write_sync_bb(BBBuf, bufIdx);	//this used to be needed... might not be now
		return DR_EMIT_DEFAULT;
	}

	//here we record all the opcodes in each instruction in the block and tell the visualiser about them
	unsigned instructionCount = 0;
	int lineIdx = 0, ilen, opcIdx;

	char *blockBuffer = thread->opBuffer;

	bool debugd = false;
	//opcodes for each instruction
	for (instr_t *ins = firstIns; ins != NULL; ins = instr_get_next(ins)) 
	{
		#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile,"\tinstrumented block instruction: "ADDR_FMT"\n",instr_get_app_pc(ins));
		#endif
		++instructionCount;
		lineIdx = dr_snprintf(blockBuffer + lineIdx, 1, "@");

		ilen = instr_length(drcontext, ins);
		for (opcIdx = 0; opcIdx < ilen; ++opcIdx)
			lineIdx += dr_snprintf(blockBuffer + lineIdx, MAXOPCODESLEN - lineIdx, "%02x", instr_get_raw_byte(ins, opcIdx));

		bufIdx += dr_snprintf(BBBuf + bufIdx, lineIdx, "%s", blockBuffer);
		DR_ASSERT_MSG(bufIdx < MAXBBBYTES, "[drgat]FATAL: BB string larger than MAXBBBYTES!");
	}

	

	BLOCKDATA *block_data = new BLOCKDATA;
	block_data->appc = firstiPC;
	block_data->blockID = blockID;
	BLOCK_IDENTIFIER_COUNT blockID_numins = ((BLOCK_IDENTIFIER_COUNT)((BLOCK_IDENTIFIER_COUNT)blockID<<32))+instructionCount;
	block_data->blockID_numins = blockID_numins;
	block_data->busyCounter = 0;
	block_data->unchained = false;
	block_data->unchainedRepeats = 0;
	block_data->targets = new std::unordered_set<TARG_BLOCKID_PAIR>;
	block_data->lastTarget = 0;
	block_data->lastTargetID = 0;
	block_data->dbgtid = tid;

	//todo: possible reader/writer locking. thread could be reading this asynchronously, not sure if a 32bit write is atomic
	#ifdef DEBUG_LOGGING
	dr_fprintf(dbgfile,"New block "ADDR_FMT", blockID: %lx\n",firstiPC, blockID);
	#endif
	thread->lastestBlockIDs[firstiPC] = blockID;

	BBBuf[bufIdx] = 0;
	traceClientptr->write_sync_bb(BBBuf, bufIdx); //send to basic block handler thread

	

	//finally we instrument the code to tell the trace handler thread each time the block executes
	instr_t *lasti = instrlist_last_app(bb);

	//debug mode or optimised
	char traceType = traceClientptr->processingMode;

	//add appropriate flow control processing code to the block terminator
	if (instr_is_cbr(lasti))
	{
		#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile,"\t\tinserted cbr instrumentation\n");
		#endif
		dr_insert_cbr_instrumentation_ex(drcontext, bb, lasti, instrumentationTable[traceType][AT_CBR], OPND_CREATE_INTPTR(block_data));
	}
	else 
	{
		//the other instruction instrumentation calls don't allow passing of a user argument
		//we have to transfer pointer to block metadata using a spill slot (2) instead
		dr_save_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_1);
		instr_t *in = INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(DR_REG_XAX), OPND_CREATE_INTPTR(block_data));
		instrlist_meta_preinsert(bb,lasti,in);
		dr_save_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_2);
		dr_restore_reg(drcontext, bb, lasti, DR_REG_XAX, SPILL_SLOT_1);

		if (instr_is_ubr(lasti))
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(dbgfile,"\t\tinserted ubr instrumentation\n");
			#endif
			dr_insert_ubr_instrumentation(drcontext, bb, lasti, instrumentationTable[traceType][AT_UBR]);
		}
		//order is important here as far calls are hit by this and instr_is_call
		else if(instr_is_mbr(lasti))
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(dbgfile,"\t\tinserted mbr instrumentation\n");
			#endif
			dr_insert_mbr_instrumentation(drcontext, bb, lasti, instrumentationTable[traceType][AT_MBR],SPILL_SLOT_1);
		}
                        
		else if (instr_is_call(lasti))
		{
			#ifdef DEBUG_LOGGING
			dr_fprintf(dbgfile,"\t\tinserted call instrumentation\n");
			#endif
			dr_insert_call_instrumentation(drcontext, bb, lasti, instrumentationTable[traceType][AT_CALL]);
		}

		else
			dr_printf("[drgat]PROBABLY FATAL: Unhandled block terminator. Memory corruption in target?\n");
	}

	#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile,"\tblock internal, done\n",firstiPC);
	#endif

	return DR_EMIT_DEFAULT;
}









