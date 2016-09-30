#include "headers\stdafx.h"
#include "headers\utilities.h"
#include "headers\b64encode.h"

//doing this for lots of big dll's is a lot of work
bool symCB(const char *name, size_t modoffs, callback_data *cbd)
{
	//char b64sym[STRINGBUFMAX];
	//b64_string_arg(name,b64sym); //@'s in symbols will wreck parsing
	traceClientptr->write_sync_mod("s!@%d@%x@%s", cbd->modnum, modoffs, name);
	return TRUE;
}

void start_sym_processing(int modindex, char *path)
{
	callback_data *cbd = (callback_data *)logged_memalloc(sizeof(callback_data));
	cbd->modnum = modindex;
	drsym_init(NULL);
	drsym_error_t r = drsym_enumerate_symbols(path, (drsym_enumerate_cb)symCB, (void *)cbd, 0);
	drsym_exit();
}


//take widestring arg
//turns it into a base64 encoded char string in buf
void b64_wstring_arg(const wchar_t * arg, char *buf)
{
	int len = dr_snprintf(buf, STRINGBUFMAX, "%S", arg); 
	std::string b64arg = base64_encode((const unsigned char *)buf, len);
	dr_snprintf(buf, STRINGBUFMAX, "%s", b64arg.c_str());
}

void b64_string_arg(const char * arg, char *buf)
{
	int len = dr_snprintf(buf, STRINGBUFMAX, "%s", arg); 
	std::string b64arg = base64_encode((const unsigned char *)buf, len);
	dr_snprintf(buf, STRINGBUFMAX, "%s", b64arg.c_str());
}

void b64_char_arg(char arg, char *buf)
{
	dr_snprintf(buf, 1, "%c", arg); 
	std::string b64arg = base64_encode((const unsigned char *)buf, 1);
	dr_snprintf(buf, STRINGBUFMAX, "%s", b64arg.c_str());
}

//adds a linked list entry containing details to free this allocation
//need to do this if we dont free in the same function we alloc
//can free everything in list on exit
//TODO: see fuzzi for freeing, need to rejig linked list
void *logged_memalloc(size_t size)
{
	void *bufAddr = dr_global_alloc(size);
	DR_ASSERT_MSG(bufAddr, "Alloc Failed!");

	ALLOCLL *thisAlloc = (ALLOCLL *)dr_global_alloc(sizeof(ALLOCLL));
	thisAlloc->addr = bufAddr;
	thisAlloc->size = size;
	
	dr_mutex_lock(traceClientptr->allocMutx);
	traceClientptr->latestAllocNode->next = thisAlloc;
	traceClientptr->latestAllocNode = thisAlloc;
	dr_mutex_unlock(traceClientptr->allocMutx);
	return bufAddr;

}

//http://stackoverflow.com/questions/5820810/case-insensitive-string-comp-in-c
//this client might need unicode...
int strcicmp(char const *a, char const *b)
{
	for (;; a++, b++) {
		int d = tolower(*a) - tolower(*b);
		if (d != 0 || !*a)
			return d;
	}
}

void printTagCache(THREAD_STATE *thread)
{
	size_t byteswritten = 0;
	int cacheEnd;
	//first print out any complete loops
	if (thread->cacheRepeats)
	{
		cacheEnd = thread->loopEnd;

		byteswritten += dr_fprintf(thread->f, "RS%d@", thread->cacheRepeats);
		for (int i = 0; i < cacheEnd; ++i)
		{
			//dr_printf("LOOP CACHEDUMP %d its of %d blocks block:%lx targ:%lx\n",
			//	thread->cacheRepeats,cacheEnd,thread->tagCache[i],thread->targetAddresses[i]);

			byteswritten += dr_fprintf(thread->f, "j%x,%x,%llx@",
				thread->tagCache[i],thread->targetAddresses[i], thread->blockID_counts[i]);
		}
		byteswritten += dr_fprintf(thread->f, "RE@");
	}
	
	cacheEnd = thread->tagIdx;
	for (int i = 0; i < cacheEnd; ++i)
	{
		//dr_printf("STD CACHEDUMP of %d blocks block:%lx targ:%lx\n",
		//		cacheEnd,thread->tagCache[i],thread->targetAddresses[i]);
		byteswritten += dr_fprintf(thread->f, "j%x,%x,%llx@",	thread->tagCache[i],thread->targetAddresses[i], thread->blockID_counts[i]);
	}

	//pipe closed, rgat probably closed too
	if ((int)byteswritten < 0)
	{
		dr_sleep(1500);
		dr_exit_process(-1);
	}
	
	dr_flush_file(thread->f);
	thread->tagIdx = 0;
	thread->loopEnd = 0;
	thread->cacheRepeats = 0;
}