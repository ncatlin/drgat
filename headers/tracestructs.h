#pragma once
#include "stdafx.h"

#define MAXMODULES 255
#define MAXBBBYTES 1024*40
#define TAGCACHESIZE 5256
#define MAXOPCODESLEN 4096 
#define MAXMODMSGSIZE 1024

#define UNKNOWN 91999
#define STRINGBUFMAX 512

typedef struct {
	unsigned int modnum;
} callback_data;

#define NO_LOOP 0
#define COND_BASE_LOOP 1
#define UNCOND_BASE_LOOP 2

static int glob_pid;

typedef unsigned long BLOCK_IDENTIFIER;
typedef unsigned long long BLOCK_IDENTIFIER_COUNT;

typedef std::pair<app_pc, BLOCK_IDENTIFIER> TARG_BLOCKID_PAIR;
namespace std{
    template <>
    struct hash<TARG_BLOCKID_PAIR>
    {
        size_t operator()(TARG_BLOCKID_PAIR const & x) const
        {
            return (
                (51 + std::hash<app_pc>()(x.first)) * 51
                + std::hash<BLOCK_IDENTIFIER>()(x.second)
            );
        }
    };
}


//passed to each basic block clean all 
//so it can decide whether to print its address
struct BLOCKDATA {
	//constant block metadata
	uint numInstructions;
	app_pc appc; 
	app_pc fallthrough;
	BLOCK_IDENTIFIER_COUNT blockID_numins;
	BLOCK_IDENTIFIER blockID;

	//block metadata specific to each thread
	//calling dr with -thread_private is essential because of this
	app_pc lastTarget;
	BLOCK_IDENTIFIER lastTargetID;
	std::unordered_set<TARG_BLOCKID_PAIR> *targets;
	unsigned long busyCounter;
	bool unchained;
	unsigned long unchainedRepeats;

	thread_id_t dbgtid;

};
typedef std::unordered_map<app_pc, BLOCK_IDENTIFIER> BLOCKIDMAP;
typedef struct {
	file_t f; //trace pipe
	thread_id_t tid;
	
	#ifdef DEBUG_LOGGING
	file_t dbgfile;
	#endif

	app_pc sourceInstruction;
	app_pc tagCache[TAGCACHESIZE];
	app_pc targetAddresses[TAGCACHESIZE];
	BLOCK_IDENTIFIER_COUNT blockID_counts[TAGCACHESIZE];

	char *BBBuf; //per thread basic block buffer
	char stringbuf[STRINGBUFMAX]; //stores b64 encoded argument strings
	char opBuffer[MAXOPCODESLEN]; //stores opcodes during block creation
	char BXbuffer[TAGCACHESIZE]; //buffer unchaining data for output

	uint cacheRepeats;
	unsigned int tagIdx;
	unsigned int loopEnd;

	//result of last call to gettickcount
	DWORD64 lastTick;

	//block activity tracker
	unsigned long busyCounter;

	//any blocks currently unchained?
	bool unchainedExist;

	BLOCKDATA *lastBlock;
	//THREAD_BLOCK_DATA* lastBlock_tracking;

	BLOCK_IDENTIFIER lastBlock_expected_targID;
	

	std::vector<void *> unchainedBlocks;

	BLOCKIDMAP lastestBlockIDs;
	bool unsatisfiedBlockIDs;
	app_pc unsatisfiedBlockIDAddress;
	std::unordered_map<app_pc, std::vector<BLOCKDATA *>> unsatisfiableBlockIDs;

	
} THREAD_STATE;



