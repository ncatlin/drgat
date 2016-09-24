// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//


#pragma once
       
#define WINDOWS
#define X86_32
//#if defined _WIN32

#define MAXSYMBOLS 10000

#include "dr_api.h"
#include <stddef.h> /* for offsetof */
#include <stdlib.h>
#include <drsyms.h>
#include <drmgr.h>
#include <drwrap.h>
#include <drutil.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <map>
#include <math.h>

#pragma comment (lib , "dynamorio.lib")
#pragma comment (lib , "drmgr.lib")
#pragma comment (lib , "drwrap.lib")
#pragma comment (lib , "drx.lib")
#pragma comment (lib , "drsyms.lib")
#pragma comment (lib , "drutil.lib")

