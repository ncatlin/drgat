#pragma once
#include "stdafx.h"
#include <windows.h>
#include "tracestructs.h"

void wrap_advapi32(module_handle_t handle);
void wrapRegQValExA(void *wrapcxt, OUT void **user_data);
void wrapRegOpenKeyExA(void *wrapcxt, OUT void **user_data);