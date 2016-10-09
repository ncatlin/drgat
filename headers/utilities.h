#pragma once
#include "traceclient.h"

void *logged_memalloc(size_t size);
int strcicmp(char const *a, char const *b);
void printTagCache(THREAD_STATE *thread);
void b64_wstring_arg(const wchar_t * arg, char *buf);
void b64_string_arg(const char * arg, char *buf);
void b64_char_arg(char arg, char *buf);

void start_sym_processing(int modindex, char *path);
extern TRACECLIENT *traceClientptr;

extern unsigned long *threadmemcount;