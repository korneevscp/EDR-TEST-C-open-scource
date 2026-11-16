#ifndef LOGGER_H
#define LOGGER_H

#include <windows.h>
#include "edr.h"

typedef struct {
    char data[16384];
    size_t len;
} X01Json;

BOOL X01LogInit(const char *path, const char *siem);
void X01LogClose(void);
void X01JsonInit(X01Json *j);
void X01JsonStr(X01Json *j, const char *key, const char *value);
void X01JsonWStr(X01Json *j, const char *key, const WCHAR *value);
void X01JsonNum(X01Json *j, const char *key, long long value);
void X01JsonBool(X01Json *j, const char *key, BOOL value);
void X01Emit(const char *module, const char *action, const X01Verdict *v, const X01Json *fields);

#endif
