#ifndef SIGN_H
#define SIGN_H

#include <windows.h>
#include "edr.h"
#include "logger.h"

BOOL X01SignInit(void);
void X01SignClose(void);
void X01SignCheck(const WCHAR *path, X01Sign *s);
BOOL X01SignTrusted(const X01Sign *s);
BOOL X01SignMicrosoft(const X01Sign *s);
void X01SignJson(X01Json *j, const char *prefix, const X01Sign *s);

#endif
