#ifndef VT_H
#define VT_H

#include <windows.h>
#include "edr.h"
#include "logger.h"

typedef enum {
    X01VT_DISABLED = 0,
    X01VT_FOUND,
    X01VT_UNKNOWN,
    X01VT_RATE_LIMITED,
    X01VT_ERROR
} X01VtStatus;

typedef struct {
    X01VtStatus status;
    int malicious;
    int suspicious;
    int harmless;
    int undetected;
} X01VtResult;

BOOL X01VtInit(const char *key, int per_minute);
void X01VtClose(void);
BOOL X01VtEnabled(void);
void X01VtLookup(const char *sha256, X01VtResult *r);
void X01VtApply(const char *sha256, const char *prefix, X01Verdict *v, X01Json *j, X01VtResult *r);

#endif
