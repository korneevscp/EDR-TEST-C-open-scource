#ifndef EDR_H
#define EDR_H

#include <windows.h>

#define EDR_VERSION "3.0.0"
#define EDR_PATH 1024
#define EDR_CMD 4096
#define X01N(a) (sizeof(a) / sizeof((a)[0]))

typedef enum {
    RISK_NONE = 0,
    RISK_LOW = 1,
    RISK_MEDIUM = 2,
    RISK_HIGH = 3,
    RISK_CRITICAL = 4
} RiskLevel;

typedef struct {
    RiskLevel level;
    int score;
    char reasons[256];
} X01Verdict;

extern volatile LONG X01Stop;

BOOL X01EdrInit(void);
void X01EdrClose(void);
const char *X01RiskName(RiskLevel level);
void X01Utf8(const WCHAR *src, char *dst, int size);
const WCHAR *X01BaseName(const WCHAR *path);
BOOL X01Sha256(const WCHAR *path, char out[65]);
BOOL X01IsSigned(const WCHAR *path);
BOOL X01IsPe(const WCHAR *path);
BOOL X01InWinDir(const WCHAR *path);
void X01VerdictAdd(X01Verdict *v, int points, const char *reason);
void X01VerdictFinish(X01Verdict *v);
void X01ScoreProcess(const WCHAR *name, const WCHAR *image, const WCHAR *parent,
                     const WCHAR *cmd, X01Verdict *v);
void X01ScoreFile(const WCHAR *path, X01Verdict *v);

#endif
