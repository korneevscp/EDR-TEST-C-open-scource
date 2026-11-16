#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vt.h"

#define X01VT_CACHE 4096
#define X01VT_BODY (1024 * 1024)

typedef struct {
    char sha[65];
    X01VtResult result;
} X01VtEntry;

static HINTERNET X01Session;
static HINTERNET X01Connect;
static WCHAR X01KeyHeader[160];
static CRITICAL_SECTION X01VtLock;
static X01VtEntry *X01Cache;
static unsigned int X01CacheNext;
static int X01PerMinute;
static ULONGLONG X01WindowStart;
static int X01WindowUsed;
static char *X01Body;

static const char *X01StatusName(X01VtStatus s) {
    static const char *names[] = { "disabled", "found", "unknown", "rate_limited", "error" };
    return names[s <= X01VT_ERROR ? s : X01VT_ERROR];
}

BOOL X01VtInit(const char *key, int per_minute) {
    WCHAR wkey[100];

    if (!key || !key[0] || strlen(key) >= X01N(wkey)) return FALSE;
    if (!MultiByteToWideChar(CP_UTF8, 0, key, -1, wkey, X01N(wkey))) return FALSE;

    X01Cache = calloc(X01VT_CACHE, sizeof(X01VtEntry));
    X01Body = malloc(X01VT_BODY + 1);
    if (!X01Cache || !X01Body) goto fail;

    X01Session = WinHttpOpen(L"MiniEDR/" EDR_VERSION, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!X01Session) goto fail;
    WinHttpSetTimeouts(X01Session, 5000, 5000, 5000, 10000);

    X01Connect = WinHttpConnect(X01Session, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!X01Connect) goto fail;

    _snwprintf(X01KeyHeader, X01N(X01KeyHeader), L"x-apikey: %ls", wkey);
    SecureZeroMemory(wkey, sizeof(wkey));
    X01PerMinute = per_minute > 0 ? per_minute : 4;
    InitializeCriticalSection(&X01VtLock);
    return TRUE;

fail:
    X01VtClose();
    return FALSE;
}

void X01VtClose(void) {
    if (X01Connect) WinHttpCloseHandle(X01Connect);
    if (X01Session) {
        WinHttpCloseHandle(X01Session);
        DeleteCriticalSection(&X01VtLock);
    }
    SecureZeroMemory(X01KeyHeader, sizeof(X01KeyHeader));
    free(X01Cache);
    free(X01Body);
    X01Connect = X01Session = NULL;
    X01Cache = NULL;
    X01Body = NULL;
}

BOOL X01VtEnabled(void) {
    return X01Connect != NULL;
}

static int X01JsonInt(const char *scope, const char *key) {
    char pattern[48];
    const char *p;

    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    p = strstr(scope, pattern);
    return p ? atoi(p + strlen(pattern)) : 0;
}

static BOOL X01Budget(void) {
    ULONGLONG now = GetTickCount64();

    if (now - X01WindowStart >= 60000) {
        X01WindowStart = now;
        X01WindowUsed = 0;
    }
    if (X01WindowUsed >= X01PerMinute) return FALSE;
    X01WindowUsed++;
    return TRUE;
}

static void X01Query(const char *sha, X01VtResult *r) {
    HINTERNET req;
    WCHAR path[96];
    DWORD code = 0;
    DWORD size = sizeof(code);
    DWORD got;
    size_t total = 0;
    const char *stats;

    r->status = X01VT_ERROR;
    _snwprintf(path, X01N(path), L"/api/v3/files/%hs", sha);

    req = WinHttpOpenRequest(X01Connect, L"GET", path, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) return;

    if (WinHttpSendRequest(req, X01KeyHeader, (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL) &&
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &size, WINHTTP_NO_HEADER_INDEX)) {
        if (code == 404) {
            r->status = X01VT_UNKNOWN;
        } else if (code == 429) {
            r->status = X01VT_RATE_LIMITED;
        } else if (code == 200) {
            while (total < X01VT_BODY &&
                   WinHttpReadData(req, X01Body + total, (DWORD)(X01VT_BODY - total), &got) && got) {
                total += got;
            }
            X01Body[total] = 0;
            stats = strstr(X01Body, "\"last_analysis_stats\"");
            if (stats) {
                r->status = X01VT_FOUND;
                r->malicious = X01JsonInt(stats, "malicious");
                r->suspicious = X01JsonInt(stats, "suspicious");
                r->harmless = X01JsonInt(stats, "harmless");
                r->undetected = X01JsonInt(stats, "undetected");
            }
        }
    }

    WinHttpCloseHandle(req);
}

void X01VtLookup(const char *sha256, X01VtResult *r) {
    unsigned int i;

    memset(r, 0, sizeof(*r));
    if (!X01VtEnabled() || !sha256 || strlen(sha256) != 64) return;

    EnterCriticalSection(&X01VtLock);

    for (i = 0; i < X01VT_CACHE; ++i) {
        if (X01Cache[i].sha[0] && !strcmp(X01Cache[i].sha, sha256)) {
            *r = X01Cache[i].result;
            LeaveCriticalSection(&X01VtLock);
            return;
        }
    }

    if (!X01Budget()) {
        r->status = X01VT_RATE_LIMITED;
    } else {
        X01Query(sha256, r);
        if (r->status == X01VT_FOUND || r->status == X01VT_UNKNOWN) {
            X01VtEntry *e = &X01Cache[X01CacheNext++ % X01VT_CACHE];
            memcpy(e->sha, sha256, 65);
            e->result = *r;
        }
    }

    LeaveCriticalSection(&X01VtLock);
}

void X01VtApply(const char *sha256, const char *prefix, X01Verdict *v, X01Json *j) {
    X01VtResult r;
    char key[64];
    char link[128];

    if (!X01VtEnabled()) return;
    X01VtLookup(sha256, &r);

    snprintf(key, sizeof(key), "%s.virustotal.status", prefix);
    X01JsonStr(j, key, X01StatusName(r.status));

    if (r.status != X01VT_FOUND) return;

    snprintf(key, sizeof(key), "%s.virustotal.malicious", prefix);
    X01JsonNum(j, key, r.malicious);
    snprintf(key, sizeof(key), "%s.virustotal.suspicious", prefix);
    X01JsonNum(j, key, r.suspicious);
    snprintf(key, sizeof(key), "%s.virustotal.harmless", prefix);
    X01JsonNum(j, key, r.harmless);
    snprintf(key, sizeof(key), "%s.virustotal.undetected", prefix);
    X01JsonNum(j, key, r.undetected);
    snprintf(key, sizeof(key), "%s.virustotal.link", prefix);
    snprintf(link, sizeof(link), "https://www.virustotal.com/gui/file/%s", sha256);
    X01JsonStr(j, key, link);

    if (r.malicious >= 5) {
        X01VerdictAdd(v, 80, "virustotal_malicious");
    } else if (r.malicious > 0 || r.suspicious >= 3) {
        X01VerdictAdd(v, 40, "virustotal_detected");
    }
    X01VerdictFinish(v);
}
