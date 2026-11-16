#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "logger.h"

#define X01LOG_MAX (50L * 1024 * 1024)

static FILE *X01File;
static char X01Path[MAX_PATH];
static char X01Host[256];
static CRITICAL_SECTION X01Lock;
static SOCKET X01Sock = INVALID_SOCKET;
static struct sockaddr_storage X01Addr;
static int X01AddrLen;
static unsigned long long X01Seq;

static void X01Put(X01Json *j, const char *s, BOOL esc) {
    for (; *s && j->len + 7 < sizeof(j->data); ++s) {
        unsigned char c = (unsigned char)*s;
        if (esc && (c == '"' || c == '\\')) {
            j->data[j->len++] = '\\';
            j->data[j->len++] = (char)c;
        } else if (esc && c < 0x20) {
            j->len += (size_t)sprintf(j->data + j->len, "\\u%04x", c);
        } else {
            j->data[j->len++] = (char)c;
        }
    }
    j->data[j->len] = 0;
}

static void X01Key(X01Json *j, const char *key) {
    X01Put(j, j->len && j->data[j->len - 1] != '{' ? ",\"" : "\"", FALSE);
    X01Put(j, key, TRUE);
    X01Put(j, "\":", FALSE);
}

void X01JsonInit(X01Json *j) {
    j->len = 0;
    j->data[0] = 0;
}

void X01JsonStr(X01Json *j, const char *key, const char *value) {
    X01Key(j, key);
    X01Put(j, "\"", FALSE);
    X01Put(j, value ? value : "", TRUE);
    X01Put(j, "\"", FALSE);
}

void X01JsonWStr(X01Json *j, const char *key, const WCHAR *value) {
    char utf8[EDR_CMD * 3];
    X01Utf8(value, utf8, sizeof(utf8));
    X01JsonStr(j, key, utf8);
}

void X01JsonNum(X01Json *j, const char *key, long long value) {
    char num[32];
    snprintf(num, sizeof(num), "%lld", value);
    X01Key(j, key);
    X01Put(j, num, FALSE);
}

void X01JsonBool(X01Json *j, const char *key, BOOL value) {
    X01Key(j, key);
    X01Put(j, value ? "true" : "false", FALSE);
}

static void X01SiemOpen(const char *target) {
    char host[256];
    const char *colon = strrchr(target, ':');
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    WSADATA wsa;
    size_t len;

    if (!colon || (len = (size_t)(colon - target)) == 0 || len >= sizeof(host)) return;
    memcpy(host, target, len);
    host[len] = 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa)) return;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (!getaddrinfo(host, colon + 1, &hints, &res) && res) {
        X01Sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        memcpy(&X01Addr, res->ai_addr, res->ai_addrlen);
        X01AddrLen = (int)res->ai_addrlen;
        freeaddrinfo(res);
    }

    if (X01Sock == INVALID_SOCKET) {
        WSACleanup();
    }
}

BOOL X01LogInit(const char *path, const char *siem) {
    DWORD n = sizeof(X01Host);

    InitializeCriticalSection(&X01Lock);
    if (!GetComputerNameA(X01Host, &n)) {
        strcpy(X01Host, "unknown");
    }
    snprintf(X01Path, sizeof(X01Path), "%s", path);
    X01File = fopen(X01Path, "ab");

    if (siem) {
        X01SiemOpen(siem);
        if (X01Sock == INVALID_SOCKET) {
            fprintf(stderr, "SIEM target unavailable: %s\n", siem);
        }
    }

    return X01File != NULL;
}

void X01LogClose(void) {
    EnterCriticalSection(&X01Lock);
    if (X01File) {
        fclose(X01File);
        X01File = NULL;
    }
    if (X01Sock != INVALID_SOCKET) {
        closesocket(X01Sock);
        X01Sock = INVALID_SOCKET;
        WSACleanup();
    }
    LeaveCriticalSection(&X01Lock);
    DeleteCriticalSection(&X01Lock);
}

static void X01Rotate(void) {
    char old[MAX_PATH + 4];

    if (!X01File || ftell(X01File) < X01LOG_MAX) return;
    fclose(X01File);
    snprintf(old, sizeof(old), "%s.1", X01Path);
    MoveFileExA(X01Path, old, MOVEFILE_REPLACE_EXISTING);
    X01File = fopen(X01Path, "ab");
}

void X01Emit(const char *module, const char *action, const X01Verdict *v, const X01Json *fields) {
    static X01Json line;
    SYSTEMTIME st;
    char ts[64];

    GetSystemTime(&st);
    snprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    EnterCriticalSection(&X01Lock);

    X01JsonInit(&line);
    X01Put(&line, "{", FALSE);
    X01JsonStr(&line, "@timestamp", ts);
    X01JsonNum(&line, "event.sequence", (long long)++X01Seq);
    X01JsonStr(&line, "host.name", X01Host);
    X01JsonStr(&line, "agent.type", "MiniEDR");
    X01JsonStr(&line, "agent.version", EDR_VERSION);
    X01JsonStr(&line, "event.module", module);
    X01JsonStr(&line, "event.action", action);
    X01JsonStr(&line, "event.kind", v && v->level >= RISK_MEDIUM ? "alert" : "event");

    if (v) {
        X01JsonNum(&line, "event.risk_score", v->score);
        X01JsonNum(&line, "event.severity", v->level);
        X01JsonStr(&line, "risk.level", X01RiskName(v->level));
        if (v->reasons[0]) {
            X01JsonStr(&line, "rule.name", v->reasons);
        }
    }

    if (fields && fields->len) {
        X01Put(&line, ",", FALSE);
        X01Put(&line, fields->data, FALSE);
    }

    if (line.len + 2 >= sizeof(line.data)) {
        line.len = sizeof(line.data) - 3;
    }
    line.data[line.len++] = '}';
    line.data[line.len++] = '\n';
    line.data[line.len] = 0;

    X01Rotate();
    if (X01File) {
        fwrite(line.data, 1, line.len, X01File);
        fflush(X01File);
    }
    if (X01Sock != INVALID_SOCKET) {
        sendto(X01Sock, line.data, (int)line.len - 1, 0, (struct sockaddr *)&X01Addr, X01AddrLen);
    }

    LeaveCriticalSection(&X01Lock);
}
