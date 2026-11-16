#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "process.h"
#include "edr.h"
#include "logger.h"

typedef struct {
    DWORD pid;
    DWORD ppid;
    WCHAR name[MAX_PATH];
} X01Proc;

typedef struct {
    X01Proc *items;
    DWORD count;
    DWORD cap;
} X01ProcList;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} X01UString;

typedef LONG (NTAPI *X01NtQueryFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static int X01ProcCmp(const void *a, const void *b) {
    DWORD x = ((const X01Proc *)a)->pid;
    DWORD y = ((const X01Proc *)b)->pid;
    return (x > y) - (x < y);
}

static BOOL X01Snapshot(X01ProcList *list) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;

    list->count = 0;
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (list->count == list->cap) {
                DWORD cap = list->cap ? list->cap * 2 : 512;
                X01Proc *grown = realloc(list->items, cap * sizeof(X01Proc));
                if (!grown) break;
                list->items = grown;
                list->cap = cap;
            }
            list->items[list->count].pid = entry.th32ProcessID;
            list->items[list->count].ppid = entry.th32ParentProcessID;
            wcscpy(list->items[list->count].name, entry.szExeFile);
            list->count++;
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    qsort(list->items, list->count, sizeof(X01Proc), X01ProcCmp);
    return list->count > 0;
}

static const X01Proc *X01Find(const X01ProcList *list, DWORD pid) {
    X01Proc key;
    key.pid = pid;
    return list->count ? bsearch(&key, list->items, list->count, sizeof(X01Proc), X01ProcCmp) : NULL;
}

static void X01ProcInfo(DWORD pid, WCHAR *image, DWORD size, WCHAR *cmd, DWORD cmdsize) {
    static X01NtQueryFn query;
    static BYTE buffer[sizeof(X01UString) + EDR_CMD * sizeof(WCHAR)];
    HANDLE h;
    DWORD n = size;
    ULONG len = 0;

    image[0] = 0;
    cmd[0] = 0;

    if (!query) {
        query = (X01NtQueryFn)(void (*)(void))GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                             "NtQueryInformationProcess");
    }

    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;

    if (!QueryFullProcessImageNameW(h, 0, image, &n)) {
        image[0] = 0;
    }

    if (query && query(h, 60, buffer, sizeof(buffer), &len) >= 0) {
        X01UString *u = (X01UString *)buffer;
        size_t chars = u->Length / sizeof(WCHAR);
        if (chars >= cmdsize) chars = cmdsize - 1;
        if (u->Buffer) wmemcpy(cmd, u->Buffer, chars);
        cmd[chars] = 0;
    }

    CloseHandle(h);
}

static BOOL X01Analyze(const X01Proc *p, const X01ProcList *all, const char *action) {
    static WCHAR image[EDR_PATH];
    static WCHAR cmd[EDR_CMD];
    const X01Proc *parent = X01Find(all, p->ppid);
    X01Verdict v;
    X01Json j;
    char sha[65] = "";
    char name[MAX_PATH * 3];

    X01ProcInfo(p->pid, image, X01N(image), cmd, X01N(cmd));
    X01ScoreProcess(p->name, image, parent ? parent->name : NULL, cmd, &v);

    X01JsonInit(&j);
    X01JsonNum(&j, "process.pid", p->pid);
    X01JsonWStr(&j, "process.name", p->name);
    X01JsonWStr(&j, "process.executable", image);
    X01JsonWStr(&j, "process.command_line", cmd);
    X01JsonNum(&j, "process.parent.pid", p->ppid);
    X01JsonWStr(&j, "process.parent.name", parent ? parent->name : L"");

    if (v.score > 0 && image[0]) {
        BOOL sign = X01InWinDir(image) || X01IsSigned(image);
        if (!sign) {
            X01VerdictAdd(&v, 10, "unsigned");
            X01VerdictFinish(&v);
        }
        if (X01Sha256(image, sha)) {
            X01JsonStr(&j, "process.hash.sha256", sha);
        }
        X01JsonBool(&j, "process.code_signature.trusted", sign);
    }

    X01Emit("process", action, &v, &j);

    if (v.level > RISK_NONE) {
        X01Utf8(p->name, name, sizeof(name));
        printf("[%-8s %3d] PID=%-6lu %-28s %s\n", X01RiskName(v.level), v.score,
               (unsigned long)p->pid, name, v.reasons);
    }

    return v.level >= RISK_MEDIUM;
}

void X01ProcessScan(void) {
    X01ProcList list = { 0 };
    X01Json j;
    DWORD i;
    unsigned int alerts = 0;

    if (!X01Snapshot(&list)) {
        printf("Process snapshot error.\n");
        X01Emit("process", "process_scan_error", NULL, NULL);
        free(list.items);
        return;
    }

    printf("\n%-14s %-10s %-28s %s\n", "RISK", "PID", "PROCESS", "REASONS");
    for (i = 0; i < list.count && !X01Stop; ++i) {
        alerts += X01Analyze(&list.items[i], &list, "process_inventory");
    }

    X01JsonInit(&j);
    X01JsonNum(&j, "scan.processes", list.count);
    X01JsonNum(&j, "scan.alerts", alerts);
    X01Emit("process", "process_scan_completed", NULL, &j);

    printf("\nProcesses analyzed: %lu  Alerts: %u\n", (unsigned long)list.count, alerts);
    free(list.items);
}

void X01ProcessWatch(void) {
    X01ProcList prev = { 0 };
    X01ProcList cur = { 0 };
    X01ProcList swap;
    X01Json j;
    DWORD i;

    if (!X01Snapshot(&prev)) {
        printf("Process snapshot error.\n");
        free(prev.items);
        return;
    }

    printf("\nProcess watch active. Ctrl+C to stop.\n");
    X01Emit("process", "process_watch_started", NULL, NULL);

    while (!X01Stop) {
        Sleep(250);
        if (!X01Snapshot(&cur)) continue;

        for (i = 0; i < cur.count; ++i) {
            if (!X01Find(&prev, cur.items[i].pid)) {
                X01Analyze(&cur.items[i], &cur, "process_started");
            }
        }

        for (i = 0; i < prev.count; ++i) {
            if (!X01Find(&cur, prev.items[i].pid)) {
                X01JsonInit(&j);
                X01JsonNum(&j, "process.pid", prev.items[i].pid);
                X01JsonWStr(&j, "process.name", prev.items[i].name);
                X01Emit("process", "process_stopped", NULL, &j);
            }
        }

        swap = prev;
        prev = cur;
        cur = swap;
    }

    X01Emit("process", "process_watch_stopped", NULL, NULL);
    free(prev.items);
    free(cur.items);
}
