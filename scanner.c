#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "scanner.h"
#include "edr.h"
#include "logger.h"

typedef struct {
    unsigned long files;
    unsigned long alerts;
} X01ScanStats;

void X01ReportFile(const char *module, const char *action, const WCHAR *path,
                   const X01Verdict *v, BOOL print) {
    WIN32_FILE_ATTRIBUTE_DATA attr;
    X01Json j;
    char sha[65];
    char utf8[EDR_PATH * 3];
    BOOL exists;

    exists = GetFileAttributesExW(path, GetFileExInfoStandard, &attr) &&
             !(attr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);

    X01JsonInit(&j);
    X01JsonWStr(&j, "file.path", path);
    X01JsonWStr(&j, "file.name", X01BaseName(path));
    if (exists) {
        X01JsonNum(&j, "file.size", ((long long)attr.nFileSizeHigh << 32) | attr.nFileSizeLow);
        if (v->level > RISK_NONE && X01Sha256(path, sha)) {
            X01JsonStr(&j, "file.hash.sha256", sha);
        }
        if (v->level > RISK_NONE && X01IsPe(path)) {
            X01JsonBool(&j, "file.code_signature.valid", X01IsSigned(path));
        }
    }

    X01Emit(module, action, v, &j);

    if (print || v->level > RISK_NONE) {
        X01Utf8(path, utf8, sizeof(utf8));
        printf("[%-8s %3d] %-12s %s %s\n", X01RiskName(v->level), v->score, action, utf8, v->reasons);
    }
}

static void X01Walk(const WCHAR *dir, X01ScanStats *stats) {
    WIN32_FIND_DATAW data;
    WCHAR path[EDR_PATH];
    X01Verdict v;
    HANDLE find;

    if (_snwprintf(path, X01N(path), L"%ls\\*", dir) < 0) return;

    find = FindFirstFileExW(path, FindExInfoBasic, &data, FindExSearchNameMatch,
                            NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..")) continue;
        if (_snwprintf(path, X01N(path), L"%ls\\%ls", dir, data.cFileName) < 0) continue;

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                X01Walk(path, stats);
            }
            continue;
        }

        X01ScoreFile(path, &v);
        stats->files++;
        if (v.level > RISK_NONE) {
            X01ReportFile("scanner", "file_detected", path, &v, FALSE);
            stats->alerts += v.level >= RISK_MEDIUM;
        }
    } while (!X01Stop && FindNextFileW(find, &data));

    FindClose(find);
}

void X01ScanDirectory(const WCHAR *path) {
    X01ScanStats stats = { 0, 0 };
    ULONGLONG start = GetTickCount64();
    X01Json j;
    DWORD attr = GetFileAttributesW(path);

    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("Directory unavailable.\n");
        X01JsonInit(&j);
        X01JsonWStr(&j, "file.directory", path);
        X01Emit("scanner", "scan_error", NULL, &j);
        return;
    }

    printf("\n");
    X01Walk(path, &stats);

    X01JsonInit(&j);
    X01JsonWStr(&j, "file.directory", path);
    X01JsonNum(&j, "scan.files", (long long)stats.files);
    X01JsonNum(&j, "scan.alerts", (long long)stats.alerts);
    X01JsonNum(&j, "scan.duration_ms", (long long)(GetTickCount64() - start));
    X01Emit("scanner", "scan_completed", NULL, &j);

    printf("\nFiles analyzed: %lu  Alerts: %lu\n", stats.files, stats.alerts);
}
