#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "monitor.h"
#include "scanner.h"
#include "edr.h"
#include "logger.h"

static const char *X01ActionName(DWORD action) {
    switch (action) {
        case FILE_ACTION_ADDED: return "file_created";
        case FILE_ACTION_REMOVED: return "file_deleted";
        case FILE_ACTION_MODIFIED: return "file_modified";
        case FILE_ACTION_RENAMED_OLD_NAME: return "file_renamed_from";
        case FILE_ACTION_RENAMED_NEW_NAME: return "file_renamed_to";
        default: return "file_unknown";
    }
}

static void X01HandleChange(const WCHAR *root, const FILE_NOTIFY_INFORMATION *info) {
    WCHAR path[EDR_PATH];
    X01Verdict v;
    int chars = (int)(info->FileNameLength / sizeof(WCHAR));

    if (_snwprintf(path, X01N(path), L"%ls\\%.*ls", root, chars, info->FileName) < 0) return;

    X01ScoreFile(path, &v);
    X01ReportFile("monitor", X01ActionName(info->Action), path, &v, TRUE);
}

void X01MonitorRun(const WCHAR *path) {
    static DWORD buffer[16384];
    OVERLAPPED ov;
    HANDLE dir;
    DWORD bytes;
    X01Json j;
    char utf8[EDR_PATH * 3];

    dir = CreateFileW(path, FILE_LIST_DIRECTORY,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);

    X01JsonInit(&j);
    X01JsonWStr(&j, "file.directory", path);

    if (dir == INVALID_HANDLE_VALUE) {
        printf("Unable to monitor directory.\n");
        X01Emit("monitor", "monitor_error", NULL, &j);
        return;
    }

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    X01Utf8(path, utf8, sizeof(utf8));
    printf("\nMonitoring %s. Ctrl+C to stop.\n", utf8);
    X01Emit("monitor", "monitor_started", NULL, &j);

    while (!X01Stop) {
        ResetEvent(ov.hEvent);
        if (!ReadDirectoryChangesW(dir, buffer, sizeof(buffer), TRUE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                   FILE_NOTIFY_CHANGE_SECURITY,
                                   NULL, &ov, NULL)) {
            X01Emit("monitor", "monitor_error", NULL, &j);
            break;
        }

        while (!X01Stop && WaitForSingleObject(ov.hEvent, 250) == WAIT_TIMEOUT) {}

        if (X01Stop) {
            CancelIoEx(dir, &ov);
            GetOverlappedResult(dir, &ov, &bytes, TRUE);
            break;
        }

        if (!GetOverlappedResult(dir, &ov, &bytes, FALSE)) {
            X01Emit("monitor", "monitor_error", NULL, &j);
            break;
        }

        if (bytes == 0) {
            X01Emit("monitor", "monitor_overflow", NULL, &j);
            continue;
        }

        {
            const BYTE *cursor = (const BYTE *)buffer;
            for (;;) {
                const FILE_NOTIFY_INFORMATION *info = (const FILE_NOTIFY_INFORMATION *)cursor;
                X01HandleChange(path, info);
                if (!info->NextEntryOffset) break;
                cursor += info->NextEntryOffset;
            }
        }
    }

    X01Emit("monitor", "monitor_stopped", NULL, &j);
    CloseHandle(ov.hEvent);
    CloseHandle(dir);
}
