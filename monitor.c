#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "monitor.h"
#include "edr.h"
#include "logger.h"

void monitor_run(const char *path) {
    HANDLE directory;
    BYTE buffer[65536];
    DWORD bytes_returned;
    char message[1024];

    directory = CreateFileA(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (directory == INVALID_HANDLE_VALUE) {
        printf("Unable to monitor directory: %s\n", path);
        logger_event("ERROR", "MONITOR", "CreateFile directory failed");
        return;
    }

    printf("\nMonitoring: %s\n", path);
    printf("Press Ctrl+C to stop.\n\n");

    for (;;) {
        DWORD offset = 0;

        if (!ReadDirectoryChangesW(
                directory,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SIZE,
                &bytes_returned,
                NULL,
                NULL)) {
            logger_event("ERROR", "MONITOR",
                         "ReadDirectoryChangesW failed");
            break;
        }

        while (offset < bytes_returned) {
            FILE_NOTIFY_INFORMATION *info;
            char name[EDR_MAX_PATH];
            int length;
            const char *action = "UNKNOWN";
            RiskLevel risk;

            info = (FILE_NOTIFY_INFORMATION *)(buffer + offset);

            length = WideCharToMultiByte(
                CP_UTF8,
                0,
                info->FileName,
                (int)(info->FileNameLength / sizeof(WCHAR)),
                name,
                sizeof(name) - 1,
                NULL,
                NULL
            );

            if (length > 0) {
                name[length] = '\0';
                risk = edr_score_file(name);

                if (info->Action == FILE_ACTION_ADDED)
                    action = "ADDED";
                else if (info->Action == FILE_ACTION_REMOVED)
                    action = "REMOVED";
                else if (info->Action == FILE_ACTION_MODIFIED)
                    action = "MODIFIED";
                else if (info->Action == FILE_ACTION_RENAMED_OLD_NAME)
                    action = "RENAMED_OLD";
                else if (info->Action == FILE_ACTION_RENAMED_NEW_NAME)
                    action = "RENAMED_NEW";

                printf("[%s] %s [%s]\n",
                       action,
                       name,
                       edr_risk_name(risk));

                snprintf(message, sizeof(message),
                         "ACTION=%s FILE=%s RISK=%s",
                         action,
                         name,
                         edr_risk_name(risk));

                logger_event(risk >= RISK_HIGH ? "ALERT" : "EVENT",
                             "MONITOR", message);
            }

            if (info->NextEntryOffset == 0) {
                break;
            }

            offset += info->NextEntryOffset;
        }
    }

    CloseHandle(directory);
}
