#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "scanner.h"
#include "edr.h"
#include "logger.h"

void scanner_scan_directory(const char *path) {
    WIN32_FIND_DATAA data;
    HANDLE find_handle;
    char pattern[EDR_MAX_PATH];
    char fullpath[EDR_MAX_PATH];
    char message[1024];
    unsigned int files = 0;
    unsigned int alerts = 0;

    snprintf(pattern, sizeof(pattern), "%s\\*", path);

    find_handle = FindFirstFileA(pattern, &data);

    if (find_handle == INVALID_HANDLE_VALUE) {
        printf("Directory unavailable: %s\n", path);
        logger_event("ERROR", "SCANNER", "Directory unavailable");
        return;
    }

    printf("\n%-45s %-12s\n", "FILE", "RISK");
    printf("------------------------------------------------------------\n");

    do {
        RiskLevel risk;

        if (!strcmp(data.cFileName, ".") ||
            !strcmp(data.cFileName, "..")) {
            continue;
        }

        snprintf(fullpath, sizeof(fullpath),
                 "%s\\%s", path, data.cFileName);

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        risk = edr_score_file(data.cFileName);

        printf("%-45s %-12s\n",
               data.cFileName,
               edr_risk_name(risk));

        if (risk > RISK_NONE) {
            snprintf(message, sizeof(message),
                     "FILE=%s RISK=%s",
                     fullpath,
                     edr_risk_name(risk));

            logger_event(risk >= RISK_HIGH ? "ALERT" : "EVENT",
                         "SCANNER", message);
            alerts++;
        }

        files++;
    } while (FindNextFileA(find_handle, &data));

    FindClose(find_handle);

    printf("\nFiles analyzed: %u\n", files);
    printf("Alerts: %u\n", alerts);

    logger_event("INFO", "SCANNER", "Directory scan completed");
}
