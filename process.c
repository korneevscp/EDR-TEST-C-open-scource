#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "process.h"
#include "edr.h"
#include "logger.h"

void process_scan(void) {
    HANDLE snapshot;
    PROCESSENTRY32 entry;
    unsigned int count = 0;
    char message[512];

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Process snapshot error.\n");
        logger_event("ERROR", "PROCESS", "CreateToolhelp32Snapshot failed");
        return;
    }

    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry)) {
        printf("Process enumeration error.\n");
        logger_event("ERROR", "PROCESS", "Process32First failed");
        CloseHandle(snapshot);
        return;
    }

    printf("\n%-8s %-35s %-12s\n", "PID", "PROCESS", "RISK");
    printf("------------------------------------------------------------\n");

    do {
        RiskLevel risk = edr_score_process(entry.szExeFile);

        printf("%-8lu %-35s %-12s\n",
               (unsigned long)entry.th32ProcessID,
               entry.szExeFile,
               edr_risk_name(risk));

        if (risk > RISK_NONE) {
            snprintf(message, sizeof(message),
                     "PID=%lu PROCESS=%s RISK=%s",
                     (unsigned long)entry.th32ProcessID,
                     entry.szExeFile,
                     edr_risk_name(risk));

            logger_event(risk >= RISK_HIGH ? "ALERT" : "EVENT",
                         "PROCESS", message);
        }

        count++;
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);

    printf("\nProcesses analyzed: %u\n", count);
    logger_event("INFO", "PROCESS", "Process scan completed");
}
