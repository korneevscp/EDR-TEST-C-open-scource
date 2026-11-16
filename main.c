#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edr.h"
#include "logger.h"
#include "process.h"
#include "monitor.h"
#include "scanner.h"

static BOOL WINAPI X01CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        InterlockedExchange(&X01Stop, 1);
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI X01MonitorThread(LPVOID param) {
    X01MonitorRun((const WCHAR *)param);
    return 0;
}

static BOOL X01ReadLine(char *buf, int size) {
    size_t len;

    clearerr(stdin);
    if (!fgets(buf, size, stdin)) return FALSE;
    len = strcspn(buf, "\r\n");
    buf[len] = 0;
    return TRUE;
}

static BOOL X01AskPath(WCHAR *path, int size) {
    char line[EDR_PATH];
    int n;

    printf("Directory: ");
    if (!X01ReadLine(line, sizeof(line)) || !line[0]) return FALSE;
    n = MultiByteToWideChar(GetConsoleCP(), 0, line, -1, path, size);
    if (n > 1 && (path[n - 2] == L'\\' || path[n - 2] == L'/')) path[n - 2] = 0;
    return n > 0;
}

static void X01Menu(void) {
    printf("\n===============================================\n");
    printf("          MiniEDR %s by korneevscp\n", EDR_VERSION);
    printf("===============================================\n");
    printf("1. Process scan\n");
    printf("2. File scan (recursive)\n");
    printf("3. Directory monitoring\n");
    printf("4. Process monitoring\n");
    printf("5. Real-time protection (processes + directory)\n");
    printf("6. Exit\n");
    printf("> ");
}

static void X01RealTime(const WCHAR *path) {
    HANDLE thread = CreateThread(NULL, 0, X01MonitorThread, (LPVOID)path, 0, NULL);

    X01ProcessWatch();
    if (thread) {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
}

int main(int argc, char **argv) {
    const char *log = "edr.jsonl";
    const char *siem = NULL;
    char line[32];
    WCHAR path[EDR_PATH];
    BOOL run = TRUE;
    int i;

    for (i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--log")) log = argv[i + 1];
        else if (!strcmp(argv[i], "--siem")) siem = argv[i + 1];
    }

    SetConsoleTitleA("MiniEDR " EDR_VERSION);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(X01CtrlHandler, TRUE);

    if (!X01EdrInit()) {
        fprintf(stderr, "SHA-256 provider unavailable, hashing disabled.\n");
    }
    if (!X01LogInit(log, siem)) {
        fprintf(stderr, "Unable to open log file: %s\n", log);
    }
    X01Emit("agent", "agent_started", NULL, NULL);

    while (run) {
        X01Menu();
        if (!X01ReadLine(line, sizeof(line))) {
            if (feof(stdin)) break;
            continue;
        }

        InterlockedExchange(&X01Stop, 0);

        switch (atoi(line)) {
            case 1:
                X01ProcessScan();
                break;
            case 2:
                if (X01AskPath(path, X01N(path))) X01ScanDirectory(path);
                break;
            case 3:
                if (X01AskPath(path, X01N(path))) X01MonitorRun(path);
                break;
            case 4:
                X01ProcessWatch();
                break;
            case 5:
                if (X01AskPath(path, X01N(path))) X01RealTime(path);
                break;
            case 6:
                run = FALSE;
                break;
            default:
                break;
        }
    }

    X01Emit("agent", "agent_stopped", NULL, NULL);
    X01LogClose();
    X01EdrClose();
    return 0;
}
