#include <windows.h>
#include <stdio.h>
#include "edr.h"
#include "logger.h"
#include "process.h"
#include "monitor.h"
#include "scanner.h"

static void menu(void) {
    printf("\n===============================================\n");
    printf("                 MiniEDR V2\n");
    printf("===============================================\n");
    printf("1. Process scan\n");
    printf("2. File scan\n");
    printf("3. File monitoring\n");
    printf("4. Full scan\n");
    printf("5. Exit\n");
    printf("> ");
}

int main(void) {
    int choice = 0;
    char path[MAX_PATH];

    SetConsoleTitleA("MiniEDR V2");
    logger_init("edr.log");

    for (;;) {
        menu();

        if (scanf("%d", &choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {}
            continue;
        }

        if (choice == 1) {
            process_scan();
        } else if (choice == 2) {
            printf("Directory: ");
            scanf("%259s", path);
            scanner_scan_directory(path);
        } else if (choice == 3) {
            printf("Directory: ");
            scanf("%259s", path);
            monitor_run(path);
        } else if (choice == 4) {
            process_scan();
            scanner_scan_directory(".");
        } else if (choice == 5) {
            break;
        }
    }

    logger_close();
    return 0;
}
