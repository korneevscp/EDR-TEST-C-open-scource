#include <stdio.h>
#include <time.h>
#include "logger.h"

static FILE *log_file = NULL;

void logger_init(const char *filename) {
    log_file = fopen(filename, "a");
}

void logger_event(const char *level, const char *source, const char *message) {
    time_t now;
    struct tm *tm_info;
    char timestamp[32];

    if (!log_file) {
        return;
    }

    now = time(NULL);
    tm_info = localtime(&now);

    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(timestamp, sizeof(timestamp), "unknown");
    }

    fprintf(log_file, "[%s] [%s] [%s] %s\n",
            timestamp, level, source, message);
    fflush(log_file);
}

void logger_close(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
