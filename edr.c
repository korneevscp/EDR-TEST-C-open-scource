#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "edr.h"

static int contains(const char *text, const char *needle) {
    char a[1024];
    char b[256];
    size_t i;

    strncpy(a, text, sizeof(a) - 1);
    a[sizeof(a) - 1] = '\0';
    strncpy(b, needle, sizeof(b) - 1);
    b[sizeof(b) - 1] = '\0';

    for (i = 0; a[i]; ++i) {
        a[i] = (char)tolower((unsigned char)a[i]);
    }

    for (i = 0; b[i]; ++i) {
        b[i] = (char)tolower((unsigned char)b[i]);
    }

    return strstr(a, b) != NULL;
}

const char *edr_risk_name(RiskLevel level) {
    switch (level) {
        case RISK_LOW: return "LOW";
        case RISK_MEDIUM: return "MEDIUM";
        case RISK_HIGH: return "HIGH";
        case RISK_CRITICAL: return "CRITICAL";
        default: return "NONE";
    }
}

void edr_print_banner(void) {
    printf("\nMiniEDR %s\n", EDR_VERSION);
}

RiskLevel edr_score_process(const char *name) {
    if (contains(name, "mimikatz") ||
        contains(name, "psexec") ||
        contains(name, "procdump")) {
        return RISK_HIGH;
    }

    if (contains(name, "powershell") ||
        contains(name, "wscript") ||
        contains(name, "cscript")) {
        return RISK_LOW;
    }

    return RISK_NONE;
}

RiskLevel edr_score_file(const char *name) {
    if (contains(name, ".ps1") ||
        contains(name, ".vbs") ||
        contains(name, ".js") ||
        contains(name, ".hta")) {
        return RISK_LOW;
    }

    if (contains(name, "mimikatz") ||
        contains(name, "payload") ||
        contains(name, "shellcode")) {
        return RISK_HIGH;
    }

    return RISK_NONE;
}
