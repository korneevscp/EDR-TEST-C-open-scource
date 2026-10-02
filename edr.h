#ifndef EDR_H
#define EDR_H

#define EDR_VERSION "2.0.0"
#define EDR_MAX_PATH 520

typedef enum {
    RISK_NONE = 0,
    RISK_LOW = 1,
    RISK_MEDIUM = 2,
    RISK_HIGH = 3,
    RISK_CRITICAL = 4
} RiskLevel;

const char *edr_risk_name(RiskLevel level);
void edr_print_banner(void);
RiskLevel edr_score_process(const char *name);
RiskLevel edr_score_file(const char *name);

#endif
