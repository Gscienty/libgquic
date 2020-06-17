#include "log.h"

#if LOG
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static char *gquic_get_level_str(const int);
static char *gquic_curr_time(char timestr[]);

void gquic_write_log(const int level, const char *const fmt, ...) {
    char timestr[25] = { 0 };
    char log_info[128] = { 0 };
    va_list args;

    va_start(args, fmt);
    snprintf(log_info, 128, fmt, args);
    va_end(args);

    printf("%s %s -|\t%s\n", gquic_get_level_str(level), gquic_curr_time(timestr), log_info);
}

static char *gquic_get_level_str(const int level) {
    switch (level) {
    case GQUIC_LOG_INFO:
        return "[ INFO]";
    case GQUIC_LOG_WARN:
        return "[ WARN]";
    case GQUIC_LOG_DEBUG:
        return "[DEBUG]";
    case GQUIC_LOG_ERROR:
        return "[ERROR]";
    case GQUIC_LOG_TRACE:
        return "[TRACE]";
    }
    return "[     ]";
}

static char *gquic_curr_time(char timestr[]) {
    time_t tt = { 0 };
    struct tm *curr_time = NULL;

    time(&tt);
    curr_time = localtime(&tt);
    snprintf(timestr, 24, "%04d/%02d/%02d %02d:%02d:%02d",
             curr_time->tm_year + 1900, curr_time->tm_mon + 1, curr_time->tm_mday,
             curr_time->tm_hour, curr_time->tm_min, curr_time->tm_sec);

    return timestr;
}
#endif
