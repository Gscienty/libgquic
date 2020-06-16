#ifndef _LIBGQUIC_LOG_H
#define _LIBGQUIC_LOG_H

#define GQUIC_LOG_TRACE 1
#define GQUIC_LOG_DEBUG 2
#define GQUIC_LOG_INFO  3
#define GQUIC_LOG_WARN  4
#define GQUIC_LOG_ERROR 5

#if LOG

void gquic_write_log(const int level, const char *const func_name, const int line, const char *const fmt, ...);

#define GQUIC_LOG(level, fmt, ...) gquic_write_log(level, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#else

#define GQUIC_LOG(level, fmt, ...)

#endif

#endif
