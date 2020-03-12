#ifndef _LIBGQUIC_UTIL_TIME_H
#define _LIBGQUIC_UTIL_TIME_H

#include <sys/types.h>
#include <sys/time.h>
#include <stddef.h>

int gquic_time_since_milli(int64_t *ret, const struct timeval *const t);
static inline u_int64_t gquic_time_now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

#endif
