#ifndef _LIBGQUIC_UTIL_TIME_H
#define _LIBGQUIC_UTIL_TIME_H

#include <sys/types.h>
#include <sys/time.h>

int gquic_time_since_milli(int64_t *ret, const struct timeval *const t);

#endif
