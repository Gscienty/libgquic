#ifndef _LIBGQUIC_UTIL_TIMEOUT_H
#define _LIBGQUIC_UTIL_TIMEOUT_H

#include <sys/types.h>
#include <pthread.h>
#include "util/time.h"

int gquic_timeout_start(const gquic_time_t expire, int (*cb) (void *const), void *const args);

#endif
