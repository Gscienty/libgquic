#include "util/time.h"
#include <stddef.h>
#include <time.h>

int gquic_time_since_milli(int64_t *ret, const struct timeval *const t) {
    struct timeval now;
    if (ret == NULL || t == NULL) {
        return -1;
    }
    gettimeofday(&now, NULL);

    int64_t sec = now.tv_sec - t->tv_sec;
    int64_t micro_sec = now.tv_usec - t->tv_usec;
    if (micro_sec < 0) {
        sec--;
        micro_sec += 1000000;
    }
    *ret = sec * 1000 + micro_sec / 1000;
    return 0;
}
