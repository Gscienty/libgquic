#include "util/pn.h"

#define __DELTA(a, b) (((a) > (b)) ? ((a) - (b)) : ((b) - (a)))

static inline u_int64_t __close_to(const u_int64_t target, const u_int64_t a, const u_int64_t b) {
    return __DELTA(target, a) < __DELTA(target, b) ? a : b;
}

u_int64_t gquic_pn_decode(const int pn_len, const u_int64_t last_pn, const u_int64_t pn) {
    u_int64_t epoch_delta = 0;
    u_int64_t epoch = 0;
    u_int64_t prev_epoch_begin = 0;
    u_int64_t next_epoch_begin = 0;
    switch (pn_len) {
    case 1:
        epoch_delta = 1UL << 8;
        break;
    case 2:
        epoch_delta = 1UL << 16;
        break;
    case 3:
        epoch_delta = 1UL << 24;
        break;
    case 4:
        epoch_delta = 1UL << 32;
        break;
    }
    epoch = last_pn & ~(epoch_delta - 1);
    if (epoch > epoch_delta) {
        prev_epoch_begin = epoch - epoch_delta;
    }
    next_epoch_begin = epoch + epoch_delta;
    return __close_to(last_pn + 1, epoch + pn, __close_to(last_pn + 1, prev_epoch_begin + pn, next_epoch_begin + pn));
}
