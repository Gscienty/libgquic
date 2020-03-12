#include "unit_test.h"
#include "util/cubic.h"
#include "util/time.h"
#include "exception.h"
#include <stdio.h>

static inline float beta() { return (2 - 1 + 0.7) / 2; }
static inline float beta_last_max() { return (2 - 1 + 0.85) / 2; }
static inline float alpha() { return 3 * 2 * 2 * (1 - beta()) / (1 + beta()); }

static inline u_int64_t reno_cwnd(const u_int64_t curr_cwnd) {
    return curr_cwnd + 1460 * alpha() * 1460 / curr_cwnd;
}

GQUIC_UNIT_TEST(cubic_same_as_reno) {
    const u_int64_t rtt_min = 100 * 1000;
    const double rtt_min_s = 0.1;
    u_int64_t curr_cwnd = 10 * 1460;
    u_int64_t initial_cwnd = curr_cwnd;

    gquic_cubic_t cubic;
    gquic_cubic_init(&cubic);
    gquic_cubic_ctor(&cubic);
    cubic.conn_count = 2;

    u_int64_t expect_cwnd = reno_cwnd(curr_cwnd);
    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, gquic_time_now());

    if (expect_cwnd != curr_cwnd) {
        return -1;
    }
    return 0;
}
