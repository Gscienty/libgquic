#include "unit_test.h"
#include "util/cubic.h"
#include "util/time.h"
#include "exception.h"
#include <stdio.h>
#include <math.h>

static inline float beta() { return (2 - 1 + 0.7) / 2; }
static inline float beta_last_max() { return (2 - 1 + 0.85) / 2; }
static inline float alpha() { return 3 * 2 * 2 * (1 - beta()) / (1 + beta()); }

static inline u_int64_t reno_cwnd(const u_int64_t curr_cwnd) {
    return curr_cwnd + 1460 * alpha() * 1460 / curr_cwnd;
}

static inline u_int64_t convex_cwnd(const u_int64_t initial_cwnd, const u_int64_t rtt, const u_int64_t elapse) {
    u_int64_t off = ((elapse + rtt) << 10) / (1000 * 1000);
    u_int64_t delta_cwnd = (410 * off * off * off * 1460) >> 40;
    return initial_cwnd + delta_cwnd;
}

GQUIC_UNIT_TEST(cubic_same_as_reno_1) {
    const u_int64_t rtt_min = 100 * 1000;
    u_int64_t curr_cwnd = 10 * 1460;

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

GQUIC_UNIT_TEST(cubic_same_as_reno_2) {
    const u_int64_t rtt_min = 100 * 1000;
    const double rtt_min_s = 0.1;
    u_int64_t curr_cwnd = 10 * 1460;
    u_int64_t initial_cwnd = curr_cwnd;

    gquic_cubic_t cubic;
    gquic_cubic_init(&cubic);
    gquic_cubic_ctor(&cubic);
    cubic.conn_count = 2;

    u_int64_t now = gquic_time_now();
    u_int64_t initial_time = now;

    u_int64_t expect_cwnd = reno_cwnd(curr_cwnd);
    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);

    if (expect_cwnd != curr_cwnd) {
        return -1;
    }
    
    int max_reno_rtts = sqrt(alpha() / (0.4 * rtt_min_s * rtt_min_s * rtt_min_s) - 2);
    int i = 0;
    for (i = 0; i < max_reno_rtts; i++) {
        int acks_count = (curr_cwnd * 1.0 / 1460) / alpha();
        u_int64_t curr_initial_cwnd = curr_cwnd;

        int n = 0;
        for (n = 0; n < acks_count; n++) {
            u_int64_t next_expect_cwnd = reno_cwnd(curr_cwnd);
            curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
            if (next_expect_cwnd != curr_cwnd) {
                return -1;
            }
        }

        u_int64_t cwnd_changed = curr_cwnd - curr_initial_cwnd;
        if (cwnd_changed < (1460 / 2) || 1460 < cwnd_changed) {
            return -1;
        }
        now += 99 * 1000;
    }

    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);

    for (i = 0; i < 54; i++) {
        int max_acks_count = curr_cwnd / 1460;
        u_int64_t interval = 100 * 1000 / max_acks_count;
        int n;
        for (n = 0; n < max_acks_count; n++) {
            now += interval;
            curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
            expect_cwnd = convex_cwnd(initial_cwnd, rtt_min, now - initial_time);
            if (expect_cwnd != curr_cwnd) {
                return -1;
            }
        }
    }
    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
    expect_cwnd = convex_cwnd(initial_cwnd, rtt_min, now - initial_time);
    if (expect_cwnd != curr_cwnd) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(cubic_test) {
    u_int64_t curr_cwnd = 1000 * 1460;
    u_int64_t initial_cwnd = curr_cwnd;
    u_int64_t rtt_min = 100 * 1000;
    u_int64_t now = gquic_time_now();
    u_int64_t initial_time = now;

    gquic_cubic_t cubic;
    gquic_cubic_init(&cubic);
    gquic_cubic_ctor(&cubic);
    cubic.conn_count = 2;

    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
    now += 600 * 1000;
    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);

    int i;
    for (i = 0; i < 100; i++) {
        now += 10 * 1000;
        u_int64_t expect_cwnd = convex_cwnd(initial_cwnd, rtt_min, now - initial_time);
        u_int64_t next_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
        if (expect_cwnd != next_cwnd) {
            return -1;
        }
        if (next_cwnd <= curr_cwnd) {
            return -1;
        }
        if (1460 / 10 <= next_cwnd - curr_cwnd) {
            return -1;
        }
        curr_cwnd = next_cwnd;
    }

    return 0;
}

GQUIC_UNIT_TEST(cubic_handle_ack) {
    u_int64_t initial_cwnd_packets = 150;
    u_int64_t curr_cwnd = initial_cwnd_packets * 1460;
    u_int64_t rtt_min = 350 * 1000;

    gquic_cubic_t cubic;
    gquic_cubic_init(&cubic);
    gquic_cubic_ctor(&cubic);
    cubic.conn_count = 2;

    u_int64_t now = gquic_time_now();

    u_int64_t r_cwnd = reno_cwnd(curr_cwnd);
    curr_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
    u_int64_t initial_cwnd = curr_cwnd;

    int max_acks = initial_cwnd_packets / alpha();
    u_int64_t interval = 30 * 1000 / (max_acks + 1);

    now += interval;
    r_cwnd = reno_cwnd(curr_cwnd);

    if (curr_cwnd != gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now)) {
        return -1;
    }
    int i;
    for (i = 0; i < max_acks; i++) {
        now += interval;
        u_int64_t next_cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic, 1460, curr_cwnd, rtt_min, now);
        r_cwnd = reno_cwnd(curr_cwnd);

        if (i != 0) {
            if (next_cwnd < curr_cwnd) {
                return -1;
            }
            if (next_cwnd != r_cwnd) {
                return -1;
            }
        }
        curr_cwnd = next_cwnd;
    }
    u_int64_t min_inc = 1460 * 9 / 10;
    if (curr_cwnd <= min_inc + initial_cwnd) {
        return -1;
    }
    return 0;
}
