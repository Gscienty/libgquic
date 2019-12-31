#ifndef _LIBGQUIC_CONG_HYBIRD_SLOW_START_H
#define _LIBGQUIC_CONG_HYBIRD_SLOW_START_H

#include <sys/types.h>

typedef struct gquic_cong_hybrid_slow_start_s gquic_cong_bybrid_slow_start_t;
struct gquic_cong_hybrid_slow_start_s {
    u_int64_t end_pn;
    u_int64_t last_sent_pn;
    int started;
    u_int64_t current_min_rtt;
    u_int32_t rtt_sample_count;
    int hystart_found;
};

int gquic_cong_hybrid_slow_start_init(gquic_cong_bybrid_slow_start_t *const slowstart);
int gquic_hybrid_slow_start_start_recv_round(gquic_cong_bybrid_slow_start_t *const slowstart, const u_int64_t last_sent);
int gquic_hybrid_slow_start_should_exit(gquic_cong_bybrid_slow_start_t *const slowstart,
                                        const u_int64_t last_rtt,
                                        const u_int64_t min_rtt,
                                        const u_int64_t cwnd);

#endif
