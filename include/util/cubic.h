#ifndef _LIBGQUIC_UTIL_CUBIC_H
#define _LIBGQUIC_UTIL_CUBIC_H

#include <sys/types.h>

typedef struct gquic_cubic_s gquic_cubic_t;
struct gquic_cubic_s {
    int conn_count;
    u_int64_t epoch;
    u_int64_t last_max_cwnd;
    u_int64_t ack_bytes_count;
    u_int64_t est_cwnd;
    u_int64_t origin_point_cwnd;
    u_int32_t origin_point_time;
    u_int64_t last_target_cwnd;
};

int gquic_cubic_init(gquic_cubic_t *const cubic);
int gquic_cubic_ctor(gquic_cubic_t *const cubic);
u_int64_t gquic_cubic_cwnd_after_packet_loss(gquic_cubic_t *const cubic, const u_int64_t cwnd);
u_int64_t gquic_cubic_cwnd_after_packet_ack(gquic_cubic_t *const cubic,
                                            const u_int64_t acked_bytes,
                                            const u_int64_t cwnd,
                                            const u_int64_t delay_min,
                                            const u_int64_t event_time);

#endif
