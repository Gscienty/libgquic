#ifndef _LIBGQUIC_UTIL_PRR_H
#define _LIBGQUIC_UTIL_PRR_H

#include <sys/types.h>

typedef struct gquic_prr_s gquic_prr_t;
struct gquic_prr_s {
    u_int64_t sent_bytes;
    u_int64_t delivered_bytes;
    u_int64_t ack_count;
    u_int64_t infly_bytes;
};

int gquic_prr_init(gquic_prr_t *const prr);
int gquic_prr_packet_lost(gquic_prr_t *const prr, const u_int64_t infly);
int gquic_prr_allowable_send(gquic_prr_t *const prr, const u_int64_t cwnd, const u_int64_t infly, const u_int64_t slowstart_thd);

#endif
