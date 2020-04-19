#ifndef _LIBGQUIC_FLOWCONTROL_BASE_H
#define _LIBGQUIC_FLOWCONTROL_BASE_H

#include "util/rtt.h"
#include "exception.h"
#include <sys/types.h>
#include <semaphore.h>
#include <stddef.h>

typedef struct gquic_flowcontrol_base_s gquic_flowcontrol_base_t;
struct gquic_flowcontrol_base_s {
    u_int64_t sent_bytes;
    u_int64_t swnd;
    u_int64_t last_blocked_at;
    sem_t mtx;
    u_int64_t read_bytes;
    u_int64_t highest_recv;
    u_int64_t rwnd;
    u_int64_t rwnd_size;
    u_int64_t max_rwnd_size;
    u_int64_t epoch_time;
    u_int64_t epoch_off;
    const gquic_rtt_t *rtt;
};

int gquic_flowcontrol_base_init(gquic_flowcontrol_base_t *const base);
int gquic_flowcontrol_base_dtor(gquic_flowcontrol_base_t *const base);
int gquic_flowcontrol_base_is_newly_blocked(u_int64_t *const swnd, gquic_flowcontrol_base_t *const base);
int gquic_flowcontrol_base_read_add_bytes(gquic_flowcontrol_base_t *const base, const u_int64_t n);
u_int64_t gquic_flowcontrol_base_swnd_size(const gquic_flowcontrol_base_t *const base);
int gquic_flowcontrol_base_has_wnd_update(const gquic_flowcontrol_base_t *const base);
u_int64_t gquic_flowcontrol_base_get_wnd_update(gquic_flowcontrol_base_t *const base);
int gquic_flowcontrol_base_sent_add_bytes(gquic_flowcontrol_base_t *const base, const u_int64_t n);
static inline int gquic_flowcontrol_base_update_swnd(gquic_flowcontrol_base_t *const base, const u_int64_t off) {
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (off > base->swnd) {
        base->swnd = off;
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
