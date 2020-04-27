#ifndef _LIBGQUIC_COROUTINE_TIMER_H
#define _LIBGQUIC_COROUTINE_TIMER_H

#include "coroutine/coroutine.h"
#include "util/list.h"
#include <pthread.h>
#include <sys/types.h>

typedef struct gquic_coroutine_timer_unit_s gquic_coroutine_timer_unit_t;
struct gquic_coroutine_timer_unit_s {
    u_int64_t timeout;
    gquic_coroutine_t *co;
};

typedef struct gquic_coroutine_timer_s gquic_coroutine_timer_t;
struct gquic_coroutine_timer_s {
    gquic_list_t waiting;
};

int gquic_coroutine_timer_init(gquic_coroutine_timer_t *const timer);
int gquic_coroutine_timer_push(gquic_coroutine_timer_t *const timer, gquic_coroutine_t *const co, const u_int64_t timeout);
int gquic_coroutine_timer_pop(gquic_coroutine_t **const co_storage, gquic_coroutine_timer_t *const timer);
u_int64_t gquic_coroutine_timer_late(gquic_coroutine_timer_t *const timer);
int gquic_coroutine_timer_exist(gquic_coroutine_timer_t *const timer, const gquic_coroutine_t *const co);

inline static int gquic_coroutine_timer_empty(gquic_coroutine_timer_t *const timer) {
    if (timer == NULL) {
        return 1;
    }
    return gquic_list_head_empty(&timer->waiting);
}

#endif
