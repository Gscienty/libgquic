#ifndef _LIBGQUIC_COROUTINE_SCHEDULE_H
#define _LIBGQUIC_COROUTINE_SCHEDULE_H

#include "coroutine/context.h"
#include "coroutine/coroutine.h"
#include "coroutine/timer.h"
#include "util/list.h"
#include <pthread.h>

typedef struct gquic_coroutine_schedule_s gquic_coroutine_schedule_t;
struct gquic_coroutine_schedule_s {
    gquic_couroutine_context_t schedule_ctx;

    pthread_mutex_t mtx;
    pthread_cond_t cond;

    gquic_list_t ready; /* gquic_coroutine_t * */
    gquic_coroutine_timer_t timer;
};

#define GQUIC_COROUTINE_GET_SCHEDULE(co) \
    ((gquic_coroutine_schedule_t *) (((void *) (co)->ctx.link) - ((void *) &((gquic_coroutine_schedule_t *) 0)->schedule_ctx)))

int gquic_coroutine_schedule_init(gquic_coroutine_schedule_t *const sche);
int gquic_coroutine_schedule_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co);
int gquic_coroutine_schedule_resume(gquic_coroutine_t **const co_storage, gquic_coroutine_schedule_t *const sche);
int gquic_coroutine_schedule_yield(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co);
int gquic_coroutine_schedule_timeout_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co, u_int64_t timeout);
static inline int gquic_coroutine_next(gquic_coroutine_t *const co) {
    gquic_coroutine_schedule_t *sche = NULL;
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sche = GQUIC_COROUTINE_GET_SCHEDULE(co);
    switch (co->status) {
    case GQUIC_COROUTINE_STATUS_RUNNING:
        co->status = GQUIC_COROUTINE_STATUS_READYING;

    case GQUIC_COROUTINE_STATUS_READYING:
        gquic_coroutine_schedule_join(sche, co);
        break;

    case GQUIC_COROUTINE_STATUS_TERMINATE:
        gquic_coroutine_try_release(co);
        break;

    case GQUIC_COROUTINE_STATUS_WAITING:
    case GQUIC_COROUTINE_STATUS_STARTING:
        break;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
