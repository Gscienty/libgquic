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
int gquic_coroutine_schedule_resume(gquic_coroutine_schedule_t *const sche);
int gquic_coroutine_schedule_yield(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co);
int gquic_coroutine_schedule_timeout_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co, u_int64_t timeout);

static inline int gquic_coroutine_fast_join(gquic_coroutine_schedule_t *const sche, size_t stack_size, int (*func) (gquic_coroutine_t *const, void *const), void *args) {
    gquic_coroutine_t *co = NULL;
    if (func == NULL || args == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_alloc(&co));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_init(co));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_ctor(co, stack_size, func, args));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_schedule_join(sche, co));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
