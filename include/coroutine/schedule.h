#ifndef _LIBGQUIC_COROUTINE_SCHEDULE_H
#define _LIBGQUIC_COROUTINE_SCHEDULE_H

#include "coroutine/context.h"
#include "coroutine/coroutine.h"
#include "util/list.h"
#include <pthread.h>

typedef struct gquic_coroutine_schedule_s gquic_coroutine_schedule_t;
struct gquic_coroutine_schedule_s {
    gquic_couroutine_context_t schedule_ctx;

    pthread_mutex_t mtx;
    pthread_cond_t cond;

    gquic_list_t ready; /* gquic_coroutine_t * */
};

int gquic_coroutine_schedule_init(gquic_coroutine_schedule_t *const sche);
int gquic_coroutine_schedule_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co);

#endif
