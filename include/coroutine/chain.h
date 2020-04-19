#ifndef _LIBGQUIC_COROUTINE_CHAIN_H
#define _LIBGQUIC_COROUTINE_CHAIN_H

#include "coroutine/coroutine.h"
#include "coroutine/schedule.h"
#include "util/list.h"
#include <pthread.h>

typedef struct gquic_coroutine_chain_s gquic_coroutine_chain_t;
struct gquic_coroutine_chain_s {
    gquic_list_t waiting; /* gquic_coroutine_t * */
    gquic_list_t elems; /* void * */

    pthread_mutex_t mtx;
};

int gquic_coroutine_chain_init(gquic_coroutine_chain_t *const chain);
int gquic_coroutine_chain_wait(void **const result, gquic_coroutine_chain_t *const chain, gquic_coroutine_t *const co);
int gquic_coroutine_chain_send(gquic_coroutine_chain_t *const chain, gquic_coroutine_schedule_t *const sche, void *const message);

#endif
