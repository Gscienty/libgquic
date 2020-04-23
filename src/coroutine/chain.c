#include "coroutine/chain.h"
#include "exception.h"
#include <stdarg.h>
#include <stdio.h>

static int gquic_coroutine_single_chain_recv(void **const, gquic_coroutine_t *const, gquic_coroutine_chain_t *const, const int waiting);

int gquic_coroutine_chain_init(gquic_coroutine_chain_t *const chain) {
    if (chain == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&chain->waiting);
    gquic_list_head_init(&chain->elems);

    pthread_mutex_init(&chain->mtx, NULL);

    chain->closed = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_chain_recv(void **const result, gquic_coroutine_t *const co, const int waiting, ...) {
    va_list chains;
    gquic_coroutine_chain_t *chain = NULL;
    if (result == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *result = NULL;
    va_start(chains, waiting);
    while ((chain = va_arg(chains, gquic_coroutine_chain_t *)) != NULL) {
        GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_single_chain_recv(result, co, chain, waiting));
        if (*result != NULL) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }
    va_end(chains);

    if (waiting) {
        co->status = GQUIC_COROUTINE_STATUS_WAITING;
        gquic_coroutine_yield(co);
        va_start(chains, waiting);
        while ((chain = va_arg(chains, gquic_coroutine_chain_t *const)) != NULL) {
            GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_single_chain_recv(result, co, chain, 0));
            if (*result != NULL) {
                GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
            }
        }
        va_end(chains);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_chain_send(gquic_coroutine_chain_t *const chain, gquic_coroutine_schedule_t *const sche, void *const message) {
    int exception = GQUIC_SUCCESS;
    void **message_storage = NULL;
    gquic_coroutine_t *co = NULL;
    if (chain == NULL || sche == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&chain->mtx);
    if (chain->closed) {
        pthread_mutex_unlock(&chain->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CLOSED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &message_storage, sizeof(void *)))) {
        pthread_mutex_unlock(&chain->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    *message_storage = message;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&chain->elems, message_storage))) {
        pthread_mutex_unlock(&chain->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    if (!gquic_list_head_empty(&chain->waiting)) {
        co = *(gquic_coroutine_t **) GQUIC_LIST_FIRST(&chain->waiting);
        gquic_list_release(GQUIC_LIST_FIRST(&chain->waiting));
    }
    pthread_mutex_unlock(&chain->mtx);
    if (co != NULL) {
        co->status = GQUIC_COROUTINE_STATUS_READYING;
        GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_schedule_join(sche, co));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_coroutine_single_chain_recv(void **const result, gquic_coroutine_t *const co, gquic_coroutine_chain_t *const chain, const int waiting) {
    int exception = GQUIC_SUCCESS;
    gquic_coroutine_t **co_storage = NULL;
    if (result == NULL || co == NULL || chain == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&chain->mtx);
    if (chain->closed) {
        pthread_mutex_unlock(&chain->mtx);
        *result = chain;
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CLOSED);
    }
    if (gquic_list_head_empty(&chain->elems) && waiting) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &co_storage, sizeof(gquic_coroutine_t *)))) {
            pthread_mutex_unlock(&chain->mtx);
            GQUIC_PROCESS_DONE(exception);
        }
        *co_storage = co;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&chain->waiting, co_storage))) {
            pthread_mutex_unlock(&chain->mtx);
            GQUIC_PROCESS_DONE(exception);
        }
    }
    else if (!gquic_list_head_empty(&chain->elems)) {
        *result = *(void **) GQUIC_LIST_FIRST(&chain->elems);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_release(GQUIC_LIST_FIRST(&chain->elems)))) {
            pthread_mutex_unlock(&chain->mtx);
            GQUIC_PROCESS_DONE(exception);
        }
    }
    pthread_mutex_unlock(&chain->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_chain_boradcast_close(gquic_coroutine_chain_t *const chain, gquic_coroutine_schedule_t *const sche) {
    gquic_coroutine_t *co = NULL;
     if (chain == NULL || sche == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
     }
     pthread_mutex_lock(&chain->mtx);
     chain->closed = 1;
     while (!gquic_list_head_empty(&chain->waiting)) {
        co = *(gquic_coroutine_t **) GQUIC_LIST_FIRST(&chain->waiting);
        gquic_list_release(GQUIC_LIST_FIRST(&chain->waiting));
        pthread_mutex_unlock(&chain->mtx);
        GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_schedule_join(sche, co));
        pthread_mutex_lock(&chain->mtx);
     }
     pthread_mutex_unlock(&chain->mtx);
     GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
