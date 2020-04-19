#include "coroutine/chain.h"
#include "exception.h"

int gquic_coroutine_chain_init(gquic_coroutine_chain_t *const chain) {
    if (chain == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&chain->waiting);
    gquic_list_head_init(&chain->elems);

    pthread_mutex_init(&chain->mtx, NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_chain_wait(void **const result, gquic_coroutine_chain_t *const chain, gquic_coroutine_t *const co) {
    int exception = GQUIC_SUCCESS;
    int first = 1;
    gquic_coroutine_t **co_storage = NULL;
    if (result == NULL || chain == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&chain->mtx);
    while (gquic_list_head_empty(&chain->elems)) {
        if (first) {
            co->status = GQUIC_COROUTINE_STATUS_WAITING;
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &co_storage, sizeof(gquic_coroutine_t *)))) {
                pthread_mutex_unlock(&chain->mtx);
                GQUIC_PROCESS_DONE(exception);
            }
            *co_storage = co;
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&chain->waiting, co_storage))) {
                pthread_mutex_unlock(&chain->mtx);
                GQUIC_PROCESS_DONE(exception);
            }
            first = 0;
        }
        pthread_mutex_unlock(&chain->mtx);
        gquic_coroutine_yield(co);
        pthread_mutex_lock(&chain->mtx);
    }

    *result = *(void **) GQUIC_LIST_FIRST(&chain->elems);
    pthread_mutex_unlock(&chain->mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_chain_send(gquic_coroutine_chain_t *const chain, gquic_coroutine_schedule_t *const sche, void *const message) {
    int exception = GQUIC_SUCCESS;
    void **message_storage = NULL;
    gquic_coroutine_t *co = NULL;
    if (chain == NULL || sche == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &message_storage, sizeof(void *)));
    *message_storage = message;

    pthread_mutex_lock(&chain->mtx);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_after(&chain->elems, message_storage))) {
        pthread_mutex_unlock(&chain->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    if (!gquic_list_head_empty(&chain->waiting)) {
        co = *(gquic_coroutine_t **) GQUIC_LIST_FIRST(&chain->waiting);
        gquic_list_release(GQUIC_LIST_FIRST(&chain->waiting));
    }
    pthread_mutex_unlock(&chain->mtx);
    if (co != NULL) {
        GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_schedule_join(sche, co));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
