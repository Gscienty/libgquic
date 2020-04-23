#include "coroutine/schedule.h"
#include "exception.h"
#include <stdio.h>

static int gquic_schedule_coroutine_execute_wrapper(void *const);
static int gquic_schedule_coroutine_executed_finally(gquic_coroutine_schedule_t *const, gquic_coroutine_t *const);

int gquic_coroutine_schedule_init(gquic_coroutine_schedule_t *const sche) {
    if (sche == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coroutine_current_context(&sche->schedule_ctx);
    pthread_mutex_init(&sche->mtx, NULL);
    pthread_cond_init(&sche->cond, NULL);
    gquic_list_head_init(&sche->ready);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_schedule_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co) {
    int exception = GQUIC_SUCCESS;
    gquic_coroutine_t **co_storage = NULL;
    if (sche == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    co->ctx.link = &sche->schedule_ctx;
    if (co->status == GQUIC_COROUTINE_STATUS_STARTING) {
        gquic_coroutine_make_context(&co->ctx, gquic_schedule_coroutine_execute_wrapper, co);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &co_storage, sizeof(gquic_coroutine_t *)));
    *co_storage = co;

    pthread_mutex_lock(&sche->mtx);
    co->status = GQUIC_COROUTINE_STATUS_READYING;
    GQUIC_EXCEPTION_ASSIGN(exception, gquic_list_insert_before(&sche->ready, co_storage));
    pthread_mutex_unlock(&sche->mtx);
    pthread_cond_signal(&sche->cond);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_coroutine_schedule_resume(gquic_coroutine_schedule_t *const sche) {
    gquic_coroutine_t *co = NULL;
    if (sche == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&sche->mtx);
    while (gquic_list_head_empty(&sche->ready)) {
        pthread_cond_wait(&sche->cond, &sche->mtx);
    }
    co = *(gquic_coroutine_t **) GQUIC_LIST_FIRST(&sche->ready);
    gquic_list_release(GQUIC_LIST_FIRST(&sche->ready));
    pthread_mutex_unlock(&sche->mtx);

    co->status = GQUIC_COROUTINE_STATUS_RUNNING;
    gquic_coroutine_swap_context(&sche->schedule_ctx, &co->ctx);
    gquic_schedule_coroutine_executed_finally(sche, co);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_schedule_yield(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co) {
    if (sche == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coroutine_swap_context(&co->ctx, &sche->schedule_ctx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_schedule_coroutine_execute_wrapper(void *const co_) {
    gquic_coroutine_t *const co = co_;
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_COROUTINE_CALL(co);

    co->status = GQUIC_COROUTINE_STATUS_TERMIATE;
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_schedule_coroutine_executed_finally(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (co->status) {
    case GQUIC_COROUTINE_STATUS_RUNNING:
        co->status = GQUIC_COROUTINE_STATUS_READYING;

    case GQUIC_COROUTINE_STATUS_READYING:
        gquic_coroutine_schedule_join(sche, co);
        break;

    case GQUIC_COROUTINE_STATUS_TERMIATE:
        gquic_coroutine_release(co);
        break;

    case GQUIC_COROUTINE_STATUS_WAITING:
    case GQUIC_COROUTINE_STATUS_STARTING:
        break;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
