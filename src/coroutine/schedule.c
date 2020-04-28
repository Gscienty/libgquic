#include "coroutine/schedule.h"
#include "exception.h"
#include "util/time.h"
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
    gquic_coroutine_timer_init(&sche->timer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_schedule_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co) {
    int exception = GQUIC_SUCCESS;
    gquic_coroutine_t **co_storage = NULL;
    if (sche == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&sche->mtx);
    GQUIC_LIST_FOREACH(co_storage, &sche->ready) {
        if (*co_storage == co) {
            pthread_mutex_unlock(&sche->mtx);
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    co->ctx.link = &sche->schedule_ctx;
    switch (co->status) {
    case GQUIC_COROUTINE_STATUS_STARTING:
        gquic_coroutine_make_context(&co->ctx, gquic_schedule_coroutine_execute_wrapper, co);
        break;

    case GQUIC_COROUTINE_STATUS_TERMIATE:
        gquic_coroutine_try_release(co);
        pthread_mutex_unlock(&sche->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CLOSED);
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &co_storage, sizeof(gquic_coroutine_t *)))) {
        pthread_mutex_unlock(&sche->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    *co_storage = co;

    co->status = GQUIC_COROUTINE_STATUS_READYING;
    gquic_coroutine_join_ref(co);
    GQUIC_EXCEPTION_ASSIGN(exception, gquic_list_insert_before(&sche->ready, co_storage));
    pthread_mutex_unlock(&sche->mtx);
    pthread_cond_signal(&sche->cond);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_coroutine_schedule_timeout_join(gquic_coroutine_schedule_t *const sche, gquic_coroutine_t *const co, u_int64_t timeout) {
    int exception = GQUIC_SUCCESS;
    if (sche == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (timeout <= gquic_time_now()) {
        return gquic_coroutine_schedule_join(sche, co);
    }

    pthread_mutex_lock(&sche->mtx);
    if (gquic_coroutine_timer_exist(&sche->timer, co)) {
        pthread_mutex_unlock(&sche->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    co->ctx.link = &sche->schedule_ctx;
    if (co->status == GQUIC_COROUTINE_STATUS_STARTING) {
        gquic_coroutine_make_context(&co->ctx, gquic_schedule_coroutine_execute_wrapper, co);
    }

    GQUIC_EXCEPTION_ASSIGN(exception, gquic_coroutine_timer_push(&sche->timer, co, timeout));
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
        if (gquic_coroutine_timer_empty(&sche->timer)) {
            pthread_cond_wait(&sche->cond, &sche->mtx);
        }
        else {
            u_int64_t deadline = gquic_coroutine_timer_late(&sche->timer);
            struct timespec timeout = { deadline / (1000 * 1000), deadline % (1000 * 1000) };
            pthread_cond_timedwait(&sche->cond, &sche->mtx, &timeout);

            if (gquic_time_now() >= deadline) {
                gquic_coroutine_t *co = NULL;
                gquic_coroutine_timer_pop(&co, &sche->timer);

                pthread_mutex_unlock(&sche->mtx);
                co->status = GQUIC_COROUTINE_STATUS_READYING;
                gquic_coroutine_schedule_join(sche, co);
                pthread_mutex_lock(&sche->mtx);
            }
        }
    }
    co = *(gquic_coroutine_t **) GQUIC_LIST_FIRST(&sche->ready);
    gquic_list_release(GQUIC_LIST_FIRST(&sche->ready));
    gquic_coroutine_join_unref(co);
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
        gquic_coroutine_try_release(co);
        break;

    case GQUIC_COROUTINE_STATUS_WAITING:
    case GQUIC_COROUTINE_STATUS_STARTING:
        break;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
