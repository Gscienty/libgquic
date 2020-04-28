#include "coroutine/coroutine.h"
#include "coroutine/schedule.h"
#include "exception.h"
#include <malloc.h>
#include <stddef.h>

int gquic_coroutine_alloc(gquic_coroutine_t **co_storage) {
    if (co_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *co_storage = malloc(sizeof(gquic_coroutine_t));
    if (*co_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_release(gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coroutine_dtor(co);
    free(co);


    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_try_release(gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (co->joined_times == 0) {
        GQUIC_PROCESS_DONE(gquic_coroutine_release(co));
    }
    else if (co->joined_times < 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_join_ref(gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&co->mtx);
    co->joined_times++;
    pthread_mutex_unlock(&co->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_join_unref(gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&co->mtx);
    co->joined_times--;
    pthread_mutex_unlock(&co->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_init(gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    co->cb.args = NULL;
    co->cb.func = NULL;
    co->joined_times = 0;
    pthread_mutex_init(&co->mtx, NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_ctor(gquic_coroutine_t *const co, size_t stack_size, int (*func) (gquic_coroutine_t *const, void *const), void *args) {
    if (co == NULL || func == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    co->cb.args = args;
    co->cb.func = func;
    co->ctx.link = NULL;
    // TODO stack pool
    co->ctx.stack.stack_pointer = malloc(stack_size);
    co->ctx.stack.stack_size = stack_size;
    co->status = GQUIC_COROUTINE_STATUS_STARTING;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_dtor(gquic_coroutine_t *const co) {
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (co->ctx.stack.stack_pointer != NULL) {
        free(co->ctx.stack.stack_pointer);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_yield(gquic_coroutine_t *const co) {
    gquic_coroutine_schedule_t *sche = NULL;
    if (co == NULL || co->ctx.link == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (co->status == GQUIC_COROUTINE_STATUS_RUNNING) {
        co->status = GQUIC_COROUTINE_STATUS_READYING;
    }
    sche = (gquic_coroutine_schedule_t *) (((void *) co->ctx.link) - ((void *) &((gquic_coroutine_schedule_t *) 0)->schedule_ctx));
    gquic_coroutine_schedule_yield(sche, co);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
