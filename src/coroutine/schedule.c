#include "coroutine/schedule.h"
#include "exception.h"

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
    if (sche == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&sche->mtx);

    co->link = &sche->schedule_ctx;
    co->status = GQUIC_COROUTINE_STATUS_READYING;

    pthread_mutex_unlock(&sche->mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
