#include "global_schedule.h"
#include <pthread.h>

gquic_coroutine_schedule_t *gquic_get_global_schedule() {
    static gquic_coroutine_schedule_t sche;
    static int inited = 0;
    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mtx);
    if (inited == 0) {
        gquic_coroutine_schedule_init(&sche);
        inited = 1;
    }
    pthread_mutex_unlock(&mtx);

    return &sche;
}

int gquic_global_schedule_join(gquic_coroutine_t **const co_storage,
                               const size_t stack_len, int (*func) (gquic_coroutine_t *const, void *const), void *args) {
    if (co_storage == NULL || func == NULL || args == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_alloc(co_storage));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_init(*co_storage));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_ctor(*co_storage, stack_len, func, args));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_schedule_join(gquic_get_global_schedule(), *co_storage));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_global_schedule_timeout_join(gquic_coroutine_t **const co_storage, const u_int64_t timeout,
                                       const size_t stack_len, int (*func) (gquic_coroutine_t *const, void *const), void *args) {
    if (co_storage == NULL || func == NULL || args == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_alloc(co_storage));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_init(*co_storage));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_ctor(*co_storage, stack_len, func, args));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_schedule_timeout_join(gquic_get_global_schedule(), *co_storage, timeout));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
