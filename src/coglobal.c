#include "coglobal.h"
#include "util/malloc.h"
#include "exception.h"
#include "liteco.h"
#include <stdbool.h>
#include <pthread.h>

static int __GQUIC_CO_DEFAULT_STACK__ = 128 * 1024;
static liteco_runtime_t __GQUIC_RUNTIMES__;
typedef struct gquic_coroutine_s gquic_coroutine_t;
struct gquic_coroutine_s {
    liteco_coroutine_t co;
    int (*fn) (void *const);
    void *args;
    bool auto_finished;
    bool lock_machine;
};
static int gquic_coroutine_func(void *const);
static int gquic_coroutine_finished(liteco_coroutine_t *const);
static bool inited = false;
static int gquic_coroutine_create(gquic_coroutine_t **const, int (*)(void *const), void *const);

__thread liteco_runtime_t *__GQUIC_CURR_RUNTIME__ = NULL;

static liteco_runtime_t *gquic_coglobal_select_runtime() {
    if (inited == false) {
        liteco_runtime_init(&__GQUIC_RUNTIMES__);
        inited = true;
    }

    return &__GQUIC_RUNTIMES__;
}

int gquic_coglobal_thread_init(int ith) {
    (void) ith;
    if (inited == false) {
        liteco_runtime_init(&__GQUIC_RUNTIMES__);
        inited = true;
    }

    __GQUIC_CURR_RUNTIME__ = &__GQUIC_RUNTIMES__ + ith;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_execute(int (*func) (void *const), void *const args) {
    gquic_coroutine_t *co = NULL;
    if (func == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_create(&co, func, args));

    liteco_runtime_join(gquic_coglobal_select_runtime(), &co->co);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_currmachine_execute(liteco_coroutine_t **const co_storage, int (*func) (void *const), void *const args) {
    gquic_coroutine_t *co = NULL;
    if (func == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_create(&co, func, args));
    co->lock_machine = true;
    if (co_storage != NULL) {
        *co_storage = &co->co;
    }

    liteco_runtime_join(__GQUIC_CURR_RUNTIME__, &co->co);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_delay_execute(const u_int64_t timeout, int (*func) (void *const), void *const args) {
    gquic_coroutine_t *co = NULL;
    if (func == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_create(&co, func, args));

    liteco_runtime_delay_join(gquic_coglobal_select_runtime(), timeout, &co->co);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_channel_recv(const void **const event, const liteco_channel_t **const recv_channel,
                                liteco_channel_t *const *channels, const u_int64_t timeout) {
    if (channels == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    int result = liteco_channel_recv(event, recv_channel,
                                     ((gquic_coroutine_t *) __CURR_CO__->args)->lock_machine
                                     ? __GQUIC_CURR_RUNTIME__
                                     : gquic_coglobal_select_runtime(),
                                     channels, timeout);

    // spec tips: ignore closed channel exception
    switch (result) {
    case LITECO_TIMEOUT:
        return GQUIC_EXCEPTION_TIMEOUT;
    case LITECO_CLOSED:
        return GQUIC_EXCEPTION_CLOSED;
    default:
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
}

static int gquic_coroutine_func(void *const args) {
    GQUIC_PROCESS_DONE(((gquic_coroutine_t *) args)->fn(((gquic_coroutine_t *) args)->args));
}

static int gquic_coroutine_finished(liteco_coroutine_t *const co) {
    if (((gquic_coroutine_t *) co->args)->auto_finished) {
        gquic_free(co->stack);
        gquic_free(co->args);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_schedule() {
    liteco_runtime_schedule(__GQUIC_CURR_RUNTIME__);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_schedule_until_completed(const liteco_coroutine_t *const co) {
    int exception = GQUIC_SUCCESS;
    if (co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ((gquic_coroutine_t *) co->args)->auto_finished = false;

    while (co->status != LITECO_TERMINATE) {
        gquic_coglobal_schedule();
    }
    GQUIC_EXCEPTION_ASSIGN(exception, co->result);

    ((gquic_coroutine_t *) co->args)->auto_finished = true;
    gquic_coroutine_finished((liteco_coroutine_t *) co);

    GQUIC_PROCESS_DONE(exception);
}

static int gquic_coroutine_create(gquic_coroutine_t **const co_storage, int (*func)(void *const), void *const args) {
    void *stack = NULL;
    if (co_storage == NULL || func == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT((void **) co_storage, gquic_coroutine_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc(&stack, __GQUIC_CO_DEFAULT_STACK__));
    (*co_storage)->fn = func;
    (*co_storage)->args = args;
    (*co_storage)->auto_finished = true;
    (*co_storage)->lock_machine = false;
    liteco_create(&(*co_storage)->co, stack, __GQUIC_CO_DEFAULT_STACK__, gquic_coroutine_func, *co_storage, gquic_coroutine_finished);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_yield() {
    liteco_yield();

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
