#include "coglobal.h"
#include "util/malloc.h"
#include "exception.h"
#include "liteco.h"
#include <stdbool.h>
#include <pthread.h>

static int __GQUIC_CO_DEFAULT_STACK__ = 128 * 1024;
static liteco_machine_t __GQUIC_MACHINES__;
typedef struct gquic_coroutine_s gquic_coroutine_t;
struct gquic_coroutine_s {
    liteco_coroutine_t co;
    int (*fn) (void *const);
    void *args;
};
static int gquic_coroutine_func(liteco_coroutine_t *const, void *const);
static int gquic_coroutine_finished(liteco_coroutine_t *const);
static bool inited = false;

__thread liteco_machine_t *__GQUIC_CURR_MACHINE__ = NULL;

static liteco_machine_t *gquic_coglobal_select_machine() {
    if (inited == false) {
        liteco_machine_init(&__GQUIC_MACHINES__);
        inited = true;
    }

    return &__GQUIC_MACHINES__;
}

int gquic_coglobal_thread_init(int ith) {
    (void) ith;
    if (inited == false) {
        liteco_machine_init(&__GQUIC_MACHINES__);
        inited = true;
    }

    __GQUIC_CURR_MACHINE__ = &__GQUIC_MACHINES__ + ith;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_execute(int (*func) (void *const), void *args) {
    gquic_coroutine_t *co = NULL;
    void *stack = NULL;
    if (func == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT((void **) &co, gquic_coroutine_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc(&stack, __GQUIC_CO_DEFAULT_STACK__));
    co->fn = func;
    co->args = args;
    liteco_create(&co->co, stack, __GQUIC_CO_DEFAULT_STACK__, gquic_coroutine_func, co, gquic_coroutine_finished);

    liteco_machine_join(gquic_coglobal_select_machine(), &co->co);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_channel_recv(const void **const event, const liteco_channel_t **const recv_channel,
                                liteco_channel_t *const *channels, const u_int64_t timeout) {
    if (channels == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    liteco_channel_recv(event, recv_channel, gquic_coglobal_select_machine(), __CURR_CO__, channels, timeout);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_coroutine_func(liteco_coroutine_t *const co, void *const args) {
    (void) co;

    GQUIC_PROCESS_DONE(((gquic_coroutine_t *) args)->fn(((gquic_coroutine_t *) args)->args));
}

static int gquic_coroutine_finished(liteco_coroutine_t *const co) {
    gquic_free(((gquic_coroutine_t *) co->args)->co.stack);
    gquic_free(co->args);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coglobal_schedule() {
    liteco_machine_schedule(__GQUIC_CURR_MACHINE__);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

