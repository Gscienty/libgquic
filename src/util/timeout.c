#include "util/timeout.h"
#include "exception.h"
#include <stddef.h>
#include <malloc.h>

typedef struct gquic_timeout_s gquic_timeout_t;
struct gquic_timeout_s {
    gquic_time_t expire;
    pthread_t thread;
    void *args;
    int (*cb) (void *const);
};

#define GQUIC_TIMEOUT_CB(timeout) ((timeout)->cb((timeout->args)))

static void *__thread_runner(void *const);
static int gquic_timeout_init(gquic_timeout_t *const timeout);
static gquic_timeout_t *gquic_timeout_alloc();

static gquic_timeout_t *gquic_timeout_alloc() {
    gquic_timeout_t *ret = malloc(sizeof(gquic_timeout_t));
    if (ret == NULL) {
        return NULL;
    }
    gquic_timeout_init(ret);
    return ret;
}

static int gquic_timeout_init(gquic_timeout_t *const timeout) {
    if (timeout == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    timeout->expire = 0;
    timeout->args = NULL;
    timeout->cb = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_timeout_start(const gquic_time_t expire, int (*cb) (void *const), void *const args) {
    gquic_timeout_t *timeout = NULL;
    if (cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((timeout = gquic_timeout_alloc()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    timeout->expire = expire;
    timeout->cb = cb;
    timeout->args = args;
    pthread_create(&timeout->thread, NULL, __thread_runner, timeout);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static void *__thread_runner(void *const timeout_) {
    gquic_timeout_t *const timeout = timeout_;
    struct timespec spec;
    if (timeout == NULL) {
        return NULL;
    }
    spec.tv_sec = timeout->expire / (1000 * 1000);
    spec.tv_nsec = (timeout->expire % (1000 * 1000)) * 1000;

    nanosleep(&spec, NULL);
    GQUIC_TIMEOUT_CB(timeout);

    free(timeout);
    return NULL;
}
