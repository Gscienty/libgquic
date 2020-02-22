#include "util/timeout.h"
#include <stddef.h>
#include <malloc.h>
#include <sys/time.h>

static void *__thread_runner(void *const);

gquic_timeout_t *gquic_timeout_alloc() {
    gquic_timeout_t *ret = malloc(sizeof(gquic_timeout_t));
    if (ret == NULL) {
        return NULL;
    }
    gquic_timeout_init(ret);
    return ret;
}

int gquic_timeout_init(gquic_timeout_t *const timeout) {
    if (timeout == NULL) {
        return -1;
    }
    timeout->expire = 0;
    timeout->args = NULL;
    timeout->cb = NULL;

    return 0;
}

int gquic_timeout_start(gquic_timeout_t *const timeout) {
    if (timeout == NULL) {
        return -1;
    }
    pthread_create(&timeout->thread, NULL, __thread_runner, timeout);

    return 0;
}

static void *__thread_runner(void *const timeout_) {
    gquic_timeout_t *const timeout = timeout_;
    struct timespec spec;
    if (timeout == NULL) {
        return NULL;
    }
    spec.tv_sec = timeout->expire / (1000 * 1000);
    spec.tv_nsec = timeout->expire % (1000 * 1000);

    nanosleep(&spec, NULL);
    GQUIC_TIMEOUT_CB(timeout);

    free(timeout);
    return NULL;
}
