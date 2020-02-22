#ifndef _LIBGQUIC_UTIL_TIMEOUT_H
#define _LIBGQUIC_UTIL_TIMEOUT_H

#include <sys/types.h>
#include <pthread.h>

typedef struct gquic_timeout_s gquic_timeout_t;
struct gquic_timeout_s {
    u_int64_t expire;
    pthread_t thread;
    void *args;
    int (*cb) (void *const);
};

#define GQUIC_TIMEOUT_CB(timeout) ((timeout)->cb((timeout->args)))

int gquic_timeout_init(gquic_timeout_t *const timeout);
gquic_timeout_t *gquic_timeout_alloc();
int gquic_timeout_start(gquic_timeout_t *const timeout);

#endif
