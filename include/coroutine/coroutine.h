#ifndef _LIBGQUIC_COROUTINE_H
#define _LIBGQUIC_COROUTINE_H

#include "coroutine/context.h"

#define GQUIC_COROUTINE_STATUS_STARTING 0x01
#define GQUIC_COROUTINE_STATUS_READYING 0x02
#define GQUIC_COROUTINE_STATUS_RUNNING 0x03
#define GQUIC_COROUTINE_STATUS_WAITING 0x04
#define GQUIC_COROUTINE_STATUS_TERMIATE 0x05

typedef struct gquic_coroutine_s gquic_coroutine_t;
struct gquic_coroutine_s {
    gquic_couroutine_context_t ctx;

    int status;

    struct {
        void *args;
        int (*func) (gquic_coroutine_t *const, void *const);
    } cb;
};

#define GQUIC_COROUTINE_CALL(co) ((co)->cb.func((co), (co)->cb.args))

int gquic_coroutine_alloc(gquic_coroutine_t **co_storage);
int gquic_coroutine_release(gquic_coroutine_t *const co);
int gquic_coroutine_init(gquic_coroutine_t *const co);
int gquic_coroutine_ctor(gquic_coroutine_t *const co, size_t stack_size, int (*func) (gquic_coroutine_t *const, void *const), void *args);
int gquic_coroutine_dtor(gquic_coroutine_t *const co);
int gquic_coroutine_yield(gquic_coroutine_t *const co);

#endif
