#ifndef _LIBGQUIC_COROUTINE_H
#define _LIBGQUIC_COROUTINE_H

#include "coroutine/context.h"

#define GQUIC_COROUTINE_STATUS_STARTING 0x00
#define GQUIC_COROUTINE_STATUS_READYING 0x01
#define GQUIC_COROUTINE_STATUS_RUNNING 0x02
#define GQUIC_COROUTINE_STATUS_WAITING 0x03
#define GQUIC_COROUTINE_STATUS_ENDING 0x04

typedef struct gquic_coroutine_s gquic_coroutine_t;
struct gquic_coroutine_s {
    gquic_couroutine_context_t *link;
    gquic_couroutine_context_t ctx;
    int status;
};

#endif
