#ifndef _LIBGQUIC_TLS_FINISHED_MSG_H
#define _LIBGQUIC_TLS_FINISHED_MSG_H

#include "util/str.h"

typedef struct gquic_tls_finished_msg_s gquic_tls_finished_msg_t;
struct gquic_tls_finished_msg_s {
    gquic_str_t verify;
};

gquic_tls_finished_msg_t *gquic_tls_finished_msg_alloc();
#endif
