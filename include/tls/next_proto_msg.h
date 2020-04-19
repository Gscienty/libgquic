#ifndef _LIBGQUIC_TLS_NEXT_PROTO_MSG_H
#define _LIBGQUIC_TLS_NEXT_PROTO_MSG_H

#include "util/str.h"

typedef struct gquic_tls_next_proto_msg_s gquic_tls_next_proto_msg_t;
struct gquic_tls_next_proto_msg_s {
    gquic_str_t verify;
};

int gquic_tls_next_proto_msg_alloc(gquic_tls_next_proto_msg_t **const result);
#endif
