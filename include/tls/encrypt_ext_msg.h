#ifndef _LIBGQUIC_TLS_ENCRYPT_EXT_MSG_H
#define _LIBGQUIC_TLS_ENCRYPT_EXT_MSG_H

#include "util/str.h"
#include "util/list.h"

typedef struct gquic_tls_encrypt_ext_msg_s gquic_tls_encrypt_ext_msg_t;
struct gquic_tls_encrypt_ext_msg_s {
    gquic_str_t alpn_proto;
    gquic_list_t addition_exts;
};

gquic_tls_encrypt_ext_msg_t *gquic_tls_encrypt_ext_msg_alloc();
#endif
