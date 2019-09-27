#ifndef _LIBGQUIC_TLS_ENCRYPT_EXT_MSG_H
#define _LIBGQUIC_TLS_ENCRYPT_EXT_MSG_H

#include "util/str.h"
#include "util/list.h"

typedef struct gquic_tls_encrypt_ext_msg_s gquic_tls_encrypt_ext_msg_t;
struct gquic_tls_encrypt_ext_msg_s {
    gquic_str_t alpn_proto;
    gquic_list_t addition_exts;
};

int gquic_tls_encrypt_ext_msg_init(gquic_tls_encrypt_ext_msg_t *msg);
int gquic_tls_encrypt_ext_msg_reset(gquic_tls_encrypt_ext_msg_t *msg);
ssize_t gquic_tls_encrypt_ext_msg_size(const gquic_tls_encrypt_ext_msg_t *msg);
ssize_t gquic_tls_encrypt_ext_msg_serialize(const gquic_tls_encrypt_ext_msg_t *msg, void *buf, const size_t size);
ssize_t gquic_tls_encrypt_ext_msg_deserialize(gquic_tls_encrypt_ext_msg_t *msg, const void *buf, const size_t size);

#endif
