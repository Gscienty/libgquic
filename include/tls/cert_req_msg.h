#ifndef _LIBGQUIC_TLS_CERT_REQ_MSG_H
#define _LIBGQUIC_TLS_CERT_REQ_MSG_H

#include "util/str.h"
#include "util/list.h"

typedef struct gquic_tls_cert_req_msg_s gquic_tls_cert_req_msg_t;
struct gquic_tls_cert_req_msg_s {
    int has_sign_algo;
    gquic_str_t cert_types;
    gquic_list_t supported_sign_algos;
    gquic_list_t cert_auths;
};

int gquic_tls_cert_req_msg_init(gquic_tls_cert_req_msg_t *msg);
int gquic_tls_cert_req_msg_reset(gquic_tls_cert_req_msg_t *msg);
ssize_t gquic_tls_cert_req_msg_size(const gquic_tls_cert_req_msg_t *msg);
ssize_t gquic_tls_cert_req_msg_serialize(const gquic_tls_cert_req_msg_t *msg, void *buf, const size_t size);
ssize_t gquic_tls_cert_req_msg_deserialize(gquic_tls_cert_req_msg_t *msg, const void *buf, const size_t size);

#endif
