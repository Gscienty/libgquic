#ifndef _LIBGQUIC_TLS_CERT_REQ_13_MSG_H
#define _LIBGQUIC_TLS_CERT_REQ_13_MSG_H

#include "util/list.h"
#include <sys/types.h>

typedef struct gquic_tls_cert_req_13_msg_s gquic_tls_cert_req_13_msg_t;
struct gquic_tls_cert_req_13_msg_s {
    int ocsp_stapling;
    int scts;
    gquic_list_t supported_sign_algo;
    gquic_list_t supported_sign_algo_cert;
    gquic_list_t cert_auths;
};

int gquic_tls_cert_req_13_msg_init(gquic_tls_cert_req_13_msg_t *msg);
int gquic_tls_cert_req_13_msg_reset(gquic_tls_cert_req_13_msg_t *msg);
ssize_t gquic_tls_cert_req_13_msg_size(const gquic_tls_cert_req_13_msg_t *msg);
ssize_t gquic_tls_cert_req_13_msg_serialize(const gquic_tls_cert_req_13_msg_t *msg, void *buf, const size_t size);
ssize_t gquic_tls_cert_req_13_msg_deserialize(gquic_tls_cert_req_13_msg_t *msg, const void *buf, const size_t size);

#endif
