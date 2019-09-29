#ifndef _LIBGQUIC_TLS_CERT_13_MSG_H
#define _LBIGQUIC_TLS_CERT_13_MSG_H

#include "tls/cert.h"

typedef struct gquic_tls_cert_13_msg_s gquic_tls_cert_13_msg_t;
struct gquic_tls_cert_13_msg_s {
    gquic_tls_cert_t cert;
};

int gquic_tls_cert_13_msg_init(gquic_tls_cert_13_msg_t *msg);
int gquic_tls_cert_13_msg_reset(gquic_tls_cert_13_msg_t *msg);
ssize_t gquic_tls_cert_13_msg_size(const gquic_tls_cert_13_msg_t *msg);
ssize_t gquic_tls_cert_13_msg_serialize(const gquic_tls_cert_13_msg_t *msg, void *buf, const size_t size);
ssize_t gquic_tls_cert_13_msg_deserialize(gquic_tls_cert_13_msg_t *msg, const void *buf, const size_t size);

#endif
