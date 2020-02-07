#ifndef _LIBGQUIC_TLS_CERT_MSG_H
#define _LIBGQUIC_TLS_CERT_MSG_H

#include "tls/cert.h"

typedef struct gquic_tls_cert_msg_s gquic_tls_cert_msg_t;
struct gquic_tls_cert_msg_s {
    gquic_tls_cert_t cert;
};

gquic_tls_cert_msg_t *gquic_tls_cert_msg_alloc();
#endif
