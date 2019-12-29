#ifndef _LIBGQUIC_TLS_CERT_13_MSG_H
#define _LBIGQUIC_TLS_CERT_13_MSG_H

#include "tls/cert.h"

typedef struct gquic_tls_cert_13_msg_s gquic_tls_cert_13_msg_t;
struct gquic_tls_cert_13_msg_s {
    gquic_tls_cert_t cert;
};

gquic_tls_cert_13_msg_t *gquic_tls_cert_13_msg_alloc();
#endif
