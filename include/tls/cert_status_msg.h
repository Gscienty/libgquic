#ifndef _LIBGQUIC_TLS_CERT_STATUS_MSG_H
#define _LIBGQUIC_TLS_CERT_STATUS_MSG_H

#include "util/str.h"

typedef struct gquic_tls_cert_status_msg_s gquic_tls_cert_status_msg_t;
struct gquic_tls_cert_status_msg_s {
    gquic_str_t res;
};

gquic_tls_cert_status_msg_t *gquic_tls_cert_status_msg_alloc();
#endif
