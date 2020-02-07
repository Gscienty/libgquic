#ifndef _LIBGQUIC_TLS_CERT_H
#define _LIBGQUIC_TLS_CERT_H

#include "util/str.h"
#include "util/list.h"

typedef struct gquic_tls_cert_s gquic_tls_cert_t;
struct gquic_tls_cert_s {
    gquic_list_t certs;
    gquic_str_t ocsp_staple;
    gquic_list_t scts;
};

int gquic_tls_cert_init(gquic_tls_cert_t *const msg);
int gquic_tls_cert_dtor(gquic_tls_cert_t *const msg);
ssize_t gquic_tls_cert_size(const gquic_tls_cert_t *const msg);
int gquic_tls_cert_serialize(const gquic_tls_cert_t *const msg, gquic_writer_str_t *const writer);
int gquic_tls_cert_deserialize(gquic_tls_cert_t *const msg, gquic_reader_str_t *const reader);

#endif
