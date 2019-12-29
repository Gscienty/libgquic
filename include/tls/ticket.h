#ifndef _LIBGQUIC_TLS_TICKET_H
#define _LIBGQUIC_TLS_TICKET_H

#include <sys/types.h>
#include "util/str.h"
#include "tls/cert.h"

typedef struct gquic_tls_sess_state_s gquic_tls_sess_state_t;
struct gquic_tls_sess_state_s {
    u_int16_t cipher_suite;
    u_int64_t create_at;
    gquic_str_t resumption_sec;
    gquic_tls_cert_t cert;
};

int gquic_tls_sess_state_init(gquic_tls_sess_state_t *const state);
int gquic_tls_sess_state_dtor(gquic_tls_sess_state_t *const state);
ssize_t gquic_tls_sess_state_size(const gquic_tls_sess_state_t *const state);
ssize_t gquic_tls_sess_state_serialize(const gquic_tls_sess_state_t *const state, void *const buf, const size_t size);
ssize_t gquic_tls_sess_state_deserialize(gquic_tls_sess_state_t *const state, const void *const buf, const size_t size);

#endif
