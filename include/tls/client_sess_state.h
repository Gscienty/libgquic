#ifndef _LIBGQUIC_TLS_CLIENT_SESS_STATE_H
#define _LIBGQUIC_TLS_CLIENT_SESS_STATE_H

#include "util/str.h"
#include "util/list.h"
#include <sys/types.h>
#include <sys/time.h>

typedef struct gquic_tls_client_sess_state_s gquic_tls_client_sess_state_t;
struct gquic_tls_client_sess_state_s {
    gquic_str_t sess_ticket;
    u_int16_t ver;
    u_int16_t cipher_suite;
    gquic_str_t master_sec;
    gquic_list_t ser_certs;
    gquic_list_t verified_chain;
    time_t recv_at;

    gquic_str_t nonce;
    time_t use_by;
    u_int32_t age_add;
};

typedef int (*gquic_tls_client_sess_cache_get_fptr) (gquic_tls_client_sess_state_t **const state, const gquic_str_t *const sess_key);
typedef int (*gquic_tls_client_sess_cache_put_fptr) (const gquic_str_t *const sess_key, const gquic_tls_client_sess_state_t *const state);

typedef struct gquic_tls_client_sess_cache_s gquic_tls_client_sess_cache_t;
struct gquic_tls_client_sess_cache_s {
    gquic_tls_client_sess_cache_get_fptr get_fptr;
    gquic_tls_client_sess_cache_put_fptr put_fptr;
};

#endif
