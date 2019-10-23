#ifndef _LIBGQUIC_TLS_CONN_H
#define _LIBGQUIC_TLS_CONN_H

#include "tls/common.h"
#include "tls/config.h"
#include "tls/client_sess_state.h"
#include "tls/client_hello_msg.h"
#include "util/str.h"
#include "util/list.h"
#include "net/addr.h"
#include <sys/types.h>

typedef struct gquic_tls_conn_s gquic_tls_conn_t;
struct gquic_tls_conn_s {
    const gquic_net_addr_t *addr;
    gquic_tls_config_t *cfg;
    int is_client;
    u_int32_t handshake_status;
    u_int16_t ver;
    int handshakes;
    u_int16_t cipher_suite;
    gquic_str_t ocsp_resp;
    gquic_list_t scts;
};

int gquic_tls_conn_init(gquic_tls_conn_t *const conn,
                        const gquic_net_addr_t *const addr,
                        gquic_tls_config_t *const cfg);

int gquic_tls_conn_load_session(const gquic_tls_conn_t *const conn,
                                gquic_str_t *const cache_key,
                                gquic_tls_client_sess_state_t **const sess,
                                gquic_str_t *const early_sec,
                                gquic_str_t *const binder_key,
                                gquic_tls_client_hello_msg_t *const hello);

#endif
