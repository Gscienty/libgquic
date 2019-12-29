#ifndef _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H
#define _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H

#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/cert_req_13_msg.h"
#include "tls/conn.h"
#include "tls/key_schedule.h"
#include "tls/client_sess_state.h"
#include "tls/cipher_suite.h"

typedef struct gquic_tls_handshake_client_state_s gquic_tls_handshake_client_state_t;
struct gquic_tls_handshake_client_state_s {
    gquic_tls_conn_t *conn;
    gquic_tls_server_hello_msg_t *s_hello;
    gquic_tls_client_hello_msg_t *c_hello;
    gquic_tls_ecdhe_params_t ecdhe_params;

    gquic_tls_client_sess_state_t *sess;
    gquic_str_t early_sec;
    gquic_str_t binder_key;

    gquic_tls_cert_req_13_msg_t *cert_req;
    int using_psk;
    int sent_dummy_ccs;
    const gquic_tls_cipher_suite_t *suite;
    gquic_tls_mac_t transport;
    gquic_str_t master_sec;
    gquic_str_t traffic_sec;
};

int gquic_tls_handshake_client_state_init(gquic_tls_handshake_client_state_t *const cli_state);
int gquic_tls_handshake_client_state_dtor(gquic_tls_handshake_client_state_t *const cli_state);

int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t **const msg,
                                          gquic_tls_ecdhe_params_t *const params,
                                          const gquic_tls_conn_t *conn);

int gquic_tls_client_handshake(gquic_tls_conn_t *const conn);
int gquic_tls_client_handshake_state_handshake(gquic_tls_handshake_client_state_t *const cli_state);

#endif
