#ifndef _LIBGQUIC_TLS_HANDSHAKE_SERVER_H
#define _LIBGQUIC_TLS_HANDSHAKE_SERVER_H

#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/cipher_suite.h"
#include "tls/conn.h"
#include <openssl/pkcs12.h>

typedef struct gquic_tls_handshake_server_state_s gquic_tls_handshake_server_state_t;
struct gquic_tls_handshake_server_state_s {
    gquic_tls_conn_t *conn;
    gquic_tls_client_hello_msg_t *c_hello;
    gquic_tls_server_hello_msg_t *s_hello;
    int sent_dummy_ccs;
    int using_psk;
    const gquic_tls_cipher_suite_t *suite;
    PKCS12 *cert;
    u_int16_t sigalg;
    gquic_str_t early_sec;
    gquic_str_t shared_key;
    gquic_str_t handshake_sec;
    gquic_str_t master_sec;
    gquic_str_t traffic_sec;
    gquic_tls_mac_t transport;
    gquic_str_t cli_finished;
};

int gquic_tls_handshake_server_state_init(gquic_tls_handshake_server_state_t *const ser_state);
int gquic_tls_handshake_server_state_release(gquic_tls_handshake_server_state_t *const ser_state);

int gquic_tls_server_handshake(gquic_coroutine_t *const co, gquic_tls_conn_t *const conn);
int gquic_tls_server_handshake_state_handshake(gquic_coroutine_t *const co, gquic_tls_handshake_server_state_t *const ser_state);

#endif
