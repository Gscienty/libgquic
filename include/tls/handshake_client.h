#ifndef _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H
#define _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H

#include "tls/client_hello_msg.h"
#include "tls/conn.h"
#include "tls/key_schedule.h"

typedef struct gquic_tls_handshake_client_state_s gquic_tls_handshake_client_state_t;
struct gquic_tls_handshake_client_state_s {
    
};

int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t *msg, const gquic_tls_conn_t *conn);

int gquic_tls_handshake_client_hello_edch_params_init(gquic_tls_ecdhe_params_t *ret, gquic_tls_client_hello_msg_t *msg);

#endif
