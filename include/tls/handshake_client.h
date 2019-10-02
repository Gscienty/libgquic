#ifndef _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H
#define _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H

#include "tls/client_hello_msg.h"
#include "tls/conn.h"

int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t *msg, const gquic_tls_conn_t *conn);

#endif
