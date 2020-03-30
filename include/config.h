#ifndef _LIBGQUIC_CONFIG_H
#define _LIBGQUIC_CONFIG_H

#include <sys/types.h>
#include "util/list.h"
#include "util/str.h"
#include "tls/config.h"
#include "tls/client_hello_msg.h"
#include "tls/cert_req_msg.h"
#include <openssl/pkcs12.h>

typedef struct gquic_config_s gquic_config_t;
struct gquic_config_s {
    gquic_list_t versions;
    int conn_id_len;
    u_int64_t handshake_timeout;
    u_int64_t max_idle_timeout;
    u_int64_t max_recv_stream_flow_ctrl_wnd;
    u_int64_t max_recv_conn_flow_ctrl_wnd;
    u_int64_t max_incoming_uni_streams;
    u_int64_t max_incoming_streams;
    gquic_str_t stateless_reset_key;
    int keep_alive;

    gquic_list_t next_protos;
    int enforce_next_proto_selections;
    int (*verify_peer_certs) (const gquic_list_t *const, const gquic_list_t *const);
    int (*get_ser_cert) (PKCS12 **const, const gquic_tls_client_hello_msg_t *const);
    int (*get_cli_cert) (PKCS12 **const, const gquic_tls_cert_req_msg_t *const);
    gquic_str_t ser_name;
    int insecure_skiy_verify;
    // TODO combine src/tls/handshake_server.c line: 220
    gquic_list_t cipher_suites;
    int ser_perfer_cipher_suite; 
};

int gquic_config_init(gquic_config_t *const config);

#endif
