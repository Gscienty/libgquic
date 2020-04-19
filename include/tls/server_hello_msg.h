#ifndef _LIBGQUIC_TLS_SERVER_HELLO_MSG_H
#define _LIBGQUIC_TLS_SERVER_HELLO_MSG_H

#include <sys/types.h>
#include "util/list.h"
#include "util/str.h"
#include "tls/common.h"

typedef struct gquic_tls_server_hello_msg_s gquic_tls_server_hello_msg_t;
struct gquic_tls_server_hello_msg_s {
    u_int16_t vers;
    gquic_str_t random;
    gquic_str_t sess_id;
    u_int16_t cipher_suite;
    u_int16_t compression_method;
    int next_proto_neg;
    gquic_list_t next_protos;
    int ocsp_stapling;
    int ticket_supported;
    int secure_regegotiation_supported;
    gquic_str_t secure_regegotation;
    gquic_str_t alpn_proto;
    gquic_list_t scts;
    u_int16_t supported_version;
    gquic_tls_key_share_t ser_share;
    int selected_identity_persent;
    u_int16_t selected_identity;

    gquic_str_t cookie;
    u_int16_t selected_group;
};

int gquic_tls_server_hello_msg_alloc(gquic_tls_server_hello_msg_t **const result);
#endif
