/* include/tls/server_hello_msg.h TLS SERVER_HELLO record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_SERVER_HELLO_MSG_H
#define _LIBGQUIC_TLS_SERVER_HELLO_MSG_H

#include "util/list.h"
#include "util/str.h"
#include "tls/common.h"
#include "exception.h"
#include <sys/types.h>

/**
 * SERVER_HELLO record
 */
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

/**
 * 申请一个SERVER_HELLO recrod
 *
 * @return result: SERVER_HELLO record
 * @return: exception
 */
gquic_exception_t gquic_tls_server_hello_msg_alloc(gquic_tls_server_hello_msg_t **const result);
#endif
