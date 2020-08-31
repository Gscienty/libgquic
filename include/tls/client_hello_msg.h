/* include/tls/client_hello_msg.h TLS CHELLO record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CLIENT_HELLO_MSG_H
#define _LIBGQUIC_TLS_CLIENT_HELLO_MSG_H

#include <sys/types.h>
#include "util/list.h"
#include "util/str.h"
#include "exception.h"

/**
 * TLS CHELLO record
 */
typedef struct gquic_tls_client_hello_msg_s gquic_tls_client_hello_msg_t;
struct gquic_tls_client_hello_msg_s {
    u_int16_t vers;
    gquic_str_t random;
    gquic_str_t sess_id;
    gquic_list_t cipher_suites;
    gquic_str_t compression_methods;
    int next_proto_neg;
    gquic_str_t ser_name;
    int ocsp_stapling;
    gquic_list_t supported_curves;
    gquic_str_t supported_points;
    int ticket_supported;
    gquic_str_t sess_ticket;
    gquic_list_t supported_sign_algos;
    gquic_list_t supported_sign_algos_cert;
    int secure_regegotiation_supported;
    gquic_str_t secure_regegotation;
    gquic_list_t alpn_protos;
    int scts;
    gquic_list_t supported_versions;
    gquic_str_t cookie;
    gquic_list_t key_shares;
    int early_data;
    gquic_str_t psk_modes;
    gquic_list_t psk_identities;
    gquic_list_t psk_binders;
    gquic_list_t extensions;
};

/**
 * 申请一个CHELLO record
 *
 * @return result: CHELLO record
 * @return: exception
 */
gquic_exception_t gquic_tls_client_hello_msg_alloc(gquic_tls_client_hello_msg_t **const result);

/**
 * 获取移除掉binders的CHELLO record长度
 *
 * @param msg: CHELLO record
 *
 * @return: 长度
 */
ssize_t gquic_tls_client_hello_msg_size_without_binders(gquic_tls_client_hello_msg_t *msg);

#endif

