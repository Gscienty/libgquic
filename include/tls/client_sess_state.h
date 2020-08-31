/* include/tls/client_key_exchange_msg.h TLS 客户端状态
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CLIENT_SESS_STATE_H
#define _LIBGQUIC_TLS_CLIENT_SESS_STATE_H

#include "util/str.h"
#include "util/list.h"
#include "exception.h"
#include <sys/types.h>
#include <sys/time.h>

/**
 * TLS 客户端状态
 */
typedef struct gquic_tls_client_sess_state_s gquic_tls_client_sess_state_t;
struct gquic_tls_client_sess_state_s {
    // ticket
    gquic_str_t sess_ticket;

    // TLS版本
    u_int16_t ver;

    // 加密套件
    u_int16_t cipher_suite;

    // master secret
    gquic_str_t master_sec;

    // 服务端证书
    gquic_list_t ser_certs; /* X509 * */

    // 认证链
    gquic_list_t verified_chains;

    // 接收时间
    struct timeval received_at;

    // 单次值
    gquic_str_t nonce;

    time_t use_by;

    u_int32_t age_add;
};

typedef struct gquic_tls_client_sess_cache_s gquic_tls_client_sess_cache_t;
struct gquic_tls_client_sess_cache_s {
    void *self;
    gquic_exception_t (*get) (gquic_tls_client_sess_state_t **const, void *const self, const gquic_str_t *const);
    gquic_exception_t (*put) (void *const self, const gquic_str_t *const, const gquic_tls_client_sess_state_t *const);
};

#endif
