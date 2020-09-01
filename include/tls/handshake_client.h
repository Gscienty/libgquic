/* include/tls/handshake_client.h 客户端握手执行规则模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H
#define _LIBGQUIC_TLS_HANDSHAKE_CLIENT_H

#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/cert_req_msg.h"
#include "tls/conn.h"
#include "tls/key_schedule.h"
#include "tls/client_sess_state.h"
#include "tls/cipher_suite.h"
#include <stdbool.h>

/**
 * 客户端握手状态
 */
typedef struct gquic_tls_handshake_client_state_s gquic_tls_handshake_client_state_t;
struct gquic_tls_handshake_client_state_s {

    // TLS连接管理模块
    gquic_tls_conn_t *conn;

    // SHELLO record
    gquic_tls_server_hello_msg_t *s_hello;

    // CHELLO record
    gquic_tls_client_hello_msg_t *c_hello;

    // ECDHE参数
    gquic_tls_ecdhe_params_t ecdhe_params;


    // TLS会话状态
    gquic_tls_client_sess_state_t *sess;

    // early secret
    gquic_str_t early_sec;

    // binder key
    gquic_str_t binder_key;


    // CERT REQ record
    gquic_tls_cert_req_msg_t *cert_req;

    // 是否使用PSK（0RTT）
    bool using_psk;
    // change cipher spec
    bool sent_dummy_ccs;

    // 加密套件
    const gquic_tls_cipher_suite_t *suite;

    // 对通信双方传递的信息进行hash认证
    gquic_tls_mac_t transport;

    // master secret
    gquic_str_t master_sec;

    // traffic secret
    gquic_str_t traffic_sec;


    // 客户端递交给服务器的证书
    PKCS12 *cert;
};

/**
 * 初始化客户端握手过程管理模块
 *
 * @param cli_state: 客户端握手状态
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_handshake_client_state_init(gquic_tls_handshake_client_state_t *const cli_state);

/**
 * 析构客户端握手过程
 *
 * @param cli_state: 客户端握手状态
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_handshake_client_state_dtor(gquic_tls_handshake_client_state_t *const cli_state);

/**
 * 根据客户端握手状态初始化CHELLO record
 *
 * @param params: ECDHE参数
 * @param conn: TLS连接管理
 * @return msg: CHELLO record
 */
gquic_exception_t gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t **const msg,
                                                        gquic_tls_ecdhe_params_t *const params, const gquic_tls_conn_t *conn);

/**
 * 执行客户端握手过程
 *
 * @param conn: TLS连接管理
 * @return: exception
 */
gquic_exception_t gquic_tls_client_handshake(gquic_tls_conn_t *const conn);

/**
 * 在客户端握手状态下执行握手过程
 *
 * @param cli_state: 客户端握手状态
 * @return: exception
 */
gquic_exception_t gquic_tls_client_handshake_state_handshake(gquic_tls_handshake_client_state_t *const cli_state);

#endif
