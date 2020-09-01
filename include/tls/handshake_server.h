/* include/tls/handshake_server.h 服务器握手执行规则模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_HANDSHAKE_SERVER_H
#define _LIBGQUIC_TLS_HANDSHAKE_SERVER_H

#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/cipher_suite.h"
#include "tls/conn.h"
#include <openssl/pkcs12.h>

/**
 * 服务端握手状态
 */
typedef struct gquic_tls_handshake_server_state_s gquic_tls_handshake_server_state_t;
struct gquic_tls_handshake_server_state_s {

    // TLS连接管理模块
    gquic_tls_conn_t *conn;

    // CHELLO record
    gquic_tls_client_hello_msg_t *c_hello;

    // SHELLO record
    gquic_tls_server_hello_msg_t *s_hello;

    // change cipher spec
    bool sent_dummy_ccs;
    // 是否使用PSK（0RTT）
    bool using_psk;
    
    // 加密套件
    const gquic_tls_cipher_suite_t *suite;

    // 服务端证书
    PKCS12 *cert;

    // 签名算法
    u_int16_t sigalg;

    // early secret
    gquic_str_t early_sec;

    // shared key
    gquic_str_t shared_key;

    // handshake secret
    gquic_str_t handshake_sec;

    // master secret
    gquic_str_t master_sec;

    // traffic secret
    gquic_str_t traffic_sec;

    // 对通信双方传递的信息进行hash认证
    gquic_tls_mac_t transport;

    // CLIENT FINISHED hash
    gquic_str_t cli_finished;
};

/**
 * 初始化服务端握手状态
 *
 * @param ser_state: 服务端握手状态
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_handshake_server_state_init(gquic_tls_handshake_server_state_t *const ser_state);

/**
 * 释放服务端握手状态
 *
 * @param ser_state: 服务端握手状态
 *
 * @@return: exception
 */
gquic_exception_t gquic_tls_handshake_server_state_release(gquic_tls_handshake_server_state_t *const ser_state);

/**
 * 执行服务端握手过程
 *
 * @param conn: TLS连接管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_server_handshake(gquic_tls_conn_t *const conn);

/**
 * 在设定好的服务端状态下执行握手过程
 *
 * @param ser_state: 服务端握手状态
 * 
 * @return: exception
 */
gquic_exception_t gquic_tls_server_handshake_state_handshake(gquic_tls_handshake_server_state_t *const ser_state);

#endif
