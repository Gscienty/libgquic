/* include/tls/key_agreement.h 密钥协商模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_KEY_AGREEMENT_H
#define _LIBGQUIC_TLS_KEY_AGREEMENT_H

#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/server_key_exchange_msg.h"
#include "tls/client_key_exchange_msg.h"
#include "tls/common.h"
#include "util/str.h"
#include <openssl/pkcs12.h>
#include <stdbool.h>

typedef struct gquic_tls_key_agreement_s gquic_tls_key_agreement_t;
struct gquic_tls_key_agreement_s {
    u_int8_t type;
    void *self;
    gquic_exception_t (*generate_ser_key_exchange)(gquic_tls_server_key_exchange_msg_t *const,
                                                   void *const,
                                                   const gquic_tls_config_t *const,
                                                   PKCS12 *const,
                                                   const gquic_tls_client_hello_msg_t *const,
                                                   const gquic_tls_server_hello_msg_t *const);
    gquic_exception_t (*process_cli_key_exchange)(gquic_str_t *const,
                                                  void *const,
                                                  const gquic_tls_config_t *const,
                                                  PKCS12 *const,
                                                  const gquic_tls_client_key_exchange_msg_t *const,
                                                  u_int16_t);

    gquic_exception_t (*generate_cli_key_exchange)(gquic_str_t *const,
                                                   gquic_tls_client_key_exchange_msg_t *const,
                                                   void *const,
                                                   const gquic_tls_config_t *const,
                                                   const gquic_tls_client_hello_msg_t *const,
                                                   X509 *const);
    gquic_exception_t (*process_ser_key_exchange)(void *const,
                                                  const gquic_tls_config_t *const,
                                                  const gquic_tls_client_hello_msg_t *const,
                                                  const gquic_tls_server_hello_msg_t *const,
                                                  X509 *const,
                                                  const gquic_tls_server_key_exchange_msg_t *const);
    gquic_exception_t (*dtor) (void *const);
};

/**
 * 析构密钥协商模块
 *
 * @param key_agreement: 密钥协商模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_key_agreement_dtor(gquic_tls_key_agreement_t *const key_agreement);

/**
 * 初始化RSA的密钥协商模块
 *
 * @param key_agreement: 密钥协商模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_key_agreement_rsa_init(gquic_tls_key_agreement_t *const key_agreement);

/**
 * 初始化ECDHE密钥协商模块
 *
 * @param key_agreement: 密钥协商模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_key_agreement_ecdhe_init(gquic_tls_key_agreement_t *const key_agreement);

gquic_exception_t gquic_tls_key_agreement_ecdhe_set_version(gquic_tls_key_agreement_t *const key_agreement, const u_int16_t ver);

/**
 * 设定ECDHE密钥协商时的签名算法是否为RSA
 *
 * @param key_agreement: 密钥协商模块
 * @param is_rsa: 是否使用RSA进行签名
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_key_agreement_ecdhe_set_is_rsa(gquic_tls_key_agreement_t *const key_agreement, const bool is_rsa);

#endif
