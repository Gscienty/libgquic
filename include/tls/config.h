/* include/tls/config.h TLS 配置
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CONFIG_H
#define _LIBGQUIC_TLS_CONFIG_H

#include "util/list.h"
#include "util/rbtree.h"
#include "util/str.h"
#include "tls/client_sess_state.h"
#include "tls/cert_req_msg.h"
#include "tls/common.h"
#include "tls/cipher_suite.h"
#include <time.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <sys/types.h>
#include <stdbool.h>

/**
 * TLS回调函数
 */
typedef struct gquic_tls_record_layer_s gquic_tls_record_layer_t;
struct gquic_tls_record_layer_s {
    void *self;

    // 设定读密钥
    gquic_exception_t (*set_rkey) (void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);

    // 设定写密钥
    gquic_exception_t (*set_wkey) (void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);

    // 读取握手数据
    gquic_exception_t (*read_handshake_msg) (gquic_str_t *const, void *const);

    // 写record
    gquic_exception_t (*write_record) (size_t *const, void *const, const gquic_str_t *const);

    // 发送Alert
    gquic_exception_t (*send_alert) (void *const, const u_int8_t);
};

int gquic_tls_record_layer_init(gquic_tls_record_layer_t *const record_layer);

struct gquic_tls_config_s {
    time_t epoch;
    gquic_list_t certs;
    gquic_rbtree_t *map_certs;
    gquic_str_t cli_ca;
    gquic_str_t ser_ca;
    gquic_list_t next_protos;
    gquic_str_t ser_name;
    int insecure_skiy_verify;
    gquic_list_t cipher_suites;
    int ser_perfer_cipher_suite;
    int sess_ticket_disabled;
    u_int8_t sess_ticket_key[32];
    u_int16_t min_v;
    u_int16_t max_v;
    int dynamic_record_sizing_disabled;
    gquic_list_t sess_ticket_keys;
    int renegotiation;
    gquic_list_t curve_perfers;
    gquic_tls_client_sess_cache_t *cli_sess_cache;
    void *ext_self;
    int (*extensions) (gquic_list_t *const, void *const, const u_int8_t);
    int (*received_extensions) (void *const, const u_int8_t, gquic_list_t *const);
    int (*verify_peer_certs) (const gquic_list_t *const, const gquic_list_t *const);
    int (*get_ser_cert) (PKCS12 **const, const gquic_tls_client_hello_msg_t *const);
    int (*get_cli_cert) (PKCS12 **const, const gquic_tls_cert_req_msg_t *const);
    gquic_tls_record_layer_t alt_record;
    int enforce_next_proto_selection;
    u_int8_t cli_auth;
};

/**
 * 获取服务端证书
 *
 * @param config: TLS 配置
 * @param chello: CHELLO record
 *
 * @return cert: 证书
 * @return: exception
 */
#define GQUIC_TLS_CONFIG_GET_SER_CERT(cert, config, chello) \
    ((config)->get_ser_cert == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (config)->get_ser_cert(cert, chello))

/**
 * 获取客户端证书
 *
 * @param config: TLS 配置
 * @param cert_req: CERT_REQ record
 *
 * @return cert: 证书
 * @return: exception
 */
#define GQUIC_TLS_CONFIG_GET_CLI_CERT(cert, config, cert_req) \
    ((config)->get_cli_cert == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (config)->get_cli_cert(cert, cert_req))


/**
 * ticket
 */
typedef struct gquic_tls_ticket_key_s gquic_tls_ticket_key_t;
struct gquic_tls_ticket_key_s {
    u_int8_t name[16];
    u_int8_t aes_key[16];
    u_int8_t hmac_key[16];
};

/**
 * 初始化TLS配置
 *
 * @param cfg: TLS配置
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_config_init(gquic_tls_config_t *const cfg);

/**
 * 获取一个默认的TLS配置
 *
 * @return cfg: TLS配置
 * @return: exception
 */
gquic_exception_t gquic_tls_config_default(gquic_tls_config_t **const cfg);

/**
 * 从TLS配置中获取支持的版本
 *
 * @param ret: 存储支持的版本
 * @param cfg: 配置文件
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_config_supported_versions(gquic_list_t *ret, const gquic_tls_config_t *cfg, bool is_client);

/**
 * 获取支持的椭圆曲线加密
 *
 * @param ret: 存储支持的椭圆曲线加密
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_config_curve_preferences(gquic_list_t *ret);

/**
 * 解析ticket
 * TODO: 需要将buf和size更改为gquic_str_reader_t
 *
 * @param ticket_key: 解析后的ticket
 * @param buf: 数据buf
 * @param size: 数据长度
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ticket_key_deserialize(gquic_tls_ticket_key_t *ticket_key, const void *buf, const size_t size);

/**
 * 从签名算法中获取签名类型
 *
 * @param sigsche: 签名算法
 *
 * @return sig: 签名类型
 * @return: exception
 */
gquic_exception_t gquic_tls_sig_trans(u_int8_t *const sig, const u_int16_t sigsche);

/**
 * TODO: 待废弃
 */
gquic_exception_t gquic_tls_supported_sigalgs_tls12(gquic_list_t *const sigsches);

#endif
