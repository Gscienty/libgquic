/* include/tls/conn.h TLS 连接管理
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CONN_H
#define _LIBGQUIC_TLS_CONN_H

#include "tls/common.h"
#include "tls/config.h"
#include "tls/client_sess_state.h"
#include "tls/client_hello_msg.h"
#include "tls/cipher_suite.h"
#include "tls/cert.h"
#include "util/str.h"
#include "util/list.h"
#include "net/addr.h"
#include <sys/types.h>
#include <stdatomic.h>
#include <semaphore.h>

/**
 * TLS 连接管理
 */
typedef struct gquic_tls_half_conn_s gquic_tls_half_conn_t;
struct gquic_tls_half_conn_s {

    // 版本
    u_int16_t ver;

    // 加密套件
    gquic_tls_suite_t suite;

    // seq
    gquic_str_t seq;

    // addata
    gquic_str_t addata;

    // 下一个加密套件
    gquic_tls_suite_t next_suite;

    // traffic secret
    gquic_str_t traffic_sec;

    // 设定加密密钥回调函数
    void *set_key_self;
    gquic_exception_t (*set_key) (void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
};

/**
 * 初始化 TLS 连接管理（读/写某端）
 *
 * @param half_conn: TLS连接管理
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_half_conn_init(gquic_tls_half_conn_t *const half_conn);

/**
 * useless
 */
gquic_exception_t gquic_tls_half_conn_encrypt(gquic_str_t *const ret,
                                              gquic_tls_half_conn_t *const half_conn,
                                              const gquic_str_t *const record, const gquic_str_t *const payload);

/**
 * useless
 */
gquic_exception_t gquic_tls_half_conn_decrypt(gquic_str_t *const ret, u_int8_t *const record_type,
                                              gquic_tls_half_conn_t *const half_conn, const gquic_str_t *const record);

/**
 * 设定密钥
 *
 * @param half_conn: TLS连接管理
 * @param enc_lv: 加密级别
 * @param cipher_suite: 加密套件
 * @param secret: secret
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_half_conn_set_key(gquic_tls_half_conn_t *const half_conn, const u_int8_t enc_lv,
                                              const gquic_tls_cipher_suite_t *const cipher_suite, const gquic_str_t *const secret);

/**
 * 设定traffic secret
 *
 * @param half_conn: TLS连接管理
 * @param cipher_suite: 加密套件
 * @param secret: traffic secret
 * @param is_read: 是否为解密密钥
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_half_conn_set_traffic_sec(gquic_tls_half_conn_t *const half_conn,
                                                      const gquic_tls_cipher_suite_t *const cipher_suite, const gquic_str_t *const secret, bool is_read);

/**
 * TLS连接管理
 */
typedef struct gquic_tls_conn_s gquic_tls_conn_t;
struct gquic_tls_conn_s {
    const gquic_net_addr_t *addr;
    gquic_tls_config_t *cfg;
    int is_client;
    _Atomic(u_int32_t) handshake_status;
    u_int16_t ver;
    int have_vers;
    int handshakes;
    int did_resume;
    u_int16_t cipher_suite;
    gquic_str_t ocsp_resp;
    gquic_list_t scts;
    gquic_list_t peer_certs; /* X509 * */
    gquic_list_t verified_chains;
    gquic_str_t ser_name;
    int sec_renegortiation;
    gquic_tls_ekm_t ekm;
    gquic_str_t resumption_sec;
    int cli_finished_is_first;
    gquic_tls_half_conn_t in;
    gquic_tls_half_conn_t out;
    u_int64_t sent_size;
    u_int64_t sent_pkg_count;
    int buffering;
    gquic_str_t cli_proto;
    int cli_proto_fallback;

    pthread_mutex_t mtx;
};

/**
 * 初始化TLS连接管理
 *
 * @param conn: TLS连接管理
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_init(gquic_tls_conn_t *const conn);

/**
 * 加载TLS连接状态
 *
 * @param conn: TLS连接管理
 * @param hello: CHELLO record
 *
 * @return cache_key: cache key
 * @return sess: 会话状态
 * @return early_sec: early secret
 * @return binder_key: binder key
 * 
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_load_session(gquic_str_t *const cache_key, gquic_tls_client_sess_state_t **const sess,
                                              gquic_str_t *const early_sec, gquic_str_t *const binder_key,
                                              const gquic_tls_conn_t *const conn, gquic_tls_client_hello_msg_t *const hello);

/**
 * useless
 */
gquic_exception_t gquic_tls_conn_write_max_write_size(size_t *const ret, const gquic_tls_conn_t *const conn, const u_int8_t record_type);

/**
 * TODO: useless
 */
gquic_exception_t gquic_tls_conn_set_alt_record(gquic_tls_conn_t *const conn);

/**
 * 写一个TLS record
 * TODO: 更改为gquic_str_reader_t
 *
 * @param conn: TLS连接管理
 * @param record_type: TLS record类型
 * @param data: data
 * 
 * @return len: 写出长度
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_write_record(size_t *const len, gquic_tls_conn_t *const conn, u_int8_t record_type, const gquic_str_t *const data);

/**
 * 读取一个TLS record
 *
 * @param conn: TLS连接管理
 *
 * @return msg: TLS record
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_read_handshake(void **const msg, gquic_tls_conn_t *const conn);

/**
 * 发送一个Alert
 *
 * @param conn: TLS连接管理
 * @param alert: alert
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_send_alert(gquic_tls_conn_t *const conn, u_int8_t alert);

/**
 * 验证服务端证书
 *
 * @param conn: TLS连接管理
 * @param certs: 服务端证书列表
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_verify_ser_cert(gquic_tls_conn_t *const conn, const gquic_list_t *const certs);

/**
 * 处理客户端证书
 *
 * @param conn: TLS连接管理
 * @param certs: 客户端证书列表
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_process_cli_cert(gquic_tls_conn_t *const conn, const gquic_list_t *const certs);

/**
 * TLS连接管理执行握手过程
 *
 * @param conn: TLS连接管理
 * 
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_handshake(gquic_tls_conn_t *const conn);


/**
 * 解密ticket
 *
 * @param plain: 存储明文
 * @param is_oldkey: 存储是否为旧密钥
 * @param conn: TLS连接管理
 * @param encrypted: 密文
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_decrypt_ticket(gquic_str_t *const plain, bool *const is_oldkey, gquic_tls_conn_t *const conn, const gquic_str_t *const encrypted);

/**
 * 加密ticket
 *
 * @param encrypted: 存储密文
 * @param conn: TLS连接管理
 * @param state: 明文
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_encrypt_ticket(gquic_str_t *const encrypted, gquic_tls_conn_t *const conn, const gquic_str_t *const state);

/**
 * 获取一个ticket
 *
 * @param msg: 存储ticket
 * @param conn: TLS连接管理
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_get_sess_ticket(gquic_str_t *const msg, gquic_tls_conn_t *const conn);

/**
 * 处理后握手阶段
 *
 * @param conn: TLS连接管理
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_conn_handle_post_handshake_msg(gquic_tls_conn_t *const conn);

#endif
