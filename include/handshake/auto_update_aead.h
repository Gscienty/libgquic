/* include/handshake/auto_update_aead.h 1RTT加密级别时使用的AEAD加密/解密模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_AUTO_UPDATE_AEAD_H
#define _LIBGQUIC_HANDSHAKE_AUTO_UPDATE_AEAD_H

#include "tls/cipher_suite.h"
#include "util/time.h"
#include "util/rtt.h"
#include "handshake/header_protector.h"
#include "exception.h"
#include <stdbool.h>

typedef struct gquic_auto_update_aead_s gquic_auto_update_aead_t;
struct gquic_auto_update_aead_s {

    // 加密套件
    const gquic_tls_cipher_suite_t *suite;

    // 模块更迭次数
    u_int64_t times;
    // 最后ACK的packet number
    u_int64_t last_ack_pn;

    // 更新间隔时间
    u_int64_t update_interval;

    // 前一个解密模块过期时间
    u_int64_t prev_recv_aead_expire;
    // 前一个解密模块
    gquic_tls_aead_t prev_recv_aead;

    // 当前密钥接收到的第一个packet number
    u_int64_t cur_key_first_recv_pn;
    // 当前密钥发送的第一个packet number
    u_int64_t cur_key_first_sent_pn;
    // 使用当前密钥解密次数
    u_int64_t cur_key_num_recv;
    // 使用当前密钥加密次数
    u_int64_t cur_key_num_sent;

    // 当前解密模块
    gquic_tls_aead_t recv_aead;
    // 当前加密模块
    gquic_tls_aead_t send_aead;

    // 下一阶段的解密模块
    gquic_tls_aead_t next_recv_aead;
    // 下一阶段的加密模块
    gquic_tls_aead_t next_send_aead;

    // 下一阶段生成解密密钥的secret
    gquic_str_t next_recv_traffic_sec;
    // 下一阶段生成加密密钥的secret
    gquic_str_t next_send_traffic_sec;

    // 头部加密组件
    gquic_header_protector_t header_enc;
    // 头部解密组件
    gquic_header_protector_t header_dec;

    // RTT
    const gquic_rtt_t *rtt;

    // 单次值
    gquic_str_t nonce_buf;
};

/**
 * 1RTT加密模块初始化
 *
 * @param aead: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_auto_update_aead_init(gquic_auto_update_aead_t *const aead);

/**
 * 加密模块阶段更迭
 *
 * @param aead: 加密模块
 * @param now: 更迭时间
 *
 * @return: exception
 */
gquic_exception_t gquic_auto_update_aead_roll(gquic_auto_update_aead_t *const aead, const u_int64_t now);

/**
 * 设定解密密钥
 *
 * @param aead: 加密模块
 * @param suite: 加密套件
 * @param traffic_sec: 生成解密密钥的secret
 *
 * @return: exception
 */
gquic_exception_t gquic_auto_update_aead_set_rkey(gquic_auto_update_aead_t *const aead,
                                                  const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 设定加密密钥
 *
 * @param aead: 加密模块
 * @param suite: 加密套件
 * @param traffic_sec: 生成加密密钥的secret
 *
 * @return: exception
 */
gquic_exception_t gquic_auto_update_aead_set_wkey(gquic_auto_update_aead_t *const aead,
                                                  const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 使用加密模块进行解密
 *
 * @param plain_text: 解密后的明文
 * @param aead: 加密模块
 * @param recv_time: 接收时间(用于加密模块的阶段更迭)
 * @param pn: packet number
 * @param kp: 是否处于更迭阶段
 * @param tag: AEAD解密时所需tag
 * @param cipher_text: 密文
 * @param addata: AEAD解密时所需addata
 *
 * @return: exception
 */
gquic_exception_t gquic_auto_update_aead_open(gquic_str_t *const plain_text,
                                              gquic_auto_update_aead_t *const aead,
                                              const u_int64_t recv_time, const u_int64_t pn, const bool kp,
                                              const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata);

/**
 * 使用加密模块进行加密
 *
 * @param tag: 加密后的tag
 * @param cipher_text: 加密后的密文
 * @param aead: 加密模块
 * @param pn: packet number
 * @param plain_text: 明文
 * @param addata: AEAD加密时所需的addata
 *
 * @return: exception
 */
gquic_exception_t gquic_auto_update_aead_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                              gquic_auto_update_aead_t *const aead,
                                              const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata);

/**
 * 获取当前加密模块的密钥阶段（可能会触发阶段更迭）
 *
 * @param aead: 加密模块
 *
 * @return: 密钥阶段
 */
bool gquic_auto_update_aead_key_phase(gquic_auto_update_aead_t *const aead);

#endif
