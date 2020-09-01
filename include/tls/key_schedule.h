/* include/tls/key_schedule.h 密钥模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_KEY_SCHEDULE_H
#define _LIBGQUIC_TLS_KEY_SCHEDULE_H

#include "util/str.h"
#include "tls/cipher_suite.h"

/**
 * ECDHE参数模块
 */
typedef struct gquic_tls_ecdhe_params_s gquic_tls_ecdhe_params_t;
struct gquic_tls_ecdhe_params_s {
    void *self;
    u_int16_t (*curve_id) (const void *const);
    gquic_exception_t (*public_key) (const void *const, gquic_str_t *const);
    gquic_exception_t (*shared_key) (const void *const, gquic_str_t *const, const gquic_str_t *const);
    gquic_exception_t (*dtor) (void *const);
};

/**
 * 获取当前ECDHE参数的curve id
 *
 * @param p: ECDHE参数
 *
 * @return: curve id
 */
#define GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(p) \
    (((gquic_tls_ecdhe_params_t *) (p))->curve_id(((gquic_tls_ecdhe_params_t *) (p))->self))

/**
 * 从ECDHE参数中获取公钥
 *
 * @param p: ECDHE参数
 * @param s: 用于存储公钥
 *
 * @return: exception
 */
#define GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(p, s) \
    (((gquic_tls_ecdhe_params_t *) (p))->public_key(\
                                                    ((gquic_tls_ecdhe_params_t *) (p))->self,\
                                                    (s)))

/**
 * 从ECDHE参数和对端的公钥生成shared key
 *
 * @param p: ECDHE参数
 * @param r: shared key
 * @param s: 对端公钥
 *
 * @return: exception
 */
#define GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(p, r, s) \
    (((gquic_tls_ecdhe_params_t *) (p))->shared_key(\
                                                    ((gquic_tls_ecdhe_params_t *) (p))->self,\
                                                    (r),\
                                                    (s)))

/**
 * 析构ECDHE参数
 *
 * @param p: ECDHE参数
 *
 * @return: exception
 */
#define GQUIC_TLS_ECDHE_PARAMS_DTOR(p) \
    (((gquic_tls_ecdhe_params_t *) (p))->dtor(((gquic_tls_ecdhe_params_t *) (p))->self))

/**
 * 根据curve id生成ECDHE参数
 *
 * @param param: ECDHE参数
 * @param curve_id: curve id
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ecdhe_params_generate(gquic_tls_ecdhe_params_t *param, const u_int16_t curve_id);

/**
 * 初始化ECDHE参数
 *
 * @param param: ECDHE参数
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ecdhe_params_init(gquic_tls_ecdhe_params_t *param);

/**
 * 析构ECDHE参数
 *
 * @param param: ECDHE参数
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ecdhe_params_dtor(gquic_tls_ecdhe_params_t *param);

/**
 * extract密钥生成
 *
 * @param ret: 存储生成后的密钥
 * @param hash: MAC哈希
 * @param secret: secret
 * @param salt: salt
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_hkdf_extract(gquic_str_t *const ret, gquic_tls_mac_t *const hash, const gquic_str_t *const secret, const gquic_str_t *const salt);

/**
 * expand密钥生成
 *
 * @param ret: 存储生成后的密钥
 * @param hash: MAC哈希
 * @param secret: secret
 * @param content: content
 * @param label: 标签
 * @param length: 生成的密钥长度
 */
gquic_exception_t gquic_tls_hkdf_expand_label(gquic_str_t *const ret,
                                              gquic_tls_mac_t *const hash,
                                              const gquic_str_t *const secret, const gquic_str_t *const content, const gquic_str_t *const label, const size_t length);


#endif
