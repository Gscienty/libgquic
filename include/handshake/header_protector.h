/* include/handshake/header_protector.h 头部保护模块定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_HEADER_PROTECTOR_H
#define _LIBGQUIC_HANDSHAKE_HEADER_PROTECTOR_H

#include "util/str.h"
#include "tls/cipher_suite.h"
#include "exception.h"
#include <stdbool.h>

/**
 * 头部保护模块抽象类
 */
typedef struct gquic_header_protector_s gquic_header_protector_t;
struct gquic_header_protector_s {
    void *self;

    // 设置加密密钥
    gquic_exception_t (*set_key) (void *const, gquic_str_t *const);

    // 加密
    gquic_exception_t (*encrypt) (gquic_str_t *const, u_int8_t *const, void *const);

    // 解密
    gquic_exception_t (*decrypt) (gquic_str_t *const, u_int8_t *const, void *const);

    // 析构
    gquic_exception_t (*dtor) (void *const);
};

/**
 * 设定头部保护模块的加密/解密密钥
 *
 * @param p: header_protector
 * @param s: 密钥
 *
 * @return: exception
 */
#define GQUIC_HEADER_PROTECTOR_SET_KEY(p, s) ((p)->set_key((p)->self, (s)))

/**
 * 对头部进行加密
 *
 * @param h(ref): 头部字节串
 * @param f(ref): 头部第一个字节
 * @param p: header_protector
 * 
 * @return: exception
 */
#define GQUIC_HEADER_PROTECTOR_ENCRYPT(h, f, p) ((p)->encrypt((h), (f), (p)->self))

/**
 * 对头部进行解密
 *
 * @param h(ref): 头部字节串
 * @param f(ref): 头部第一个字节
 * @param p: header_protector
 * 
 * @return: exception
 */
#define GQUIC_HEADER_PROTECTOR_DECRYPT(h, f, p) ((p)->decrypt((h), (f), (p)->self))

/**
 * 初始化头部保护模块
 *
 * @param protector: header_protector
 * 
 * @return: exception
 */
gquic_exception_t gquic_header_protector_init(gquic_header_protector_t *const protector);

/**
 * 构造头部保护模块
 *
 * @param protector: header_protector
 * @param suite: 加密套件
 * @param tarffic_sec: 密钥交换后的秘密序列
 * @param is_long_header: 是否为长首部
 *
 * @return: exception
 */
gquic_exception_t gquic_header_protector_ctor(gquic_header_protector_t *const protector,
                                              const gquic_tls_cipher_suite_t *const suite,
                                              const gquic_str_t *const traffic_sec, const bool is_long_header);

/**
 * 析构头部保护模块
 *
 * @param protector: header_protector
 *
 * @return: exception
 */
gquic_exception_t gquic_header_protector_dtor(gquic_header_protector_t *const protector);

#endif
