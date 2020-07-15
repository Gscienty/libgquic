/* include/handshake/aead.h 针对quic的包加密，对AEAD加密模块的封装
 * 该模块主要针对加密级别为initial或handshake时对AEAD的封装
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_AEAD_H
#define _LIBGQUIC_HANDSHAKE_AEAD_H

#include "handshake/header_protector.h"
#include "util/str.h"

/**
 * 长首部包加密模块
 */
typedef struct gquic_long_header_sealer_s gquic_long_header_sealer_t;
struct gquic_long_header_sealer_s {
    
    // AEAD 加密模块
    gquic_tls_aead_t aead;

    // 头部保护模块
    gquic_header_protector_t protector;

    // 单次值
    gquic_str_t nonce_buf;
};

/**
 * 长首部包加密模块初始化
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_sealer_init(gquic_long_header_sealer_t *const sealer);

/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分加密密钥
 * @param iv: 主体部分加密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_sealer_ctor(gquic_long_header_sealer_t *const sealer,
                                                const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec);
/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_sealer_traffic_ctor(gquic_long_header_sealer_t *const sealer,
                                                        const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 析构长首部包加密模块
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_sealer_dtor(gquic_long_header_sealer_t *const sealer);

/**
 * 使用长首部包加密模块进行加密操作
 *
 * @param tag: 加密后产出的tag
 * @param cipher_text: 加密后产出的密文
 * @param sealer: 加密模块
 * @param pn: packet number
 * @param plain_text: 明文
 * @param addata: AEAD加密时所需的addata
 * 
 * @return: exception
 */
gquic_exception_t gquic_long_header_sealer_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                                gquic_long_header_sealer_t *const sealer,
                                                const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata);

/**
 * 长首部包解密模块
 */
typedef struct gquic_long_header_opener_s gquic_long_header_opener_t;
struct gquic_long_header_opener_s {

    // AEAD 加密模块
    gquic_tls_aead_t aead;

    // 头部保护模块
    gquic_header_protector_t protector;

    // 单次值
    gquic_str_t nonce_buf;
};

/**
 * 长首部包解密模块初始化
 *
 * @param opener: 解密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_opener_init(gquic_long_header_opener_t *const opener);

/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分解密密钥
 * @param iv: 主体部分解密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_opener_ctor(gquic_long_header_opener_t *const opener,
                                                const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec);

/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_opener_traffic_ctor(gquic_long_header_opener_t *const opener,
                                                        const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 析构长首部包加密模块
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_opener_dtor(gquic_long_header_opener_t *const opener);

/**
 * 使用长首部解密模块进行解密操作
 *
 * @param plain_text: 明文
 * @param opener: 解密模块
 * @param pn: packet number
 * @param tag: 解密使用的tag
 * @param cipher_text: 密文
 * @param addata: AEAD解密使用的addata
 *
 * @return: exception
 */
gquic_exception_t gquic_long_header_opener_open(gquic_str_t *const plain_text,
                                                gquic_long_header_opener_t *const opener,
                                                const u_int64_t pn, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata);

/**
 * 加密级别为handshake时的长首部加密模块
 */
typedef struct gquic_handshake_sealer_s gquic_handshake_sealer_t;
struct gquic_handshake_sealer_s {

    // 长首部包加密模块
    gquic_long_header_sealer_t sealer;

    // 丢弃密钥的回调函数
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const);
    } drop_keys;
    
    // 当前加密包是否被丢弃
    bool dropped;
};

/**
 * 长首部包加密模块初始化
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_sealer_init(gquic_handshake_sealer_t *const sealer);

/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分加密密钥
 * @param iv: 主体部分加密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_sealer_ctor(gquic_handshake_sealer_t *const sealer,
                                              const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                              const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                              void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const));

/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_sealer_traffic_ctor(gquic_handshake_sealer_t *const sealer,
                                                      const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                      void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const));

/**
 * 析构长首部包加密模块
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_sealer_dtor(gquic_handshake_sealer_t *const sealer);

/**
 * 使用长首部包加密模块进行加密操作
 *
 * @param tag: 加密后产出的tag
 * @param cipher_text: 加密后产出的密文
 * @param sealer: 加密模块
 * @param pn: packet number
 * @param plain_text: 明文
 * @param addata: AEAD加密时所需的addata
 * 
 * @return: exception
 */
gquic_exception_t gquic_handshake_sealer_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                              gquic_handshake_sealer_t *const sealer,
                                              const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata);

/**
 * 长首部包加密模块丢弃密钥
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
#define GQUIC_HANDSHAKE_SEALER_DROP_KEYS(sealer) ((sealer)->drop_keys.cb((sealer)->drop_keys.self))

/**
 * 长首部包解密模块
 */
typedef struct gquic_handshake_opener_s gquic_handshake_opener_t;
struct gquic_handshake_opener_s {

    // 长首部包解密模块
    gquic_long_header_opener_t opener;

    // 丢弃密钥的回调函数
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const);
    } drop_keys;

    // 当前解密包是否被丢弃
    bool dropped;
};

/**
 * 长首部包解密模块初始化
 *
 * @param opener: 解密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_opener_init(gquic_handshake_opener_t *const opener);

/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分解密密钥
 * @param iv: 主体部分解密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_opener_ctor(gquic_handshake_opener_t *const opener,
                                              const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                              const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                              void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const));

/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_opener_traffic_ctor(gquic_handshake_opener_t *const opener,
                                                      const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                      void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const));

/**
 * 析构长首部包加密模块
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_opener_dtor(gquic_handshake_opener_t *const opener);

/**
 * 使用长首部解密模块进行解密操作
 *
 * @param plain_text: 明文
 * @param opener: 解密模块
 * @param pn: packet number
 * @param tag: 解密使用的tag
 * @param cipher_text: 密文
 * @param addata: AEAD解密使用的addata
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_opener_open(gquic_str_t *const plain_text,
                                              gquic_handshake_opener_t *const opener,
                                              const u_int64_t pn, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata);
/**
 * 长首部包解密模块丢弃密钥
 *
 * @param sealer: 解密模块
 *
 * @return: exception
 */
#define GQUIC_HANDSHAKE_OPENER_DROP_KEYS(opener) ((opener)->drop_keys.cb((opener)->drop_keys.self))


/**
 * initial和handshake通用加密模块
 */
typedef struct gquic_common_long_header_sealer_s gquic_common_long_header_sealer_t;
struct gquic_common_long_header_sealer_s {

    // 加密模块是否可用
    bool available;

    // 是否使用handshake加密模块
    bool use_handshake;

    union {
        gquic_long_header_sealer_t initial_sealer;
        gquic_handshake_sealer_t handshake_sealer;
    } sealer;
};

/**
 * 长首部包加密模块初始化
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_init(gquic_common_long_header_sealer_t *const sealer);

/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分加密密钥
 * @param iv: 主体部分加密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_long_header_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                   const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                   const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec);
/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_long_header_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                           const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);
/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分加密密钥
 * @param iv: 主体部分加密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_handshake_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                 const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                 const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                                                 void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                 const bool is_client);
/**
 * 构造长首部包加密模块
 *
 * @param sealer: 加密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_handshake_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                         const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                                         void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                         const bool is_client);

/**
 * 析构长首部包加密模块
 *
 * @param sealer: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_dtor(gquic_common_long_header_sealer_t *const sealer);

/**
 * 使用长首部包加密模块进行加密操作
 *
 * @param tag: 加密后产出的tag
 * @param cipher_text: 加密后产出的密文
 * @param sealer: 加密模块
 * @param pn: packet number
 * @param plain_text: 明文
 * @param addata: AEAD加密时所需的addata
 * 
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                                       gquic_common_long_header_sealer_t *const sealer,
                                                       const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata);

/**
 * 获取头部保护模块
 *
 * @param sealer: 加密模块
 *
 * @return: protector: 头部保护模块
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_sealer_get_header_sealer(gquic_header_protector_t **const protector, gquic_common_long_header_sealer_t *const sealer);

/**
 * 长首部包解密模块
 */
typedef struct gquic_common_long_header_opener_s gquic_common_long_header_opener_t;
struct gquic_common_long_header_opener_s {

    // 加密模块是否可用
    bool available;

    // 是否使用handshake加密模块
    bool use_handshake;
    union {
        gquic_long_header_opener_t initial_opener;
        gquic_handshake_opener_t handshake_opener;
    } opener;
};

/**
 * 长首部包解密模块初始化
 *
 * @param opener: 解密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_init(gquic_common_long_header_opener_t *const opener);

/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分解密密钥
 * @param iv: 主体部分解密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_long_header_ctor(gquic_common_long_header_opener_t *const opener,
                                                                   const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                   const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec);
/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_long_header_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                                           const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param aead_suite: 主体部分加密套件
 * @param key: 主体部分解密密钥
 * @param iv: 主体部分解密初始向量
 * @param protector_suite: 头部保护模块使用的加密套件
 * @param traffic_sec: secret (投递给头部保护模块)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_handshake_ctor(gquic_common_long_header_opener_t *const opener,
                                                                 const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                 const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                                                 void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                 const bool is_client);
/**
 * 构造长首部包解密模块
 *
 * @param opener: 解密模块
 * @param suite: 加密套件 (头部保护模块及主体部分共用)
 * @param traffic_sec: secret (头部保护模块及主体部分共用)
 * @param drop_keys_self: 丢弃密钥回调函数的self参数
 * @param drop_keys_cb: 丢弃密钥回调函数
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_handshake_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                                         const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                                         void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                         const bool is_client);
/**
 * 使用长首部解密模块进行解密操作
 *
 * @param plain_text: 明文
 * @param opener: 解密模块
 * @param pn: packet number
 * @param tag: 解密使用的tag
 * @param cipher_text: 密文
 * @param addata: AEAD解密使用的addata
 *
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_dtor(gquic_common_long_header_opener_t *const opener);
gquic_exception_t gquic_common_long_header_opener_open(gquic_str_t *const plain_text,
                                                       gquic_common_long_header_opener_t *const opener,
                                                       const u_int64_t pn, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata);

/**
 * 获取头部保护模块
 *
 * @param sealer: 加密模块
 *
 * @return: protector: 头部保护模块
 * @return: exception
 */
gquic_exception_t gquic_common_long_header_opener_get_header_opener(gquic_header_protector_t **const protector, gquic_common_long_header_opener_t *const opener);


#endif
