/* include/tls/cipher_suite.h TLS 加密套件
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CIPHER_SUITE_H
#define _LIBGQUIC_TLS_CIPHER_SUITE_H

#include "tls/key_agreement.h"
#include "util/str.h"
#include "exception.h"
#include <sys/types.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_RC4_128_SHA 0x0005
#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA 0x000a
#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA 0x002f
#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA 0x0035
#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 0x003c
#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 0x009c
#define GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384 0x009d
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_RC4_128_SHA 0xc007
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 0xc009
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 0xc00a
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_RC4_128_SHA 0xc011
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA 0xc012
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA 0xc013
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA 0xc014
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xc023
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xc027
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc02f
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xc030
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xc02c
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305 0xcca8
#define GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 0xcca9
#define GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

#define GQUIC_TLS_SUITE_ECDHE 0x01
#define GQUIC_TLS_SUITE_EC_SIGN 0x02
#define GQUIC_TLS_SUITE_TLS12 0x04
#define GQUIC_TLS_SUITE_SHA384 0x08
#define GQUIC_TLS_SUITE_DEF 0x10

#define GQUIC_TLS_HASH_SHA256 0x0001
#define GQUIC_TLS_HASH_SHA384 0x0002

/**
 * AEAD
 */
typedef struct gquic_tls_aead_s gquic_tls_aead_t;
struct gquic_tls_aead_s {
    void *self;
    gquic_exception_t (*seal)(gquic_str_t *const, gquic_str_t *const,
                              void *const,
                              const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
    gquic_exception_t (*open)(gquic_str_t *const,
                              void *const,
                              const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
    gquic_exception_t (*dtor) (void *const);
};

#define GQUIC_TLS_AEAD_SEAL(tag, cipher_text, aead, nonce, plain_text, addata) \
    (((aead)->seal) == NULL \
    ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
    : ((aead)->seal((tag), (cipher_text), (aead)->self, (nonce), (plain_text), (addata))))

#define GQUIC_TLS_AEAD_OPEN(plain_text, aead, nonce, tag, cipher_text, addata) \
    (((aead)->open) == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((aead)->open((plain_text), (aead)->self, (nonce), (tag), (cipher_text), (addata))))
#define GQUIC_TLS_AEAD_DTOR(aead) \
    (((aead)->dtor) == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((aead)->dtor((aead)->self)))

/**
 * 初始化AEAD
 *
 * @param aead: AEAD
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_aead_init(gquic_tls_aead_t *const aead);

/**
 * 析构AEAD
 * 
 * @param aead: AEAD
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_aead_dtor(gquic_tls_aead_t *const aead);

/**
 * 复制一个AEAD
 *
 * @param aead: AEAD
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_aead_copy(gquic_tls_aead_t *const aead, const gquic_tls_aead_t *const ref);

/**
 * 加密模块
 */
typedef struct gquic_tls_cipher_s gquic_tls_cipher_t;
struct gquic_tls_cipher_s {
    EVP_CIPHER_CTX *cipher;
    gquic_str_t key;
    gquic_str_t iv;
};

/**
 * 初始化加密模块
 *
 * @param cipher: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_init(gquic_tls_cipher_t *const cipher);

/**
 * 析构加密模块
 *
 * @param cipher: 加密模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_dtor(gquic_tls_cipher_t *const cipher);

/**
 * 加密操作
 *
 * @param ret: 存放密文的容器
 * @param cipher: 加密模块
 * @param plain_text: 明文
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_encrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const plain_text);

/**
 * 解密操作
 *
 * @param ret: 存放明文的容器
 * @param cipher: 加密模块
 * @param cipher_text: 密文
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_decrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const cipher_text);

/**
 * MAC
 */
typedef struct gquic_tls_mac_s gquic_tls_mac_t;
struct gquic_tls_mac_s {
    const EVP_MD *md;
    HMAC_CTX *mac;
    EVP_MD_CTX *md_ctx;
    gquic_str_t key;
};

/**
 * 初始化MAC
 *
 * @param mac: MAC
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_init(gquic_tls_mac_t *const mac);

/**
 * 析构MAC
 * 
 * @param mac: MAC
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_dtor(gquic_tls_mac_t *const mac);

/**
 * 计算HMAC
 *
 * @param ret: 存放最终哈希结果的容器
 * @param mac: MAC
 * @param seq: seq
 * @param header: header
 * @param data: data
 * @param extra: extra
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_hmac_hash(gquic_str_t *const ret,
                                          gquic_tls_mac_t *const mac,
                                          const gquic_str_t *const seq, const gquic_str_t *const header, const gquic_str_t *const data, const gquic_str_t *const extra);

/**
 * 计算哈希值
 *
 * @param ret: 存放最终哈希结果的容器
 * @param mac: MAC
 * @param data: data
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_md_hash(gquic_str_t *const ret, gquic_tls_mac_t *const mac, const gquic_str_t *const data);

/**
 * 填充MAC
 *
 * @param mac: MAC
 * @param data: data
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_md_update(gquic_tls_mac_t *const mac, const gquic_str_t *const data);

/**
 * 重置MAC
 *
 * @param mac: MAC
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_md_reset(gquic_tls_mac_t *const mac);

/**
 * 计算MAC结果
 *
 * @param ret: 存放哈希结果的容器
 * @param mac: MAC
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_md_sum(gquic_str_t *const ret, gquic_tls_mac_t *const mac);

/**
 * 复制MAC
 * 
 * @param ret: 被复制的MAC容器
 * @param origin: 复制的MAC容器
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_mac_md_copy(gquic_tls_mac_t *const ret, gquic_tls_mac_t *const origin);

/**
 * 加密套件，用于根据定义的算法构建加密套件
 */
typedef struct gquic_tls_cipher_suite_s gquic_tls_cipher_suite_t;
struct gquic_tls_cipher_suite_s {
    u_int16_t id;
    size_t key_len;
    size_t mac_len;
    size_t iv_len;
    gquic_exception_t (*ka) (gquic_tls_key_agreement_t *const, const u_int16_t);
    int flags;
    u_int16_t hash;

    gquic_exception_t (*cipher_encrypt) (gquic_tls_cipher_t *const, const gquic_str_t *const, const gquic_str_t *const, const bool);
    gquic_exception_t (*mac) (gquic_tls_mac_t *const, const u_int16_t, const gquic_str_t *const);
    gquic_exception_t (*aead) (gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

/**
 * 根据加密套件ID获取加密套件
 *
 * @param cipher_suite_id: 加密套件ID
 * 
 * @return cipher_suite: 加密套件
 * @return: exception
 */
gquic_exception_t gquic_tls_get_cipher_suite(const gquic_tls_cipher_suite_t **const cipher_suite, const u_int16_t cipher_suite_id);

/**
 * 从允许的加密套件列表中选择对应的加密套件
 *
 * @param have: 加密套件ID列表
 * @param want: 加密套件ID
 *
 * @return cipher_suite: 加密套件
 * @return: exception
 */
gquic_exception_t gquic_tls_choose_cipher_suite(const gquic_tls_cipher_suite_t **const cipher_suite, const gquic_list_t *const have, const u_int16_t want);

/**
 * 根据加密套件构造AEAD
 *
 * @param aead: 构造的AEAD
 * @param suite: 加密套件
 * @param traffic_sec: traffic secret
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_create_aead(gquic_tls_aead_t *const aead, const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 对label进行指纹生成
 *
 * @param ret: 生成的指纹
 * @param cipher_suite: 加密套件
 * @param secret: secret
 * @param label: label
 * @param content: 消息内容
 * @param length: 指纹长度
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_suite_expand_label(gquic_str_t *const ret,
                                                      const gquic_tls_cipher_suite_t *const cipher_suite,
                                                      const gquic_str_t *const secret, const gquic_str_t *const label, const gquic_str_t *const content, const size_t length);

/**
 * 根据上一个secret生成下一个secret
 *
 * @param ret: 生成的scret
 * @param cipher_suite: 加密套件
 * @param mac: MAC，对会话过程的每一个record都进行哈希过
 * @param secret: 原secret
 * @param label: 标签
 */
gquic_exception_t gquic_tls_cipher_suite_derive_secret(gquic_str_t *const ret,
                                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                                       gquic_tls_mac_t *const mac, const gquic_str_t *const secret, const gquic_str_t *const label);

/**
 * 根据secret和salt生成下一个secret
 *
 * @param ret: 生成的secret
 * @param cipher_suite: 加密套件
 * @param secret: 原secret
 * @param salt: 盐
 */
gquic_exception_t gquic_tls_cipher_suite_extract(gquic_str_t *const ret,
                                                 const gquic_tls_cipher_suite_t *const cipher_suite,
                                                 const gquic_str_t *const secret, const gquic_str_t *const salt);

/**
 * 根据traffic_sec生成key和iv
 * 
 * @param key: 生成的key
 * @param iv: 生成的iv
 * @param cipher_suite: 加密套件
 * @param traffic_sec: traffic_sec
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_suite_traffic_key(gquic_str_t *const key, gquic_str_t *const iv,
                                                     const gquic_tls_cipher_suite_t *const cipher_suite, const gquic_str_t *const traffic_sec);
gquic_exception_t gquic_tls_cipher_suite_finished_hash(gquic_str_t *const ret,
                                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                                       const gquic_str_t *const base_key, gquic_tls_mac_t *const transport);

#define GQUIC_TLS_CIPHER_TYPE_UNKNOW 0
#define GQUIC_TLS_CIPHER_TYPE_STREAM 1
#define GQUIC_TLS_CIPHER_TYPE_AEAD 2
#define GQUIC_TLS_CIPHER_TYPE_CBC 3

/**
 * 加密套件，用于实际加密和签名
 */
typedef struct gquic_tls_suite_s gquic_tls_suite_t;
struct gquic_tls_suite_s {
    u_int8_t type;
    gquic_tls_cipher_t cipher;
    gquic_tls_aead_t aead;
    gquic_tls_mac_t mac;
};

/**
 * 初始化加密套件
 *
 * @param suite: 加密套件
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_init(gquic_tls_suite_t *const suite);

/**
 * 构造加密套件
 *
 * @param suite: 加密套件
 * @param cipher_suite: 加密套件定义
 * @param iv: iv
 * @param cipher_key: 加密密钥
 * @param mac_key: 签名密钥
 * @param is_read: 是否用于解密
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_ctor(gquic_tls_suite_t *const suite,
                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                       const gquic_str_t *const iv, const gquic_str_t *const cipher_key,
                                       const gquic_str_t *const mac_key, const bool is_read);

/**
 * 使用加密套件进行加密
 *
 * @param result: 存取加密后的密文
 * @param suite: 加密套件
 * @param plain_text: 明文
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_encrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const plain_text);

/**
 * 使用加密套件的AEAD进行加密
 *
 * @param tag: AEAD加密后的tag
 * @param cipher_text: 加密后的密文
 * @param suite: 加密套件
 * @param nonce: nonce
 * @param plain_text: 明文
 * @param addata: addata
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_aead_encrypt(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                               gquic_tls_suite_t *const suite,
                                               const gquic_str_t *const nonce, const gquic_str_t *const plain_text, const gquic_str_t *const addata);

/**
 * 使用加密套件进行解密
 *
 * @param plain_text: 存放解密后的明文
 * @param suite: 加密套件
 * @param cipher_text: 密文
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_decrypt(gquic_str_t *const plain_text, gquic_tls_suite_t *const suite, const gquic_str_t *const cipher_text);

/**
 * 使用加密套件进行AEAD解密
 *
 * @param plain_text: 存放解密后的明文
 * @param suite: 加密套件
 * @param nonce: nonce
 * @param tag: tag
 * @param cipher_text: 密文
 * @param addata: addata
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_aead_decrypt(gquic_str_t *const plain_text,
                                               gquic_tls_suite_t *const suite,
                                               const gquic_str_t *const nonce, const gquic_str_t *const tag,
                                               const gquic_str_t *const cipher_text, const gquic_str_t *const addata);

/**
 * 使用加密套件进行哈希计算
 *
 * @param hash: 存放哈希计算结果
 * @param suite: 加密套件
 * @param seq: seq
 * @param header: header
 * @param data: data
 * @param extra: extra
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_suite_hmac_hash(gquic_str_t *const hash,
                                            gquic_tls_suite_t *const suite,
                                            const gquic_str_t *const seq, const gquic_str_t *const header,
                                            const gquic_str_t *const data, const gquic_str_t *const extra);

/**
 * 获取加密套件单次值长度
 *
 * @param suite: 加密套件
 * 
 * @return: 单次值长度
 */
static inline size_t gquic_tls_suite_nonce_size(const gquic_tls_suite_t *const suite) {
    if (suite == NULL) {
        return 0;
    }

    switch (suite->type) {
    case GQUIC_TLS_CIPHER_TYPE_AEAD:
        return 1 + 8;
    }
    return 0;
}

/**
 * 获取加密套件mac结果长度
 *
 * @param suite: 加密套件
 *
 * @return: mac结果长度
 */
static inline size_t gquic_tls_suite_mac_size(const gquic_tls_suite_t *const suite) {
    if (suite == NULL || suite->mac.mac == NULL) {
        return 0;
    }

    return HMAC_size(suite->mac.mac);
}

/**
 * 扩展密钥管理模块
 */
typedef struct gquic_tls_ekm_s gquic_tls_ekm_t;
struct gquic_tls_ekm_s {
    void *self;
    gquic_exception_t (*ekm) (gquic_str_t *const, void *const, const gquic_str_t *const, const gquic_str_t *const, const size_t);
    gquic_exception_t (*dtor) (void *self);
};

/**
 * 初始化扩展密钥管理模块
 *
 * @param ekm: 扩展密钥管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ekm_init(gquic_tls_ekm_t *const ekm);

/**
 * 析构扩展密钥管理模块
 *
 * @param ekm: 扩展密钥管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ekm_dtor(gquic_tls_ekm_t *const ekm);

/**
 * 执行扩展密钥
 *
 * @param ret: 存储扩展密钥后的结果
 * @param ekm: 扩展密钥模块
 * @param cnt: 扩展内容
 * @param label: 标签
 * @param length: 扩展后的密钥长度
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_ekm_invoke(gquic_str_t *const ret,
                                       gquic_tls_ekm_t *const ekm,
                                       const gquic_str_t *const cnt, const gquic_str_t *const label, const size_t length);

/**
 * 根据指定的加密套件设定扩展密钥管理模块
 *
 * @param ekm: 扩展密钥管理模块
 * @param cipher_suite: 加密套件
 * @param master_sec: 扩展密钥的基础secret
 * @param transport: mac
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cipher_suite_export_keying_material(gquic_tls_ekm_t *const ekm,
                                                                const gquic_tls_cipher_suite_t *const cipher_suite,
                                                                const gquic_str_t *const master_sec, gquic_tls_mac_t *const transport);

#endif
