/* src/tls/cipher_suite.c TLS 加密套件
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "tls/cipher_suite.h"
#include "tls/key_agreement.h"
#include "tls/key_schedule.h"
#include "util/malloc.h"
#include "exception.h"
#include <string.h>
#include <openssl/sha.h>

/**
 * AEAD加密/解密的context
 */
typedef struct gquic_tls_aead_ctx_s gquic_tls_aead_ctx_t;
struct gquic_tls_aead_ctx_s {
    const EVP_CIPHER *cipher;
    gquic_str_t nonce;
    gquic_str_t key;

    gquic_exception_t (*nonce_wrapper) (gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

/**
 * 初始化AEAD context
 *
 * @param ctx: context
 *
 * @return: exception
 */
static gquic_exception_t gquic_tls_aead_ctx_init(gquic_tls_aead_ctx_t *const ctx);

/**
 * 析构AEAD context
 *
 * @param ctx: context
 *
 * @return: exception
 */
static gquic_exception_t gquic_tls_aead_ctx_dtor(gquic_tls_aead_ctx_t *const ctx);

/**
 * 构造密钥协商与认证：使用ECDHE进行密钥协商，RSA用于身份认证
 *
 * @param ka: 密钥协商模块
 * @param ver: 版本号
 *
 * @return: exception
 */
static gquic_exception_t ecdhe_rsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver);

/**
 * 构造密钥协商与认证：使用ECDHE进行密钥协商，ECDSA用于身份认证
 *
 * @param ka: 密钥协商模块
 * @param ver: 版本号
 *
 * @return: exception
 */
static gquic_exception_t ecdhe_ecdsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver);

/**
 * 构造密钥协商与认证：使用RSA进行密钥协商和身份认证
 *
 * @param ka: 密钥协商模块
 * @param ver: 版本
 *
 * @return: exception
 */
static gquic_exception_t rsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);

/**
 * 根据EVP_CIPHER构造加密套件
 *
 * @param ret: 加密套件
 * @param cipher: EVP_CIPHER
 * @param key: 密钥
 * @param iv: iv
 * @param is_read: 是否用于解密
 *
 * @return: exception
 */
static gquic_exception_t cipher_common(gquic_tls_cipher_t *const ret,
                                       const EVP_CIPHER *const cipher,
                                       const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read);

/**
 * 构造RC4加密套件
 *
 * @param ret: 加密套件
 * @param key: 密钥
 * @param iv: iv
 * @param is_read: 是否用于解密
 *
 * @return: exception
 */
static gquic_exception_t cipher_rc4(gquic_tls_cipher_t *const ret,
                                    const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read);

/**
 * 构造3DES加密套件
 *
 * @param ret: 加密套件
 * @param key: 密钥
 * @param iv: iv
 * @param is_read: 是否用于解密
 *
 * @return: exception
 */
static gquic_exception_t cipher_3des(gquic_tls_cipher_t *const ret,
                                     const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read);

/**
 * 构造AES加密套件
 *
 * @param ret: 加密套件
 * @param key: 密钥
 * @param iv: iv
 * @param is_read: 是否用于解密
 *
 * @return: exception
 */
static gquic_exception_t cipher_aes(gquic_tls_cipher_t *const ret,
                                    const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read);

/**
 * 初始化MAC
 *
 * @param mac: mac
 * @param ver: 版本号
 * @param md: EVP_MD
 * @param key: 签名密钥
 *
 * @return: exception
 */
static gquic_exception_t mac_common_init(gquic_tls_mac_t *const mac,
                                         const u_int16_t ver, const EVP_MD *const md, const gquic_str_t *const key);

/**
 * 初始化MAC，使用的哈希算法为SHA1
 *
 * @param mac: mac
 * @param ver: 版本号
 * @param md: EVP_MD
 * @param key: 签名密钥
 *
 * @return: exception
 */
static gquic_exception_t mac_sha1_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key);

/**
 * 初始化MAC，使用的哈希算法为SHA256
 *
 * @param mac: mac
 * @param ver: 版本号
 * @param md: EVP_MD
 * @param key: 签名密钥
 *
 * @return: exception
 */
static gquic_exception_t mac_sha256_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key);

/**
 * 初始化MAC，使用的哈希算法为SHA384
 *
 * @param mac: mac
 * @param ver: 版本号
 * @param md: EVP_MD
 * @param key: 签名密钥
 *
 * @return: exception
 */
static gquic_exception_t mac_sha384_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key);

/**
 * AEAD加密
 *
 * @param tag: 存放加密后的tag结果
 * @param cipher_text: 存放加密后的密文结果
 * @param ctx: EVP_CIPHER_CTX
 * @param plain_text: 明文
 * @param addata: addata
 *
 * @return: exception
 */
static gquic_exception_t aead_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                   EVP_CIPHER_CTX *const ctx,
                                   const gquic_str_t *const plain_text, const gquic_str_t *const addata);

/**
 * AEAD解密
 *
 * @param plain_text: 存放解密后的明文
 * @param ctx: EVP_CIPHER_CTX
 * @param tag: tag
 * @param cipher_text: 密文
 * @param addata: addata
 *
 * @return: exception
 */
static gquic_exception_t aead_open(gquic_str_t *const plain_text,
                                   EVP_CIPHER_CTX *const ctx,
                                   const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata);

static gquic_exception_t gquic_tls_aead_seal(gquic_str_t *const, gquic_str_t *const,
                                             void *const,
                                             const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);

static gquic_exception_t gquic_tls_aead_open(gquic_str_t *const,
                                             void *const,
                                             const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);

/**
 * 根据固定nonce前缀生成加密或解密IV
 *
 * @param ret: 存放生成的iv
 * @param prefix: iv前缀
 * @param nonce: nonce
 *
 * @return: exception
 */
static gquic_exception_t aead_prefix_nonce_wrapper(gquic_str_t *const ret, const gquic_str_t *const prefix, const gquic_str_t *const nonce);

/**
 * 根据固定nonce异或生成加密或解密IV
 *
 * @param ret: 存放生成的iv
 * @param prefix: iv前缀
 * @param nonce: nonce
 *
 * @return: exception
 */
static gquic_exception_t aead_xor_nonce_wrapper(gquic_str_t *const ret, const gquic_str_t *const prefix, const gquic_str_t *const nonce);

/**
 * 析构AEAD context
 *
 * @param self: context
 *
 * @return: exception
 */
static gquic_exception_t aead_ctx_dtor(void *self);
static inline gquic_exception_t aead_aes_gcm_init(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static inline gquic_exception_t aead_chacha20_poly1305_init(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static gquic_exception_t aead_aes_gcm_init_prefix(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static gquic_exception_t aead_chacha20_poly1305_init_prefix(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static gquic_exception_t aead_aes_gcm_init_xor(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static gquic_exception_t aead_chacha20_poly1305_init_xor(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);

/**
 * 本项目所支持的所有加密套件
 */
static gquic_tls_cipher_suite_t cipher_suites[] = {
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_TLS12, 0, NULL, NULL, aead_chacha20_poly1305_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdhe_ecdsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_EC_SIGN | GQUIC_TLS_SUITE_TLS12, 0, NULL, NULL, aead_chacha20_poly1305_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_TLS12, 0, NULL, NULL, aead_aes_gcm_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_TLS12, 0, NULL, NULL, aead_aes_gcm_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_TLS12 | GQUIC_TLS_SUITE_SHA384, 0, NULL, NULL, aead_aes_gcm_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdhe_ecdsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_EC_SIGN | GQUIC_TLS_SUITE_TLS12 | GQUIC_TLS_SUITE_SHA384, 0, NULL, NULL, aead_aes_gcm_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_TLS12 | GQUIC_TLS_SUITE_DEF, 0, cipher_aes, mac_sha256_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE, 0, cipher_aes, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdhe_ecdsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_EC_SIGN | GQUIC_TLS_SUITE_TLS12 | GQUIC_TLS_SUITE_DEF, 0, cipher_aes, mac_sha256_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdhe_ecdsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_EC_SIGN, 0, cipher_aes, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE, 0, cipher_aes, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdhe_ecdsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_EC_SIGN, 0, cipher_aes, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsa_ka, GQUIC_TLS_SUITE_TLS12, 0, NULL, NULL, aead_aes_gcm_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsa_ka, GQUIC_TLS_SUITE_TLS12 | GQUIC_TLS_SUITE_SHA384, 0, NULL, NULL, aead_aes_gcm_init_prefix },
    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsa_ka, GQUIC_TLS_SUITE_TLS12 | GQUIC_TLS_SUITE_DEF, 0, cipher_aes, mac_sha256_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsa_ka, 0, 0, cipher_aes, mac_sha256_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsa_ka, 0, 0, cipher_aes, mac_sha256_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE, 0, cipher_3des, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsa_ka, 0, 0, cipher_3des, mac_sha1_init, NULL },

    { GQUIC_TLS_CIPHER_SUITE_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsa_ka, GQUIC_TLS_SUITE_DEF, 0, cipher_rc4, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdhe_rsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_DEF, 0, cipher_rc4, mac_sha1_init, NULL },
    { GQUIC_TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdhe_ecdsa_ka, GQUIC_TLS_SUITE_ECDHE | GQUIC_TLS_SUITE_EC_SIGN | GQUIC_TLS_SUITE_DEF, 0, cipher_rc4, mac_sha1_init, NULL },

    { GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256, 16, 0, 12, NULL, 0, GQUIC_TLS_HASH_SHA256, NULL, mac_sha256_init, aead_aes_gcm_init_xor },
    { GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256, 32, 0, 12, NULL, 0, GQUIC_TLS_HASH_SHA256, NULL, mac_sha256_init, aead_chacha20_poly1305_init_xor },
    { GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384, 32, 0, 12, NULL, 0, GQUIC_TLS_HASH_SHA384, NULL, mac_sha384_init, aead_aes_gcm_init_xor },
};
static const int cipher_suites_count = sizeof(cipher_suites) / sizeof(gquic_tls_cipher_suite_t);

gquic_exception_t gquic_tls_get_cipher_suite(const gquic_tls_cipher_suite_t **const cipher, const u_int16_t cipher_suite_id) {
    if (cipher == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    int i;
    for (i = 0; i < cipher_suites_count; i++) {
        if (cipher_suites[i].id == cipher_suite_id) {
           *cipher = &cipher_suites[i]; 
           GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
}

gquic_exception_t gquic_tls_choose_cipher_suite(const gquic_tls_cipher_suite_t **const cipher_suite,
                                                const gquic_list_t *const have, const u_int16_t want) {
    u_int16_t *have_cipher_suite_id;
    if (cipher_suite == NULL || have == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LIST_FOREACH(have_cipher_suite_id, have) {
        if (*have_cipher_suite_id == want) {
            GQUIC_ASSERT_FAST_RETURN(gquic_tls_get_cipher_suite(cipher_suite, want));
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }
    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
}

gquic_exception_t gquic_tls_create_aead(gquic_tls_aead_t *const aead,
                                        const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t key = { 0, NULL };
    gquic_str_t iv = { 0, NULL };
    gquic_tls_mac_t hash;
    static const gquic_str_t key_label = { 8, "quic key" };
    static const gquic_str_t iv_label = { 7, "quic iv" };
    if (aead == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(&hash);
    GQUIC_ASSERT_FAST_RETURN(suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(&key, &hash, traffic_sec, NULL, &key_label, suite->key_len))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(&iv, &hash, traffic_sec, NULL, &iv_label, suite->key_len))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, suite->aead(aead, &key, &iv))) {
        goto failure;
    }

    gquic_str_reset(&key);
    gquic_str_reset(&iv);
    gquic_tls_mac_dtor(&hash);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:

    gquic_str_reset(&key);
    gquic_str_reset(&iv);
    gquic_tls_mac_dtor(&hash);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_tls_mac_hmac_hash(gquic_str_t *const ret,
                                          gquic_tls_mac_t *const mac,
                                          const gquic_str_t *const seq, const gquic_str_t *const header,
                                          const gquic_str_t *const data, const gquic_str_t *const extra) {
    unsigned int size;
    (void) extra;
    if (ret == NULL || mac == NULL || mac->mac == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, HMAC_size(mac->mac)));
    if (seq != NULL && HMAC_Update(mac->mac, GQUIC_STR_VAL(seq), GQUIC_STR_SIZE(seq)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HMAC_FAILED);
    }
    if (header != NULL && HMAC_Update(mac->mac, GQUIC_STR_VAL(header), GQUIC_STR_SIZE(header)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HMAC_FAILED);
    }
    if (HMAC_Update(mac->mac, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HMAC_FAILED);
    }
    if (HMAC_Final(mac->mac, GQUIC_STR_VAL(ret), &size) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HMAC_FAILED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_md_hash(gquic_str_t *const ret, gquic_tls_mac_t *const mac, const gquic_str_t *const data) {
    unsigned int size;
    if (ret == NULL || mac == NULL || mac->md_ctx == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, EVP_MD_CTX_size(mac->md_ctx)));
    EVP_DigestUpdate(mac->md_ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data));
    EVP_DigestFinal_ex(mac->md_ctx, GQUIC_STR_VAL(ret), &size);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_md_update(gquic_tls_mac_t *const mac, const gquic_str_t *const data) {
    if (mac == NULL || mac->md_ctx == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (EVP_DigestUpdate(mac->md_ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_md_reset(gquic_tls_mac_t *const mac) {
    if (mac == NULL || mac->md_ctx == NULL) {
        GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    const EVP_MD *md = EVP_MD_CTX_md(mac->md_ctx);
    if (EVP_MD_CTX_reset(mac->md_ctx) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    if (EVP_DigestInit_ex(mac->md_ctx, md, NULL) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_md_sum(gquic_str_t *const ret, gquic_tls_mac_t *const mac) {
    unsigned int size = 0;
    EVP_MD_CTX *output_ctx = NULL;
    if (ret == NULL || mac == NULL || mac->md_ctx == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if ((output_ctx = EVP_MD_CTX_new()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if (EVP_MD_CTX_copy_ex(output_ctx, mac->md_ctx) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, EVP_MD_CTX_size(output_ctx)));
    if (EVP_DigestFinal_ex(output_ctx, GQUIC_STR_VAL(ret), &size) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DIGEST_FAILED);
    }
    EVP_MD_CTX_free(output_ctx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_md_copy(gquic_tls_mac_t *const ret, gquic_tls_mac_t *const origin) {
    if (ret == NULL || origin == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ret->md = origin->md;
    if ((ret->md_ctx = EVP_MD_CTX_new()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if (EVP_MD_CTX_copy_ex(ret->md_ctx, origin->md_ctx) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_aead_dtor(gquic_tls_aead_t *const aead) {
    if (aead == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_TLS_AEAD_DTOR(aead);
    if (aead->self != NULL) {
        gquic_free(aead->self);
        aead->self = NULL;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_aead_init(gquic_tls_aead_t *const aead) {
    if (aead == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    aead->self = NULL;
    aead->open = NULL;
    aead->seal = NULL;
    aead->dtor = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_aead_copy(gquic_tls_aead_t *const aead, const gquic_tls_aead_t *const ref) {
    if (aead == NULL || ref == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    aead->self = ref->self;
    aead->open = ref->open;
    aead->seal = ref->seal;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_init(gquic_tls_cipher_t *const cipher) {
    if (cipher == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cipher->cipher = NULL;
    gquic_str_init(&cipher->iv);
    gquic_str_init(&cipher->key);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_dtor(gquic_tls_cipher_t *const cipher) {
    if (cipher == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cipher->cipher != NULL) {
        EVP_CIPHER_CTX_free(cipher->cipher);
    }
    gquic_str_reset(&cipher->iv);
    gquic_str_reset(&cipher->key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_encrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const plain_text) {
    if (ret == NULL || cipher == NULL || plain_text == NULL || cipher->cipher == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    int outlen = 0;
    gquic_str_init(ret);
    if (EVP_EncryptUpdate(cipher->cipher, NULL, &outlen, GQUIC_STR_VAL(plain_text), GQUIC_STR_SIZE(plain_text)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ENCRYPT_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, outlen + 32));
    if (EVP_EncryptUpdate(cipher->cipher, GQUIC_STR_VAL(ret), &outlen, GQUIC_STR_VAL(plain_text), GQUIC_STR_SIZE(plain_text)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ENCRYPT_FAILED);
    }
    ret->size = outlen;
    if (EVP_EncryptFinal_ex(cipher->cipher, GQUIC_STR_VAL(ret), &outlen) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ENCRYPT_FAILED);
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_decrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const cipher_text) {
    if (ret == NULL || cipher == NULL || cipher_text == NULL || cipher->cipher == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    int outlen = 0;
    gquic_str_init(ret);
    if (EVP_DecryptUpdate(cipher->cipher, NULL, &outlen, GQUIC_STR_VAL(cipher_text), GQUIC_STR_SIZE(cipher_text)) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DECRYPT_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, outlen + 32));
    if (EVP_DecryptUpdate(cipher->cipher, GQUIC_STR_VAL(ret), &outlen, GQUIC_STR_VAL(cipher_text), GQUIC_STR_SIZE(cipher_text)) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DECRYPT_FAILED);
    }
    ret->size = outlen;
    if (EVP_DecryptFinal_ex(cipher->cipher, GQUIC_STR_VAL(ret), &outlen) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DECRYPT_FAILED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_aead_ctx_init(gquic_tls_aead_ctx_t *const ctx) {
    if (ctx == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ctx->cipher = NULL;
    gquic_str_init(&ctx->nonce);
    gquic_str_init(&ctx->key);
    ctx->nonce_wrapper = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_aead_ctx_dtor(gquic_tls_aead_ctx_t *const ctx) {
    if (ctx == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&ctx->nonce);
    gquic_str_reset(&ctx->key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_init(gquic_tls_suite_t *const suite) {
    if (suite == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_aead_init(&suite->aead);
    gquic_tls_cipher_init(&suite->cipher);
    gquic_tls_mac_init(&suite->mac);
    suite->type = GQUIC_TLS_CIPHER_TYPE_UNKNOW;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_ctor(gquic_tls_suite_t *const suite,
                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                       const gquic_str_t *const iv, const gquic_str_t *const cipher_key, const gquic_str_t *const mac_key,
                                       const bool is_read) {
    if (suite == NULL || cipher_suite == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cipher_suite->aead != NULL && cipher_key != NULL && iv != NULL) {
        if (cipher_suite->key_len > GQUIC_STR_SIZE(cipher_key)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_OR_IV_LENGTH_UNEXCEPTED);
        }
        GQUIC_ASSERT_FAST_RETURN(cipher_suite->aead(&suite->aead, cipher_key, iv));
        suite->type = GQUIC_TLS_CIPHER_TYPE_AEAD;
    }
    if (cipher_suite->cipher_encrypt != NULL && cipher_key != NULL && iv != NULL) {
        if (cipher_suite->key_len != GQUIC_STR_SIZE(cipher_key) || cipher_suite->iv_len != GQUIC_STR_SIZE(iv)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_OR_IV_LENGTH_UNEXCEPTED);
        }
        GQUIC_ASSERT_FAST_RETURN(cipher_suite->cipher_encrypt(&suite->cipher, cipher_key, iv, is_read));
        suite->type = GQUIC_TLS_CIPHER_TYPE_STREAM;
    }
    if (cipher_suite->mac != NULL && mac_key != NULL) {
        if (cipher_suite->mac_len != GQUIC_STR_SIZE(mac_key)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_MAC_LENGTH_UNEXCEPTED);
        }
        GQUIC_ASSERT_FAST_RETURN(cipher_suite->mac(&suite->mac, 0, mac_key));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_encrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const plain_text) {
    if (result == NULL || suite == NULL || plain_text == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_encrypt(result, &suite->cipher, plain_text));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_aead_encrypt(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                               gquic_tls_suite_t *const suite,
                                               const gquic_str_t *const nonce, const gquic_str_t *const plain_text, const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || suite == NULL || nonce == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_AEAD_SEAL(tag, cipher_text, &suite->aead, nonce, plain_text, addata));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_decrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const cipher_text) {
    if (result == NULL || suite == NULL || cipher_text == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_decrypt(result, &suite->cipher, cipher_text));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_aead_decrypt(gquic_str_t *const plain_text,
                                               gquic_tls_suite_t *const suite,
                                               const gquic_str_t *const nonce, const gquic_str_t *const tag,
                                               const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    if (plain_text == NULL || suite == NULL || nonce == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_AEAD_OPEN(plain_text, &suite->aead, nonce, tag, cipher_text, addata));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_init(gquic_tls_mac_t *const mac) {
    if (mac == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    mac->mac = NULL;
    mac->md = NULL;
    mac->md_ctx = NULL;
    gquic_str_init(&mac->key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_mac_dtor(gquic_tls_mac_t *const mac) {
    if (mac == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (mac->mac != NULL) {
        HMAC_CTX_free(mac->mac);
    }
    if (mac->md_ctx != NULL) {
        EVP_MD_CTX_free(mac->md_ctx);
    }
    gquic_str_reset(&mac->key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_suite_hmac_hash(gquic_str_t *const hash,
                                            gquic_tls_suite_t *const suite,
                                            const gquic_str_t *const seq, const gquic_str_t *const header,
                                            const gquic_str_t *const data, const gquic_str_t *const extra) {
    if (hash == NULL || suite == NULL || data == NULL || suite->mac.mac == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_mac_hmac_hash(hash, &suite->mac, seq, header, data, extra));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t ecdhe_rsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver) {
    if (ka == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_key_agreement_ecdhe_init(ka);
    gquic_tls_key_agreement_ecdhe_set_version(ka, ver);
    gquic_tls_key_agreement_ecdhe_set_is_rsa(ka, 1);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t ecdhe_ecdsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver) {
    if (ka == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_key_agreement_ecdhe_init(ka);
    gquic_tls_key_agreement_ecdhe_set_version(ka, ver);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t rsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver) {
    (void) ver;
    if (ka == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_key_agreement_rsa_init(ka);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_aead_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                             void *const aead,
                                             const gquic_str_t *const nonce, const gquic_str_t *const plain_text, const gquic_str_t *const addata) {

    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t iv;
    EVP_CIPHER_CTX *ctx = NULL;
    gquic_tls_aead_ctx_t *aead_ctx = aead;
    if (tag == NULL || cipher_text == NULL || aead == NULL || plain_text == NULL || addata == NULL || aead_ctx->nonce_wrapper == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&iv);
    if (GQUIC_ASSERT_CAUSE(exception, aead_ctx->nonce_wrapper(&iv, &aead_ctx->nonce, nonce))) {
        goto failure;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (EVP_EncryptInit_ex(ctx, aead_ctx->cipher, NULL, NULL, NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(&iv), NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, GQUIC_STR_VAL(&aead_ctx->key), GQUIC_STR_VAL(&iv)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }

    if (GQUIC_ASSERT_CAUSE(exception, aead_seal(tag, cipher_text, ctx, plain_text, addata))) {
        goto failure;
    }

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_tls_aead_open(gquic_str_t *const plain_text,
                                             void *const aead,
                                             const gquic_str_t *const nonce, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t iv;
    EVP_CIPHER_CTX *ctx = NULL;
    gquic_tls_aead_ctx_t *aead_ctx = aead;
    if (plain_text == NULL
        || tag == NULL
        || cipher_text == NULL
        || aead == NULL
        || cipher_text == NULL
        || addata == NULL
        || aead_ctx->nonce_wrapper == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&iv);
    if (GQUIC_ASSERT_CAUSE(exception, aead_ctx->nonce_wrapper(&iv, &aead_ctx->nonce, nonce))) {
        goto failure;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (EVP_DecryptInit_ex(ctx, aead_ctx->cipher, NULL, NULL, NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(&iv), NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, GQUIC_STR_VAL(&aead_ctx->key), GQUIC_STR_VAL(&iv)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }

    if (GQUIC_ASSERT_CAUSE(exception, aead_open(plain_text, ctx, tag, cipher_text, addata))) {
        goto failure;
    }

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t cipher_common(gquic_tls_cipher_t *const ret,
                                       const EVP_CIPHER *const cipher,
                                       const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read) {
    if (ret == NULL || cipher == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) EVP_CIPHER_key_length(cipher) != GQUIC_STR_SIZE(key)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_OR_IV_LENGTH_UNEXCEPTED);
    }
    if (iv != NULL && (size_t) EVP_CIPHER_iv_length(cipher) != GQUIC_STR_SIZE(iv)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_OR_IV_LENGTH_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ret->key, key));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ret->iv, iv));

    if (is_read) {
        EVP_DecryptInit_ex(ret->cipher, cipher, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(iv));
    }
    else {
        EVP_EncryptInit_ex(ret->cipher, cipher, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(iv));
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t cipher_rc4(gquic_tls_cipher_t *const ret,
                                    const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read) {
    if (ret == NULL || key == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    return cipher_common(ret, EVP_rc4(), key, iv, is_read);
}

static gquic_exception_t cipher_3des(gquic_tls_cipher_t *const ret,
                                     const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read) {
    if (ret == NULL || key == NULL || iv == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    return cipher_common(ret, EVP_des_ede3_cbc(), key, iv, is_read);
}
static gquic_exception_t cipher_aes(gquic_tls_cipher_t *const ret,
                                    const gquic_str_t *const key, const gquic_str_t *const iv, const bool is_read) {
    if (ret == NULL || key == NULL || iv == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    return cipher_common(ret, EVP_aes_256_cbc(), key, iv, is_read);
}

static gquic_exception_t mac_common_init(gquic_tls_mac_t *const mac,
                                         const u_int16_t ver, const EVP_MD *const md, const gquic_str_t *const key) {
    (void) ver;
    if (mac == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(mac);
    mac->md = md;
    if (GQUIC_STR_SIZE(key) == 0) {
        mac->md_ctx = EVP_MD_CTX_new();
        if (EVP_DigestInit_ex(mac->md_ctx, mac->md, NULL) <= 0) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DIGEST_FAILED);
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&mac->key, key));
    mac->mac = HMAC_CTX_new();
    if (HMAC_Init_ex(mac->mac, GQUIC_STR_VAL(key), GQUIC_STR_SIZE(key), mac->md, NULL) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HMAC_FAILED);
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t mac_sha1_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key) {
    return mac_common_init(mac, ver, EVP_sha1(), key);
}

static gquic_exception_t mac_sha256_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key) {
    return mac_common_init(mac, ver, EVP_sha256(), key);
}

static gquic_exception_t mac_sha384_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key) {
    return mac_common_init(mac, ver, EVP_sha3_384(), key);
}

static gquic_exception_t aead_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                   EVP_CIPHER_CTX *const ctx, const gquic_str_t *const plain_text, const gquic_str_t *const addata) {
    int outlen = 0;
    if (tag == NULL || cipher_text == NULL || ctx == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(tag, 16));
    EVP_EncryptUpdate(ctx, NULL, &outlen, GQUIC_STR_VAL(addata), GQUIC_STR_SIZE(addata));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(cipher_text, GQUIC_STR_SIZE(addata) + GQUIC_STR_SIZE(plain_text)));
    EVP_EncryptUpdate(ctx, GQUIC_STR_VAL(cipher_text), &outlen, GQUIC_STR_VAL(plain_text), GQUIC_STR_SIZE(plain_text));
    cipher_text->size = outlen;
    EVP_EncryptFinal_ex(ctx, GQUIC_STR_VAL(cipher_text), &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, GQUIC_STR_VAL(tag));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_open(gquic_str_t *const ret,
                                   EVP_CIPHER_CTX *const ctx,
                                   const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    int outlen = 0;
    if (ret == NULL || tag == NULL || cipher_text == NULL || ctx == NULL || cipher_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    EVP_DecryptUpdate(ctx, NULL, &outlen, GQUIC_STR_VAL(addata), GQUIC_STR_SIZE(addata));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, GQUIC_STR_SIZE(cipher_text) + GQUIC_STR_SIZE(addata)));
    EVP_DecryptUpdate(ctx, GQUIC_STR_VAL(ret), &outlen, GQUIC_STR_VAL(cipher_text), GQUIC_STR_SIZE(cipher_text));
    ret->size = outlen;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GQUIC_STR_SIZE(tag), GQUIC_STR_VAL(tag));
    EVP_DecryptFinal_ex(ctx, GQUIC_STR_VAL(ret), &outlen);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_ctx_dtor(void *self) {
    return gquic_tls_aead_ctx_dtor(self);
}

static inline gquic_exception_t aead_aes_gcm_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&ctx, gquic_tls_aead_ctx_t));
    gquic_tls_aead_ctx_init(ctx);
    if ((size_t) EVP_CIPHER_key_length(EVP_aes_128_gcm()) == GQUIC_STR_SIZE(key)) {
        ctx->cipher = EVP_aes_128_gcm();
    }
    else if ((size_t) EVP_CIPHER_key_length(EVP_aes_192_gcm()) == GQUIC_STR_SIZE(key)) {
        ctx->cipher = EVP_aes_192_gcm();
    }
    else if ((size_t) EVP_CIPHER_key_length(EVP_aes_256_gcm()) == GQUIC_STR_SIZE(key)) {
        ctx->cipher = EVP_aes_256_gcm();
    }
    else {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_OR_IV_LENGTH_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ctx->nonce, nonce));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ctx->key, key));
    ret->self = ctx;
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    ret->dtor = aead_ctx_dtor;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t aead_chacha20_poly1305_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&ctx, gquic_tls_aead_ctx_t));
    gquic_tls_aead_ctx_init(ctx);
    ctx->cipher = EVP_chacha20_poly1305();
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ctx->nonce, nonce));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ctx->key, key));
    ret->self = ctx;
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    ret->dtor = aead_ctx_dtor;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_aes_gcm_init_prefix(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(aead_aes_gcm_init(ret, key, nonce));
    ctx = ret->self;
    ctx->nonce_wrapper = aead_prefix_nonce_wrapper;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_chacha20_poly1305_init_prefix(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    aead_chacha20_poly1305_init(ret, key, nonce);
    ctx = ret->self;
    ctx->nonce_wrapper = aead_prefix_nonce_wrapper;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_aes_gcm_init_xor(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(aead_aes_gcm_init(ret, key, nonce));
    ctx = ret->self;
    ctx->nonce_wrapper = aead_xor_nonce_wrapper;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_chacha20_poly1305_init_xor(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    aead_chacha20_poly1305_init(ret, key, nonce);
    ctx = ret->self;
    ctx->nonce_wrapper = aead_xor_nonce_wrapper;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_prefix_nonce_wrapper(gquic_str_t *const ret, const gquic_str_t *const base, const gquic_str_t *const nonce) {
    if (ret == NULL || base == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(ret);
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, 12));
    memcpy(GQUIC_STR_VAL(ret), GQUIC_STR_VAL(base), 4);
    memcpy(GQUIC_STR_VAL(ret) + 4, GQUIC_STR_VAL(nonce), 8);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t aead_xor_nonce_wrapper(gquic_str_t *const ret, const gquic_str_t *const base, const gquic_str_t *const nonce) {
    size_t i;
    if (ret == NULL || base == NULL || nonce == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(ret);
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(ret, base));
    for (i = 0; i < GQUIC_STR_SIZE(nonce); i++) {
        ((unsigned char *) GQUIC_STR_VAL(ret))[i + 4] ^= ((unsigned char *) GQUIC_STR_VAL(nonce))[i];
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_suite_expand_label(gquic_str_t *const ret,
                                                      const gquic_tls_cipher_suite_t *const cipher_suite,
                                                      const gquic_str_t *const secret, const gquic_str_t *const label, const gquic_str_t *const content, const size_t length) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_tls_mac_t hash;
    if (ret == NULL || cipher_suite == NULL || secret == NULL || label == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(&hash);
    GQUIC_ASSERT_FAST_RETURN(cipher_suite->mac(&hash, 0, NULL));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(ret, &hash, secret, content, label, length))) {
        gquic_tls_mac_dtor(&hash);
        GQUIC_PROCESS_DONE(exception);
    }

    gquic_tls_mac_dtor(&hash);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_suite_derive_secret(gquic_str_t *const ret,
                                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                                       gquic_tls_mac_t *const transport,
                                                       const gquic_str_t *const secret, const gquic_str_t *const label) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_tls_mac_t default_transport;
    gquic_str_t content = { 0, NULL };
    if (ret == NULL || cipher_suite == NULL || secret == NULL || label == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(&default_transport);
    if (transport != NULL
        && transport->md_ctx != NULL
        && GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_sum(&content, transport))) {
        GQUIC_PROCESS_DONE(exception);
    }
    else {
        cipher_suite->mac(&default_transport, 0, NULL);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_expand_label(ret,
                                                                 cipher_suite,
                                                                 secret,
                                                                 &content,
                                                                 label,
                                                                 EVP_MD_size(transport == NULL ? default_transport.md : transport->md)));

    gquic_tls_mac_dtor(&default_transport);
    gquic_str_reset(&content);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_suite_extract(gquic_str_t *const ret,
                                                 const gquic_tls_cipher_suite_t *const cipher_suite,
                                                 const gquic_str_t *const secret, const gquic_str_t *const salt) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_tls_mac_t hash;
    if (ret == NULL || cipher_suite == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(&hash);
    if (cipher_suite->mac == NULL || GQUIC_ASSERT_CAUSE(exception, cipher_suite->mac(&hash, 0, NULL))) {
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_extract(ret, &hash, secret, salt))) {
        gquic_tls_mac_dtor(&hash);
        GQUIC_PROCESS_DONE(exception);
    }

    gquic_tls_mac_dtor(&hash);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_suite_traffic_key(gquic_str_t *const key, gquic_str_t *const iv,
                                                     const gquic_tls_cipher_suite_t *const cipher_suite, const gquic_str_t *const traffic_sec) {
    static const gquic_str_t key_label = { 3, "key" };
    static const gquic_str_t iv_label = { 2, "iv" };
    if (key == NULL || iv == NULL || cipher_suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_expand_label(key, cipher_suite, traffic_sec, &key_label, NULL, cipher_suite->key_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_expand_label(iv, cipher_suite, traffic_sec, &iv_label, NULL, 12));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_suite_finished_hash(gquic_str_t *const hash,
                                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                                       const gquic_str_t *const base_key, gquic_tls_mac_t *const transport) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t finished_key = { 0, NULL };
    gquic_str_t verify_data = { 0, NULL };
    gquic_tls_mac_t mac;
    gquic_tls_mac_t tmp;
    gquic_tls_mac_init(&mac);
    gquic_tls_mac_init(&tmp);
    static const gquic_str_t label = { 8, "finished" };
    if (hash == NULL || cipher_suite == NULL || base_key == NULL || transport == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cipher_suite->mac(&tmp, GQUIC_TLS_VERSION_13, NULL);
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_expand_label(&finished_key, cipher_suite, base_key, &label, NULL, EVP_MD_size(tmp.md)))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, cipher_suite->mac(&mac, 0, &finished_key))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_sum(&verify_data, transport))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_hmac_hash(hash, &mac, NULL, NULL, &verify_data, NULL))) {
        goto failure;
    }

    gquic_str_reset(&finished_key);
    gquic_str_reset(&verify_data);
    gquic_tls_mac_dtor(&mac);
    gquic_tls_mac_dtor(&tmp);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&finished_key);
    gquic_str_reset(&verify_data);
    gquic_tls_mac_dtor(&mac);
    gquic_tls_mac_dtor(&tmp);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_tls_ekm_init(gquic_tls_ekm_t *const ekm) {
    if (ekm == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ekm->ekm = NULL;
    ekm->dtor = NULL;
    ekm->self = NULL;
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_ekm_dtor(gquic_tls_ekm_t *const ekm) {
    if (ekm == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (ekm->self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (ekm->dtor != NULL) {
        ekm->dtor(ekm->self);
        gquic_free(ekm->self);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_ekm_invoke(gquic_str_t *const ret,
                                       gquic_tls_ekm_t *const ekm,
                                       const gquic_str_t *const cnt, const gquic_str_t *const label, const size_t length) {
    if (ekm == NULL || ekm->ekm == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    return ekm->ekm(ret, ekm->self, cnt, label, length);
}

typedef struct gquic_tls_ekm_keying_material_s gquic_tls_ekm_keying_material_t;
struct gquic_tls_ekm_keying_material_s {
    const gquic_tls_cipher_suite_t *cipher_suite;
    gquic_str_t exp_master_sec;
};

static gquic_exception_t gquic_tls_ekm_keying_material_invoke(gquic_str_t *const ret,
                                                              void *self,
                                                              const gquic_str_t *const cnt, const gquic_str_t *const label, const size_t length) {
    gquic_tls_mac_t hash;
    gquic_str_t sec = { 0, NULL };
    gquic_str_t cnt_hash = { 0, NULL };
    static const gquic_str_t exporter_label = { 8, "exporter" };
    gquic_tls_ekm_keying_material_t *ekm_self = self;
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (ret == NULL || self == NULL || cnt == NULL || label == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_derive_secret(&sec, ekm_self->cipher_suite, NULL, &ekm_self->exp_master_sec, label));
    gquic_tls_mac_init(&hash);
    if (GQUIC_ASSERT_CAUSE(exception, ekm_self->cipher_suite->mac(&hash, 0, NULL))) {
        gquic_str_reset(&sec);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&hash, cnt))) {
        gquic_str_reset(&sec);
        gquic_tls_mac_dtor(&hash);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_sum(&cnt_hash, &hash))) {
        gquic_str_reset(&sec);
        gquic_tls_mac_dtor(&hash);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_expand_label(ret, ekm_self->cipher_suite, &sec, &exporter_label, &cnt_hash, length))) {
        gquic_str_reset(&sec);
        gquic_str_reset(&cnt_hash);
        gquic_tls_mac_dtor(&hash);
        GQUIC_PROCESS_DONE(exception);
    }

    gquic_str_reset(&sec);
    gquic_str_reset(&cnt_hash);
    gquic_tls_mac_dtor(&hash);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_ekm_keying_material_dtor(void *self) {
    gquic_tls_ekm_keying_material_t *ekm_self = self;
    if (self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&ekm_self->exp_master_sec);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_cipher_suite_export_keying_material(gquic_tls_ekm_t *const ekm,
                                                                const gquic_tls_cipher_suite_t *const cipher_suite,
                                                                const gquic_str_t *const master_sec, gquic_tls_mac_t *const transport) {
    static const gquic_str_t exporter_label = { 10, "exp master" };
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (ekm == NULL || cipher_suite == NULL || master_sec == NULL || transport == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_ekm_keying_material_t *self = NULL;
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&self, gquic_tls_ekm_keying_material_t));
    self->cipher_suite = cipher_suite;
    gquic_str_init(&self->exp_master_sec);
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&self->exp_master_sec, cipher_suite, transport, master_sec, &exporter_label))) {
        gquic_free(self);
        GQUIC_PROCESS_DONE(exception);
    }

    ekm->self = self;
    ekm->ekm = gquic_tls_ekm_keying_material_invoke;
    ekm->dtor = gquic_tls_ekm_keying_material_dtor;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
