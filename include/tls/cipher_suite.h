#ifndef _LIBGQUIC_TLS_CIPHER_SUITE_H
#define _LIBGQUIC_TLS_CIPHER_SUITE_H

#include "tls/key_schedule.h"
#include "tls/key_agreement.h"
#include <sys/types.h>
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

int gquic_tls_mac_func(gquic_str_t *const ret,
                       HMAC_CTX *const ctx,
                       const gquic_str_t *const seq,
                       const gquic_str_t *const header,
                       const gquic_str_t *const data,
                       const gquic_str_t *const extra);

typedef struct gquic_tls_aead_ctx_s gquic_tls_aead_ctx_t;
struct gquic_tls_aead_ctx_s {
    const EVP_CIPHER *cipher;
    gquic_str_t nonce;
    gquic_str_t key;

    int (*nonce_wrapper) (gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

int gquic_tls_aead_ctx_init(gquic_tls_aead_ctx_t *const ctx);

typedef struct gquic_tls_aead_s gquic_tls_aead_t;
struct gquic_tls_aead_s {
    gquic_tls_aead_ctx_t ctx;
    int (*seal)(gquic_str_t *const,
                gquic_str_t *const,
                gquic_tls_aead_ctx_t *const,
                const gquic_str_t *const,
                const gquic_str_t *const,
                const gquic_str_t *const);
    int (*open)(gquic_str_t *const,
                gquic_tls_aead_ctx_t *const,
                const gquic_str_t *const,
                const gquic_str_t *const,
                const gquic_str_t *const,
                const gquic_str_t *const);
};

#define GQUIC_TLS_AEAD_SEAL(tag, cipher_text, aead, plain_text, addata) \
    ((aead)->seal((tag), (cipher_text), &(aead)->ctx, (plain_text), (addata)))

#define GQUIC_TLS_AEAD_OPEN(plain_text, aead, tag, cipher_text, addata) \
    ((aead)->open((plain_text), &(aead)->ctx, (tag), (cipher_text), (addata)))

int gquic_tls_aead_release(gquic_tls_aead_t *const);

typedef struct gquic_tls_cipher_suite_s gquic_tls_cipher_suite_t;
struct gquic_tls_cipher_suite_s {
    u_int16_t id;
    size_t key_len;
    size_t mac_len;
    size_t iv_len;
    int (*ka) (gquic_tls_key_agreement_t *const, const u_int16_t);
    int flags;
    u_int16_t hash;

    int (*cipher_encrypt) (EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);
    int (*mac) (HMAC_CTX **const, const u_int16_t, const gquic_str_t *const);
    int (*aead) (gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

#endif
