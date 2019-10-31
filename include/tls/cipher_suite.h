#ifndef _LIBGQUIC_TLS_CIPHER_SUITE_H
#define _LIBGQUIC_TLS_CIPHER_SUITE_H

#include "tls/key_agreement.h"
#include "util/str.h"
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

#define GQUIC_TLS_AEAD_SEAL(tag, cipher_text, aead, nonce, plain_text, addata) \
    (((aead)->seal) == NULL \
    ? -1 \
    : ((aead)->seal((tag), (cipher_text), &(aead)->ctx, (nonce), (plain_text), (addata))))

#define GQUIC_TLS_AEAD_OPEN(plain_text, aead, nonce, tag, cipher_text, addata) \
    (((aead)->open) == NULL \
     ? -1 \
     : ((aead)->open((plain_text), &(aead)->ctx, (nonce), (tag), (cipher_text), (addata))))

int gquic_tls_aead_init(gquic_tls_aead_t *const aead);
int gquic_tls_aead_release(gquic_tls_aead_t *const aead);

typedef struct gquic_tls_cipher_s gquic_tls_cipher_t;
struct gquic_tls_cipher_s {
    EVP_CIPHER_CTX *cipher;
    gquic_str_t key;
    gquic_str_t iv;
};
int gquic_tls_cipher_init(gquic_tls_cipher_t *const cipher);
int gquic_tls_cipher_release(gquic_tls_cipher_t *const cipher);
int gquic_tls_cipher_encrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const plain_text);
int gquic_tls_cipher_decrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const cipher_text);

typedef struct gquic_tls_mac_s gquic_tls_mac_t;
struct gquic_tls_mac_s {
    HMAC_CTX *mac;
    gquic_str_t key;
};
int gquic_tls_mac_init(gquic_tls_mac_t *const mac);
int gquic_tls_mac_release(gquic_tls_mac_t *const mac);
int gquic_tls_mac_hash(gquic_str_t *const ret,
                       gquic_tls_mac_t *const mac,
                       const gquic_str_t *const seq,
                       const gquic_str_t *const header,
                       const gquic_str_t *const data,
                       const gquic_str_t *const extra);

typedef struct gquic_tls_cipher_suite_s gquic_tls_cipher_suite_t;
struct gquic_tls_cipher_suite_s {
    u_int16_t id;
    size_t key_len;
    size_t mac_len;
    size_t iv_len;
    int (*ka) (gquic_tls_key_agreement_t *const, const u_int16_t);
    int flags;
    u_int16_t hash;

    int (*cipher_encrypt) (gquic_tls_cipher_t *const, const gquic_str_t *const, const gquic_str_t *const, const int);
    int (*mac) (gquic_tls_mac_t *const, const u_int16_t, const gquic_str_t *const);
    int (*aead) (gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

int gquic_tls_get_cipher_suite(const gquic_tls_cipher_suite_t **const cipher_suite, const u_int16_t cipher_suite_id);
int gquic_tls_choose_cipher_suite(const gquic_tls_cipher_suite_t **const cipher_suite, const gquic_list_t *const have, const u_int16_t want);

#define GQUIC_TLS_CIPHER_TYPE_UNKNOW 0
#define GQUIC_TLS_CIPHER_TYPE_STREAM 1
#define GQUIC_TLS_CIPHER_TYPE_AEAD 2
#define GQUIC_TLS_CIPHER_TYPE_CBC 3

typedef struct gquic_tls_suite_s gquic_tls_suite_t;
struct gquic_tls_suite_s {
    u_int8_t type;
    gquic_tls_cipher_t cipher;
    gquic_tls_aead_t aead;
    gquic_tls_mac_t mac;
};

int gquic_tls_suite_init(gquic_tls_suite_t *const suite);
int gquic_tls_suite_assign(gquic_tls_suite_t *const suite,
                           const gquic_tls_cipher_suite_t *const cipher_suite,
                           const gquic_str_t *const iv,
                           const gquic_str_t *const cipher_key,
                           const gquic_str_t *const mac_key,
                           const int is_read);
int gquic_tls_suite_encrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const plain_text);
int gquic_tls_suite_aead_encrypt(gquic_str_t *const tag,
                                 gquic_str_t *const cipher_text,
                                 gquic_tls_suite_t *const suite,
                                 const gquic_str_t *const nonce,
                                 const gquic_str_t *const plain_text,
                                 const gquic_str_t *const addata);
int gquic_tls_suite_decrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const cipher_text);
int gquic_tls_suite_aead_decrypt(gquic_str_t *const plain_text,
                                 gquic_tls_suite_t *const suite,
                                 const gquic_str_t *const nonce,
                                 const gquic_str_t *const tag,
                                 const gquic_str_t *const cipher_text,
                                 const gquic_str_t *const addata);
int gquic_tls_suite_hash(gquic_str_t *const hash,
                         gquic_tls_suite_t *const suite,
                         const gquic_str_t *const seq,
                         const gquic_str_t *const header,
                         const gquic_str_t *const data,
                         const gquic_str_t *const extra);
size_t gquic_tls_suite_nonce_size(const gquic_tls_suite_t *const suite);
size_t gquic_tls_suite_mac_size(const gquic_tls_suite_t *const suite);


#endif
