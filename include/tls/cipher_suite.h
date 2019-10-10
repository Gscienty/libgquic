#ifndef _LIBGQUIC_TLS_CIPHER_SUITE_H
#define _LIBGQUIC_TLS_CIPHER_SUITE_H

#include "tls/key_schedule.h"
#include "tls/config.h"
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


typedef struct gquic_tls_mac_func_s gquic_tls_mac_func_t;
struct gquic_tls_mac_func_s {
    HMAC_CTX *ctx;
    size_t (*size)();
    int (*mac)(gquic_str_t *const,
               const gquic_tls_mac_func_t *const,
               const gquic_str_t *const,
               const gquic_str_t *const,
               const gquic_str_t *const,
               const gquic_str_t *const);
};

int gquic_tls_mac_func_init(gquic_tls_mac_func_t *const);
int gquic_tls_mac_func_reset(gquic_tls_mac_func_t *const);

typedef struct gquic_tls_aead_ctx_s gquic_tls_aead_ctx_t;
struct gquic_tls_aead_ctx_s {
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
};

typedef struct gquic_tls_aead_s gquic_tls_aead_t;
struct gquic_tls_aead_s {
    gquic_tls_aead_ctx_t ctx;
    int (*seal)(gquic_str_t *const,
                gquic_str_t *const,
                gquic_tls_aead_ctx_t *const,
                const gquic_str_t *const,
                const gquic_str_t *const);
    int (*open)(gquic_str_t *const,
                gquic_tls_aead_ctx_t *const,
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
    const gquic_tls_key_aggrement_t *ka;
    int flags;
    u_int32_t hash;

    int (*cipher_encrypt) (EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);
    int (*mac) (gquic_tls_mac_func_t *const, const u_int16_t, const gquic_str_t *const);
    int (*aead) (gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

#endif
