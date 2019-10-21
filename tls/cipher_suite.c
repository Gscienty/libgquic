#include "tls/cipher_suite.h"
#include "tls/key_agreement.h"
#include <malloc.h>
#include <string.h>
#include <openssl/sha.h>

static int ecdhe_rsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);
static int ecdhe_ecdsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);
static int rsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);

static int cipher_common(EVP_CIPHER_CTX **const,
                         const EVP_CIPHER *const,
                         const gquic_str_t *const,
                         const gquic_str_t *const,
                         const int);
static int cipher_rc4(EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);
static int cipher_3des(EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);
static int cipher_aes(EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);

static int mac_sha1_init(HMAC_CTX **const, const u_int16_t, const gquic_str_t *const);
static int mac_sha256_init(HMAC_CTX **const, const u_int16_t, const gquic_str_t *const);

static int aead_seal(gquic_str_t *const,
                     gquic_str_t *const,
                     EVP_CIPHER_CTX *const,
                     const gquic_str_t *const,
                     const gquic_str_t *const);
static int aead_open(gquic_str_t *const,
                     EVP_CIPHER_CTX *const,
                     const gquic_str_t *const,
                     const gquic_str_t *const,
                     const gquic_str_t *const);

static int gquic_tls_aead_seal(gquic_str_t *const,
                               gquic_str_t *const,
                               gquic_tls_aead_ctx_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const);

static int gquic_tls_aead_open(gquic_str_t *const,
                               gquic_tls_aead_ctx_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const);

static int aead_prefix_nonce_wrapper(gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_xor_nonce_wrapper(gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);

static inline int aead_aes_gcm_init(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static inline int aead_chacha20_poly1305_init(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_aes_gcm_init_prefix(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_chacha20_poly1305_init_prefix(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_aes_gcm_init_xor(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_chacha20_poly1305_init_xor(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);

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

    { GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256, 16, 0, 0, NULL, 0, GQUIC_TLS_HASH_SHA256, NULL, NULL, aead_aes_gcm_init_xor },
    { GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256, 32, 0, 0, NULL, 0, GQUIC_TLS_HASH_SHA256, NULL, NULL, aead_chacha20_poly1305_init_xor },
    { GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384, 32, 0, 0, NULL, 0, GQUIC_TLS_HASH_SHA384, NULL, NULL, aead_aes_gcm_init_xor },
};

int gquic_tls_mac_func(gquic_str_t *const ret,
                       HMAC_CTX *const ctx,
                       const gquic_str_t *const seq,
                       const gquic_str_t *const header,
                       const gquic_str_t *const data,
                       const gquic_str_t *const extra) {
    unsigned int size;
    (void) extra;
    if (ret == NULL || ctx == NULL || seq == NULL || header == NULL || data == NULL) {
        return -1;
    }
    if (gquic_str_alloc(ret, HMAC_size(ctx)) != 0) {
        return -2;
    }
    HMAC_Update(ctx, GQUIC_STR_VAL(seq), GQUIC_STR_SIZE(seq));
    HMAC_Update(ctx, GQUIC_STR_VAL(header), GQUIC_STR_SIZE(header));
    HMAC_Update(ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data));
    HMAC_Final(ctx, GQUIC_STR_VAL(ret), &size);
    return 0;
}

int gquic_tls_aead_release(gquic_tls_aead_t *const aead) {
    if (aead == NULL) {
        return -1;
    }
    gquic_str_reset(&aead->ctx.nonce);
    gquic_str_reset(&aead->ctx.key);

    return 0;
}

int gquic_tls_aead_ctx_init(gquic_tls_aead_ctx_t *const ctx) {
    if (ctx == NULL) {
        return -1;
    }
    ctx->cipher = NULL;
    gquic_str_init(&ctx->nonce);
    gquic_str_init(&ctx->key);
    ctx->nonce_wrapper = NULL;
    return 0;
}

static int ecdhe_rsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver) {
    if (ka == NULL) {
        return -1;
    }
    gquic_tls_key_agreement_ecdhe_init(ka);
    gquic_tls_key_agreement_ecdhe_set_version(ka, ver);
    gquic_tls_key_agreement_ecdhe_set_is_rsa(ka, 1);
    return 0;
}

static int ecdhe_ecdsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver) {
    if (ka == NULL) {
        return -1;
    }
    gquic_tls_key_agreement_ecdhe_init(ka);
    gquic_tls_key_agreement_ecdhe_set_version(ka, ver);
    return 0;
}

static int rsa_ka(gquic_tls_key_agreement_t *const ka, const u_int16_t ver) {
    (void) ver;
    if (ka == NULL) {
        return -1;
    }
    gquic_tls_key_agreement_rsa_init(ka);
    return 0;
}

static int gquic_tls_aead_seal(gquic_str_t *const tag,
                               gquic_str_t *const cipher_text,
                               gquic_tls_aead_ctx_t *const aead,
                               const gquic_str_t *const nonce,
                               const gquic_str_t *const plain_text,
                               const gquic_str_t *const addata) {

    gquic_str_t iv;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;
    if (tag == NULL || cipher_text == NULL || aead == NULL || plain_text == NULL || addata == NULL || aead->nonce_wrapper != NULL) {
        return -1;
    }
    gquic_str_init(&iv);
    if (aead->nonce_wrapper(&iv, &aead->nonce, nonce) != 0) {
        ret = -2;
        goto failure;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = -3;
        goto failure;
    }
    if (EVP_EncryptInit_ex(ctx, aead->cipher, NULL, NULL, NULL) <= 0) {
        ret = -4;
        goto failure;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(&iv), NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, GQUIC_STR_VAL(&aead->key), GQUIC_STR_VAL(&iv)) <= 0) {
        ret = -6;
        goto failure;
    }

    if (aead_seal(tag, cipher_text, ctx, plain_text, addata) != 0) {
        ret = -7;
        goto failure;
    }

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    return 0;
failure:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    return ret;
}

static int gquic_tls_aead_open(gquic_str_t *const plain_text,
                               gquic_tls_aead_ctx_t *const aead,
                               const gquic_str_t *const nonce,
                               const gquic_str_t *const tag,
                               const gquic_str_t *const cipher_text,
                               const gquic_str_t *const addata) {
    gquic_str_t iv;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;
    if (plain_text == NULL || tag == NULL || cipher_text == NULL || aead == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    gquic_str_init(&iv);
    if (aead->nonce_wrapper(&iv, &aead->nonce, nonce) != 0) {
        ret = -2;
        goto failure;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = -3;
        goto failure;
    }
    if (EVP_DecryptInit_ex(ctx, aead->cipher, NULL, NULL, NULL) <= 0) {
        ret = -4;
        goto failure;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(&iv), NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, GQUIC_STR_VAL(&aead->key), GQUIC_STR_VAL(&iv)) <= 0) {
        ret = -6;
        goto failure;
    }

    if (aead_open(plain_text, ctx, tag, cipher_text, addata) <= 0) {
        return -2;
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    return 0;
failure:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    gquic_str_reset(&iv);
    return ret;
}

static int cipher_common(EVP_CIPHER_CTX **const ctx,
                         const EVP_CIPHER *const cipher,
                         const gquic_str_t *const key,
                         const gquic_str_t *const iv,
                         const int is_read) {
    if ((size_t) EVP_CIPHER_key_length(cipher) != GQUIC_STR_SIZE(key)) {
        return -2;
    }
    if (iv != NULL && (size_t) EVP_CIPHER_iv_length(cipher) != GQUIC_STR_SIZE(iv)) {
        return -3;
    }
    if (is_read) {
        EVP_DecryptInit_ex(*ctx, cipher, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(iv));
    }
    else {
        EVP_EncryptInit_ex(*ctx, cipher, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(iv));
    }
    return 0;
}

static int cipher_rc4(EVP_CIPHER_CTX **const ret, const gquic_str_t *const key, const gquic_str_t *const iv, const int is_read) {
    (void) iv;
    if (ret == NULL || key == NULL) {
        return -1;
    }
    return cipher_common(ret, EVP_rc4(), key, iv, is_read);
}

static int cipher_3des(EVP_CIPHER_CTX **const ret, const gquic_str_t *const key, const gquic_str_t *const iv, const int is_read) {
    if (ret == NULL || key == NULL || iv == NULL) {
        return -1;
    }
    return cipher_common(ret, EVP_des_ede3_cbc(), key, iv, is_read);
}
static int cipher_aes(EVP_CIPHER_CTX **const ret, const gquic_str_t *const key, const gquic_str_t *const iv, const int is_read) {
    if (ret == NULL || key == NULL || iv == NULL) {
        return -1;
    }
    return cipher_common(ret, EVP_aes_256_cbc(), key, iv, is_read);
}

static int mac_sha1_init(HMAC_CTX **const ctx, const u_int16_t ver, const gquic_str_t *const key) {
    (void) ver;
    if (ctx == NULL || key == NULL) {
        return -1;
    }
    *ctx = HMAC_CTX_new();
    if (HMAC_Init_ex(*ctx, GQUIC_STR_VAL(key), GQUIC_STR_SIZE(key), EVP_sha1(), NULL) <= 0) {
        return -2;
    }
    return 0;
}

static int mac_sha256_init(HMAC_CTX **const ctx, const u_int16_t ver, const gquic_str_t *const key) {
    (void) ver;
    if (ctx == NULL || key == NULL) {
        return -1;
    }
    *ctx = HMAC_CTX_new();
    if (HMAC_Init_ex(*ctx, GQUIC_STR_VAL(key), GQUIC_STR_SIZE(key), EVP_sha256(), NULL) <= 0) {
        return -2;
    }
    return 0;
}

static int aead_seal(gquic_str_t *const tag,
                     gquic_str_t *const cipher_text,
                     EVP_CIPHER_CTX *const ctx,
                     const gquic_str_t *const plain_text,
                     const gquic_str_t *const addata) {
    int outlen = 0;
    if (tag == NULL || cipher_text == NULL || ctx == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    if (gquic_str_alloc(tag, 16) != 0) {
        return -2;
    }
    EVP_EncryptUpdate(ctx, NULL, &outlen, GQUIC_STR_VAL(addata), GQUIC_STR_SIZE(addata));
    if (gquic_str_alloc(cipher_text, GQUIC_STR_SIZE(addata) + GQUIC_STR_SIZE(plain_text)) != 0) {
        return -3;
    }
    EVP_EncryptUpdate(ctx, GQUIC_STR_VAL(cipher_text), &outlen, GQUIC_STR_VAL(plain_text), GQUIC_STR_SIZE(plain_text));
    cipher_text->size = outlen;
    EVP_EncryptFinal_ex(ctx, GQUIC_STR_VAL(cipher_text), &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, GQUIC_STR_VAL(tag));
    return 0;
}

static int aead_open(gquic_str_t *const ret,
                     EVP_CIPHER_CTX *const ctx,
                     const gquic_str_t *const tag,
                     const gquic_str_t *const cipher_text,
                     const gquic_str_t *const addata) {
    int outlen = 0;
    if (ret == NULL || tag == NULL || cipher_text == NULL || ctx == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    EVP_DecryptUpdate(ctx, NULL, &outlen, GQUIC_STR_VAL(addata), GQUIC_STR_SIZE(addata));
    if (gquic_str_alloc(ret, GQUIC_STR_SIZE(cipher_text) + GQUIC_STR_SIZE(addata)) != 0) {
        return -3;
    }
    EVP_DecryptUpdate(ctx, GQUIC_STR_VAL(ret), &outlen, GQUIC_STR_VAL(cipher_text), GQUIC_STR_SIZE(cipher_text));
    ret->size = outlen;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GQUIC_STR_SIZE(tag), GQUIC_STR_VAL(tag));
    return EVP_DecryptFinal_ex(ctx, GQUIC_STR_VAL(ret), &outlen);
}
static inline int aead_aes_gcm_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(nonce) != 4) {
        return -2;
    }
    if (gquic_tls_aead_ctx_init(&ret->ctx) != 0) {
        return -3;
    }
    if ((size_t) EVP_CIPHER_key_length(EVP_aes_128_gcm()) == GQUIC_STR_SIZE(key)) {
        ret->ctx.cipher = EVP_aes_128_gcm();
    }
    else if ((size_t) EVP_CIPHER_key_length(EVP_aes_192_gcm()) == GQUIC_STR_SIZE(key)) {
        ret->ctx.cipher = EVP_aes_192_gcm();
    }
    else if ((size_t) EVP_CIPHER_key_length(EVP_aes_256_gcm()) == GQUIC_STR_SIZE(key)) {
        ret->ctx.cipher = EVP_aes_256_gcm();
    }
    else {
        return -4;
    }
    if (gquic_str_copy(&ret->ctx.nonce, nonce) != 0) {
        return -5;
    }
    if (gquic_str_copy(&ret->ctx.key, key) != 0) {
        return -5;
    }
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    return 0;
}

static inline int aead_chacha20_poly1305_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (gquic_tls_aead_ctx_init(&ret->ctx) != 0) {
        return -2;
    }
    ret->ctx.cipher = EVP_chacha20_poly1305();
    if (gquic_str_copy(&ret->ctx.nonce, nonce) != 0) {
        return -5;
    }
    if (gquic_str_copy(&ret->ctx.key, key) != 0) {
        return -5;
    }
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    return 0;
}

static int aead_aes_gcm_init_prefix(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (aead_aes_gcm_init(ret, key, nonce) != 0) {
        return -1;
    }
    ret->ctx.nonce_wrapper = aead_prefix_nonce_wrapper;
    return 0;
}

static int aead_chacha20_poly1305_init_prefix(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (aead_chacha20_poly1305_init(ret, key, nonce) != 0) {
        return -1;
    }
    ret->ctx.nonce_wrapper = aead_prefix_nonce_wrapper;
    return 0;
}

static int aead_aes_gcm_init_xor(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (aead_aes_gcm_init(ret, key, nonce) != 0) {
        return -1;
    }
    ret->ctx.nonce_wrapper = aead_xor_nonce_wrapper;
    return 0;
}

static int aead_chacha20_poly1305_init_xor(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (aead_chacha20_poly1305_init(ret, key, nonce) != 0) {
        return -1;
    }
    ret->ctx.nonce_wrapper = aead_xor_nonce_wrapper;
    return 0;
}

static int aead_prefix_nonce_wrapper(gquic_str_t *const ret, const gquic_str_t *const base, const gquic_str_t *const nonce) {
    if (ret == NULL || base == NULL || nonce == NULL) {
        return -1;
    }
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    if (gquic_str_alloc(ret, 12) != 0) {
        return -3;
    }
    memcpy(GQUIC_STR_VAL(ret), GQUIC_STR_VAL(base), 4);
    memcpy(GQUIC_STR_VAL(ret) + 4, GQUIC_STR_VAL(nonce), 8);

    return 0;
}

static int aead_xor_nonce_wrapper(gquic_str_t *const ret, const gquic_str_t *const base, const gquic_str_t *const nonce) {
    size_t i;
    if (ret == NULL || base == NULL || nonce == NULL) {
        return -1;
    }
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    if (gquic_str_copy(ret, base) != 0) {
        return -2;
    }
    for (i = 0; i < GQUIC_STR_SIZE(nonce); i++) {
        ((unsigned char *) GQUIC_STR_VAL(ret))[i + 4] ^= ((unsigned char *) GQUIC_STR_VAL(nonce))[i];
    }

    return 0;
}
