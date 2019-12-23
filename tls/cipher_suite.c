#include "tls/cipher_suite.h"
#include "tls/key_agreement.h"
#include "tls/key_schedule.h"
#include <malloc.h>
#include <string.h>
#include <openssl/sha.h>

typedef struct gquic_tls_aead_ctx_s gquic_tls_aead_ctx_t;
struct gquic_tls_aead_ctx_s {
    const EVP_CIPHER *cipher;
    gquic_str_t nonce;
    gquic_str_t key;

    int (*nonce_wrapper) (gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
};

int gquic_tls_aead_ctx_init(gquic_tls_aead_ctx_t *const ctx);
int gquic_tls_aead_ctx_release(gquic_tls_aead_ctx_t *const ctx);

static int ecdhe_rsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);
static int ecdhe_ecdsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);
static int rsa_ka(gquic_tls_key_agreement_t *const, const u_int16_t);

static int cipher_common(gquic_tls_cipher_t *const,
                         const EVP_CIPHER *const,
                         const gquic_str_t *const,
                         const gquic_str_t *const,
                         const int);
static int cipher_rc4(gquic_tls_cipher_t *const, const gquic_str_t *const, const gquic_str_t *const, const int);
static int cipher_3des(gquic_tls_cipher_t *const, const gquic_str_t *const, const gquic_str_t *const, const int);
static int cipher_aes(gquic_tls_cipher_t *const, const gquic_str_t *const, const gquic_str_t *const, const int);

static int mac_common_init(gquic_tls_mac_t *const, const u_int16_t, const EVP_MD *const, const gquic_str_t *const);
static int mac_sha1_init(gquic_tls_mac_t *const, const u_int16_t, const gquic_str_t *const);
static int mac_sha256_init(gquic_tls_mac_t *const, const u_int16_t, const gquic_str_t *const);
static int mac_sha384_init(gquic_tls_mac_t *const, const u_int16_t, const gquic_str_t *const);

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
                               void *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const);

static int gquic_tls_aead_open(gquic_str_t *const,
                               void *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const);

static int aead_prefix_nonce_wrapper(gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_xor_nonce_wrapper(gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);

static int aead_ctx_release(void *self);
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

    { GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256, 16, 0, 12, NULL, 0, GQUIC_TLS_HASH_SHA256, NULL, mac_sha256_init, aead_aes_gcm_init_xor },
    { GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256, 32, 0, 12, NULL, 0, GQUIC_TLS_HASH_SHA256, NULL, mac_sha256_init, aead_chacha20_poly1305_init_xor },
    { GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384, 32, 0, 12, NULL, 0, GQUIC_TLS_HASH_SHA384, NULL, mac_sha384_init, aead_aes_gcm_init_xor },
};
static const int cipher_suites_count = sizeof(cipher_suites) / sizeof(gquic_tls_cipher_suite_t);

int gquic_tls_get_cipher_suite(const gquic_tls_cipher_suite_t **const cipher, const u_int16_t cipher_suite_id) {
    if (cipher == NULL) {
        return -1;
    }
    int i;
    for (i = 0; i < cipher_suites_count; i++) {
        if (cipher_suites[i].id == cipher_suite_id) {
           *cipher = &cipher_suites[i]; 
           return 0;
        }
    }
    return -2;
}

int gquic_tls_choose_cipher_suite(const gquic_tls_cipher_suite_t **const cipher_suite, const gquic_list_t *const have, const u_int16_t want) {
    u_int16_t *have_cipher_suite_id;
    if (cipher_suite == NULL || have == NULL) {
        return -1;
    }
    GQUIC_LIST_FOREACH(have_cipher_suite_id, have) {
        if (*have_cipher_suite_id == want) {
            return gquic_tls_get_cipher_suite(cipher_suite, want);
        }
    }
    return -2;
}

int gquic_tls_create_aead(gquic_tls_aead_t *const aead, const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec) {
    int ret = 0;
    gquic_str_t key = { 0, NULL };
    gquic_str_t iv = { 0, NULL };
    gquic_tls_mac_t hash;
    static const gquic_str_t key_label = { 8, "quic key" };
    static const gquic_str_t iv_label = { 7, "quic iv" };
    if (aead == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_tls_mac_init(&hash);
    if (suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL) != 0) {
        return -2;
    }
    if (gquic_tls_hkdf_expand_label(&key, &hash, traffic_sec, NULL, &key_label, suite->key_len) != 0) {
        ret = -3;
        goto failure;
    }
    if (gquic_tls_hkdf_expand_label(&iv, &hash, traffic_sec, NULL, &iv_label, suite->key_len) != 0) {
        ret = -4;
        goto failure;
    }
    if (suite->aead(aead, &key, &iv) != 0) {
        ret = -5;
        goto failure;
    }

    gquic_str_reset(&key);
    gquic_str_reset(&iv);
    gquic_tls_mac_release(&hash);
    return 0;
failure:

    gquic_str_reset(&key);
    gquic_str_reset(&iv);
    gquic_tls_mac_release(&hash);
    return ret;
}

int gquic_tls_mac_hmac_hash(gquic_str_t *const ret,
                            gquic_tls_mac_t *const mac,
                            const gquic_str_t *const seq,
                            const gquic_str_t *const header,
                            const gquic_str_t *const data,
                            const gquic_str_t *const extra) {
    unsigned int size;
    (void) extra;
    if (ret == NULL || mac == NULL || mac->mac == NULL || data == NULL) {
        return -1;
    }
    if (gquic_str_alloc(ret, HMAC_size(mac->mac)) != 0) {
        return -2;
    }
    if (seq != NULL && HMAC_Update(mac->mac, GQUIC_STR_VAL(seq), GQUIC_STR_SIZE(seq)) <= 0) {
        return -3;
    }
    if (header != NULL && HMAC_Update(mac->mac, GQUIC_STR_VAL(header), GQUIC_STR_SIZE(header)) <= 0) {
        return -4;
    }
    if (HMAC_Update(mac->mac, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data)) <= 0) {
        return -5;
    }
    if (HMAC_Final(mac->mac, GQUIC_STR_VAL(ret), &size) <= 0) {
        return -6;
    }
    return 0;
}

int gquic_tls_mac_md_hash(gquic_str_t *const ret,
                          gquic_tls_mac_t *const mac,
                          const gquic_str_t *const data) {
    unsigned int size;
    if (ret == NULL || mac == NULL || mac->md_ctx == NULL || data == NULL) {
        return -1;
    }
    if (gquic_str_alloc(ret, EVP_MD_CTX_size(mac->md_ctx)) != 0) {
        return -2;
    }
    EVP_DigestUpdate(mac->md_ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data));
    EVP_DigestFinal_ex(mac->md_ctx, GQUIC_STR_VAL(ret), &size);
    return 0;
}

int gquic_tls_mac_md_update(gquic_tls_mac_t *const mac,
                            const gquic_str_t *const data) {
    if (mac == NULL || mac->md_ctx == NULL || data == NULL) {
        return -1;
    }
    if (EVP_DigestUpdate(mac->md_ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data)) <= 0) {
        return -2;
    }
    return 0;
}

int gquic_tls_mac_md_reset(gquic_tls_mac_t *const mac) {
    if (mac == NULL || mac->md_ctx == NULL) {
        return -1;
    }
    const EVP_MD *md = EVP_MD_CTX_md(mac->md_ctx);
    if (EVP_MD_CTX_reset(mac->md_ctx) <= 0) {
        return -2;
    }
    if (EVP_DigestInit_ex(mac->md_ctx, md, NULL) <= 0) {
        return -3;
    }
    return 0;
}

int gquic_tls_mac_md_sum(gquic_str_t *const ret,
                         gquic_tls_mac_t *const mac) {
    unsigned int size = 0;
    EVP_MD_CTX *output_ctx = NULL;
    if (ret == NULL || mac == NULL || mac->md_ctx == NULL) {
        return -1;
    }
    if ((output_ctx = EVP_MD_CTX_new()) == NULL) {
        return -2;
    }
    if (EVP_MD_CTX_copy_ex(output_ctx, mac->md_ctx) <= 0) {
        return -3;
    }
    if (gquic_str_alloc(ret, EVP_MD_CTX_size(output_ctx)) != 0) {
        return -4;
    }
    if (EVP_DigestFinal_ex(output_ctx, GQUIC_STR_VAL(ret), &size) <= 0) {
        return -5;
    }
    EVP_MD_CTX_free(output_ctx);
    return 0;
}

int gquic_tls_mac_md_copy(gquic_tls_mac_t *const ret,
                          gquic_tls_mac_t *const origin) {
    if (ret == NULL || origin == NULL) {
        return -1;
    }
    ret->md = origin->md;
    if ((ret->md_ctx = EVP_MD_CTX_new()) == NULL) {
        return -2;
    }
    if (EVP_MD_CTX_copy_ex(ret->md_ctx, origin->md_ctx) <= 0) {
        return -3;
    }
    return 0;
}

int gquic_tls_aead_init(gquic_tls_aead_t *const aead) {
    if (aead == NULL) {
        return -1;
    }
    aead->self = NULL;
    aead->open = NULL;
    aead->seal = NULL;
    aead->release = NULL;
    return 0;
}

int gquic_tls_aead_release(gquic_tls_aead_t *const aead) {
    if (aead == NULL) {
        return -1;
    }
    if (aead->release != NULL) {
        if (aead->self != NULL) {
            aead->release(aead->self);
            free(aead->self);
        }
    }
    return 0;
}

int gquic_tls_aead_copy(gquic_tls_aead_t *const aead, const gquic_tls_aead_t *const ref) {
    if (aead == NULL || ref == NULL) {
        return -1;
    }
    aead->self = ref->self;
    aead->open = ref->open;
    aead->seal = ref->seal;

    return 0;
}

int gquic_tls_cipher_init(gquic_tls_cipher_t *const cipher) {
    if (cipher == NULL) {
        return -1;
    }
    cipher->cipher = NULL;
    gquic_str_init(&cipher->iv);
    gquic_str_init(&cipher->key);
    return 0;
}

int gquic_tls_cipher_release(gquic_tls_cipher_t *const cipher) {
    if (cipher == NULL) {
        return -1;
    }
    if (cipher->cipher != NULL) {
        EVP_CIPHER_CTX_free(cipher->cipher);
    }
    gquic_str_reset(&cipher->iv);
    gquic_str_reset(&cipher->key);
    return 0;
}

int gquic_tls_cipher_encrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const plain_text) {
    if (ret == NULL || cipher == NULL || plain_text == NULL || cipher->cipher == NULL) {
        return -1;
    }
    int outlen = 0;
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    if (EVP_EncryptUpdate(cipher->cipher, NULL, &outlen, GQUIC_STR_VAL(plain_text), GQUIC_STR_SIZE(plain_text)) <= 0) {
        return -3;
    }
    if (gquic_str_alloc(ret, outlen + 32) != 0) {
        return -4;
    }
    if (EVP_EncryptUpdate(cipher->cipher, GQUIC_STR_VAL(ret), &outlen, GQUIC_STR_VAL(plain_text), GQUIC_STR_SIZE(plain_text)) <= 0) {
        return -5;
    }
    ret->size = outlen;
    if (EVP_EncryptFinal_ex(cipher->cipher, GQUIC_STR_VAL(ret), &outlen) <= 0) {
        return -6;
    }
    return 0;
}

int gquic_tls_cipher_decrypt(gquic_str_t *const ret, gquic_tls_cipher_t *const cipher, const gquic_str_t *const cipher_text) {
    if (ret == NULL || cipher == NULL || cipher_text == NULL || cipher->cipher == NULL) {
        return -1;
    }
    int outlen = 0;
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    if (EVP_DecryptUpdate(cipher->cipher, NULL, &outlen, GQUIC_STR_VAL(cipher_text), GQUIC_STR_SIZE(cipher_text)) != 0) {
        return -3;
    }
    if (gquic_str_alloc(ret, outlen + 32) != 0) {
        return -4;
    }
    if (EVP_DecryptUpdate(cipher->cipher, GQUIC_STR_VAL(ret), &outlen, GQUIC_STR_VAL(cipher_text), GQUIC_STR_SIZE(cipher_text)) != 0) {
        return -5;
    }
    ret->size = outlen;
    if (EVP_DecryptFinal_ex(cipher->cipher, GQUIC_STR_VAL(ret), &outlen) != 0) {
        return -6;
    }
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

int gquic_tls_aead_ctx_release(gquic_tls_aead_ctx_t *const ctx) {
    if (ctx == NULL) {
        return -1;
    }
    gquic_str_reset(&ctx->nonce);
    gquic_str_reset(&ctx->key);
    return 0;
}

int gquic_tls_suite_init(gquic_tls_suite_t *const suite) {
    if (suite == NULL) {
        return -1;
    }
    gquic_tls_aead_init(&suite->aead);
    gquic_tls_cipher_init(&suite->cipher);
    gquic_tls_mac_init(&suite->mac);
    suite->type = GQUIC_TLS_CIPHER_TYPE_UNKNOW;
    return 0;
}

int gquic_tls_suite_assign(gquic_tls_suite_t *const suite,
                           const gquic_tls_cipher_suite_t *const cipher_suite,
                           const gquic_str_t *const iv,
                           const gquic_str_t *const cipher_key,
                           const gquic_str_t *const mac_key,
                           const int is_read) {
    if (suite == NULL || cipher_suite == NULL) {
        return -1;
    }
    if (cipher_suite->aead != NULL && cipher_key != NULL && iv != NULL) {
        if (cipher_suite->key_len > GQUIC_STR_SIZE(cipher_key)) {
            return -2;
        }
        if (cipher_suite->aead(&suite->aead, cipher_key, iv) != 0) {
            return -3;
        }
        suite->type = GQUIC_TLS_CIPHER_TYPE_AEAD;
    }
    if (cipher_suite->cipher_encrypt != NULL && cipher_key != NULL && iv != NULL) {
        if (cipher_suite->key_len != GQUIC_STR_SIZE(cipher_key) || cipher_suite->iv_len != GQUIC_STR_SIZE(iv)) {
            return -4;
        }
        if (cipher_suite->cipher_encrypt(&suite->cipher, cipher_key, iv, is_read) != 0) {
            return -5;
        }
        suite->type = GQUIC_TLS_CIPHER_TYPE_STREAM;
    }
    if (cipher_suite->mac != NULL && mac_key != NULL) {
        if (cipher_suite->mac_len != GQUIC_STR_SIZE(mac_key)) {
            return -6;
        }
        if (cipher_suite->mac(&suite->mac, 0, mac_key) != 0) {
            return -7;
        }
    }
    return 0;
}

int gquic_tls_suite_encrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const plain_text) {
    if (result == NULL || suite == NULL || plain_text == NULL) {
        return -1;
    }
    return gquic_tls_cipher_encrypt(result, &suite->cipher, plain_text);
}

int gquic_tls_suite_aead_encrypt(gquic_str_t *const tag,
                                 gquic_str_t *const cipher_text,
                                 gquic_tls_suite_t *const suite,
                                 const gquic_str_t *const nonce,
                                 const gquic_str_t *const plain_text,
                                 const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || suite == NULL || nonce == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    return GQUIC_TLS_AEAD_SEAL(tag, cipher_text, &suite->aead, nonce, plain_text, addata);
}

int gquic_tls_suite_decrypt(gquic_str_t *const result, gquic_tls_suite_t *const suite, const gquic_str_t *const cipher_text) {
    if (result == NULL || suite == NULL || cipher_text == NULL) {
        return -1;
    }
    return gquic_tls_cipher_decrypt(result, &suite->cipher, cipher_text);
}

int gquic_tls_suite_aead_decrypt(gquic_str_t *const plain_text,
                                 gquic_tls_suite_t *const suite,
                                 const gquic_str_t *const nonce,
                                 const gquic_str_t *const tag,
                                 const gquic_str_t *const cipher_text,
                                 const gquic_str_t *const addata) {
    if (plain_text == NULL || suite == NULL || nonce == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    return GQUIC_TLS_AEAD_OPEN(plain_text, &suite->aead, nonce, tag, cipher_text, addata);
}

int gquic_tls_mac_init(gquic_tls_mac_t *const mac) {
    if (mac == NULL) {
        return -1;
    }
    mac->mac = NULL;
    mac->md = NULL;
    mac->md_ctx = NULL;
    gquic_str_init(&mac->key);
    return 0;
}

int gquic_tls_mac_release(gquic_tls_mac_t *const mac) {
    if (mac == NULL) {
        return -1;
    }
    if (mac->mac != NULL) {
        HMAC_CTX_free(mac->mac);
    }
    if (mac->md_ctx != NULL) {
        EVP_MD_CTX_free(mac->md_ctx);
    }
    gquic_str_reset(&mac->key);
    return 0;
}

int gquic_tls_suite_hmac_hash(gquic_str_t *const hash,
                              gquic_tls_suite_t *const suite,
                              const gquic_str_t *const seq,
                              const gquic_str_t *const header,
                              const gquic_str_t *const data,
                              const gquic_str_t *const extra) {
    if (hash == NULL || suite == NULL || data == NULL || suite->mac.mac == NULL) {
        return -1;
    }
    return gquic_tls_mac_hmac_hash(hash, &suite->mac, seq, header, data, extra);
}

size_t gquic_tls_suite_nonce_size(const gquic_tls_suite_t *const suite) {
    if (suite == NULL) {
        return 0;
    }
    switch (suite->type) {
    case GQUIC_TLS_CIPHER_TYPE_AEAD:
        return 1 + 8;
    }
    return 0;
}

size_t gquic_tls_suite_mac_size(const gquic_tls_suite_t *const suite) {
    if (suite == NULL || suite->mac.mac == NULL) {
        return 0;
    }
    return HMAC_size(suite->mac.mac);
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
                               void *const aead,
                               const gquic_str_t *const nonce,
                               const gquic_str_t *const plain_text,
                               const gquic_str_t *const addata) {

    gquic_str_t iv;
    EVP_CIPHER_CTX *ctx = NULL;
    gquic_tls_aead_ctx_t *aead_ctx = aead;
    int ret = 0;
    if (tag == NULL || cipher_text == NULL || aead == NULL || plain_text == NULL || addata == NULL || aead_ctx->nonce_wrapper == NULL) {
        return -1;
    }
    gquic_str_init(&iv);
    if (aead_ctx->nonce_wrapper(&iv, &aead_ctx->nonce, nonce) != 0) {
        ret = -2;
        goto failure;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = -3;
        goto failure;
    }
    if (EVP_EncryptInit_ex(ctx, aead_ctx->cipher, NULL, NULL, NULL) <= 0) {
        ret = -4;
        goto failure;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(&iv), NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, GQUIC_STR_VAL(&aead_ctx->key), GQUIC_STR_VAL(&iv)) <= 0) {
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
                               void *const aead,
                               const gquic_str_t *const nonce,
                               const gquic_str_t *const tag,
                               const gquic_str_t *const cipher_text,
                               const gquic_str_t *const addata) {
    gquic_str_t iv;
    EVP_CIPHER_CTX *ctx = NULL;
    gquic_tls_aead_ctx_t *aead_ctx = aead;
    int ret = 0;
    if (plain_text == NULL
        || tag == NULL
        || cipher_text == NULL
        || aead == NULL
        || cipher_text == NULL
        || addata == NULL
        || aead_ctx->nonce_wrapper == NULL) {
        return -1;
    }
    gquic_str_init(&iv);
    if (aead_ctx->nonce_wrapper(&iv, &aead_ctx->nonce, nonce) != 0) {
        ret = -2;
        goto failure;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = -3;
        goto failure;
    }
    if (EVP_DecryptInit_ex(ctx, aead_ctx->cipher, NULL, NULL, NULL) <= 0) {
        ret = -4;
        goto failure;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(&iv), NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, GQUIC_STR_VAL(&aead_ctx->key), GQUIC_STR_VAL(&iv)) <= 0) {
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

static int cipher_common(gquic_tls_cipher_t *const ret,
                         const EVP_CIPHER *const cipher,
                         const gquic_str_t *const key,
                         const gquic_str_t *const iv,
                         const int is_read) {
    if (ret == NULL || cipher == NULL) {
        return -1;
    }
    if ((size_t) EVP_CIPHER_key_length(cipher) != GQUIC_STR_SIZE(key)) {
        return -2;
    }
    if (iv != NULL && (size_t) EVP_CIPHER_iv_length(cipher) != GQUIC_STR_SIZE(iv)) {
        return -3;
    }
    if (gquic_str_copy(&ret->key, key) != 0) {
        return -4;
    }
    if (gquic_str_copy(&ret->iv, iv) != 0) {
        return -5;
    }
    if (is_read) {
        EVP_DecryptInit_ex(ret->cipher, cipher, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(iv));
    }
    else {
        EVP_EncryptInit_ex(ret->cipher, cipher, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(iv));
    }
    return 0;
}

static int cipher_rc4(gquic_tls_cipher_t *const ret, const gquic_str_t *const key, const gquic_str_t *const iv, const int is_read) {
    if (ret == NULL || key == NULL) {
        return -1;
    }
    return cipher_common(ret, EVP_rc4(), key, iv, is_read);
}

static int cipher_3des(gquic_tls_cipher_t *const ret, const gquic_str_t *const key, const gquic_str_t *const iv, const int is_read) {
    if (ret == NULL || key == NULL || iv == NULL) {
        return -1;
    }
    return cipher_common(ret, EVP_des_ede3_cbc(), key, iv, is_read);
}
static int cipher_aes(gquic_tls_cipher_t *const ret, const gquic_str_t *const key, const gquic_str_t *const iv, const int is_read) {
    if (ret == NULL || key == NULL || iv == NULL) {
        return -1;
    }
    return cipher_common(ret, EVP_aes_256_cbc(), key, iv, is_read);
}

static int mac_common_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const EVP_MD *const md, const gquic_str_t *const key) {
    (void) ver;
    if (mac == NULL) {
        return -1;
    }
    gquic_tls_mac_init(mac);
    mac->md = md;
    if (GQUIC_STR_SIZE(key) == 0) {
        mac->md_ctx = EVP_MD_CTX_new();
        if (EVP_DigestInit_ex(mac->md_ctx, mac->md, NULL) <= 0) {
            return -2;
        }
        return 0;
    }
    if (gquic_str_copy(&mac->key, key) != 0) {
        return -3;
    }
    mac->mac = HMAC_CTX_new();
    if (HMAC_Init_ex(mac->mac, GQUIC_STR_VAL(key), GQUIC_STR_SIZE(key), mac->md, NULL) <= 0) {
        return -4;
    }
    return 0;
}

static int mac_sha1_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key) {
    return mac_common_init(mac, ver, EVP_sha1(), key);
}

static int mac_sha256_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key) {
    return mac_common_init(mac, ver, EVP_sha256(), key);
}

static int mac_sha384_init(gquic_tls_mac_t *const mac, const u_int16_t ver, const gquic_str_t *const key) {
    return mac_common_init(mac, ver, EVP_sha3_384(), key);
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

static int aead_ctx_release(void *self) {
    return gquic_tls_aead_ctx_release(self);
}

static inline int aead_aes_gcm_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if ((ctx = malloc(sizeof(gquic_tls_aead_ctx_t))) == NULL) {
        return -2;
    }
    gquic_tls_aead_ctx_init(ctx);
    if (gquic_tls_aead_ctx_init(ctx) != 0) {
        return -3;
    }
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
        return -4;
    }
    if (gquic_str_copy(&ctx->nonce, nonce) != 0) {
        return -5;
    }
    if (gquic_str_copy(&ctx->key, key) != 0) {
        return -5;
    }
    ret->self = ctx;
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    ret->release = aead_ctx_release;
    return 0;
}

static inline int aead_chacha20_poly1305_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if ((ctx = malloc(sizeof(gquic_tls_aead_ctx_t))) == NULL) {
        return -2;
    }
    gquic_tls_aead_ctx_init(ctx);
    if (gquic_tls_aead_ctx_init(ctx) != 0) {
        return -2;
    }
    ctx->cipher = EVP_chacha20_poly1305();
    if (gquic_str_copy(&ctx->nonce, nonce) != 0) {
        return -5;
    }
    if (gquic_str_copy(&ctx->key, key) != 0) {
        return -5;
    }
    ret->self = ctx;
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    ret->release = aead_ctx_release;
    return 0;
}

static int aead_aes_gcm_init_prefix(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (aead_aes_gcm_init(ret, key, nonce) != 0) {
        return -2;
    }
    ctx = ret->self;
    ctx->nonce_wrapper = aead_prefix_nonce_wrapper;
    return 0;
}

static int aead_chacha20_poly1305_init_prefix(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (aead_chacha20_poly1305_init(ret, key, nonce) != 0) {
        return -2;
    }
    ctx = ret->self;
    ctx->nonce_wrapper = aead_prefix_nonce_wrapper;
    return 0;
}

static int aead_aes_gcm_init_xor(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (aead_aes_gcm_init(ret, key, nonce) != 0) {
        return -2;
    }
    ctx = ret->self;
    ctx->nonce_wrapper = aead_xor_nonce_wrapper;
    return 0;
}

static int aead_chacha20_poly1305_init_xor(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    gquic_tls_aead_ctx_t *ctx = NULL;
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (aead_chacha20_poly1305_init(ret, key, nonce) != 0) {
        return -2;
    }
    ctx = ret->self;
    ctx->nonce_wrapper = aead_xor_nonce_wrapper;
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

int gquic_tls_cipher_suite_expand_label(gquic_str_t *const ret,
                                        const gquic_tls_cipher_suite_t *const cipher_suite,
                                        const gquic_str_t *const secret,
                                        const gquic_str_t *const label,
                                        const gquic_str_t *const content,
                                        const size_t length) {
    gquic_tls_mac_t hash;
    if (ret == NULL || cipher_suite == NULL || secret == NULL || label == NULL) {
        return -1;
    }
    gquic_tls_mac_init(&hash);
    if (cipher_suite->mac(&hash, 0, NULL) != 0) {
        return -2;
    }
    if (gquic_tls_hkdf_expand_label(ret, &hash, secret, content, label, length) != 0) {
        gquic_tls_mac_release(&hash);
        return -3;
    }

    gquic_tls_mac_release(&hash);
    return 0;
}

int gquic_tls_cipher_suite_derive_secret(gquic_str_t *const ret,
                                         const gquic_tls_cipher_suite_t *const cipher_suite,
                                         gquic_tls_mac_t *const transport,
                                         const gquic_str_t *const secret,
                                         const gquic_str_t *const label) {
    gquic_tls_mac_t default_transport;
    gquic_str_t content = { 0, NULL };
    if (ret == NULL || cipher_suite == NULL || secret == NULL || label == NULL) {
        return -1;
    }
    gquic_tls_mac_init(&default_transport);
    if (transport != NULL
        && transport->md_ctx != NULL
        && gquic_tls_mac_md_sum(&content, transport) != 0) {
        return -2;
    }
    else {
        cipher_suite->mac(&default_transport, 0, NULL);
    }
    if (gquic_tls_cipher_suite_expand_label(ret,
                                            cipher_suite,
                                            secret,
                                            &content,
                                            label,
                                            EVP_MD_size(transport == NULL ? default_transport.md : transport->md)) != 0) {
        return -3;
    }
    gquic_tls_mac_release(&default_transport);
    gquic_str_reset(&content);
    return 0;
}

int gquic_tls_cipher_suite_extract(gquic_str_t *const ret,
                                   const gquic_tls_cipher_suite_t *const cipher_suite,
                                   const gquic_str_t *const secret,
                                   const gquic_str_t *const salt) {
    gquic_tls_mac_t hash;
    if (ret == NULL || cipher_suite == NULL) {
        return -1;
    }
    gquic_tls_mac_init(&hash);
    if (cipher_suite->mac == NULL || cipher_suite->mac(&hash, 0, NULL) != 0) {
        return -2;
    }
    if (gquic_tls_hkdf_extract(ret, &hash, secret, salt) != 0) {
        gquic_tls_mac_release(&hash);
        return -3;
    }

    gquic_tls_mac_release(&hash);
    return 0;
}

int gquic_tls_cipher_suite_traffic_key(gquic_str_t *const key,
                                       gquic_str_t *const iv,
                                       const gquic_tls_cipher_suite_t *const cipher_suite,
                                       const gquic_str_t *const traffic_sec) {
    static const gquic_str_t key_label = { 3, "key" };
    static const gquic_str_t iv_label = { 2, "iv" };
    if (key == NULL || iv == NULL || cipher_suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    if (gquic_tls_cipher_suite_expand_label(key, cipher_suite, traffic_sec, &key_label, NULL, cipher_suite->key_len) != 0) {
        return -2;
    }
    if (gquic_tls_cipher_suite_expand_label(iv, cipher_suite, traffic_sec, &iv_label, NULL, 12) != 0) {
        return -3;
    }
    return 0;
}

int gquic_tls_cipher_suite_finished_hash(gquic_str_t *const hash,
                                         const gquic_tls_cipher_suite_t *const cipher_suite,
                                         const gquic_str_t *const base_key,
                                         gquic_tls_mac_t *const transport) {
    int ret = 0;
    gquic_str_t finished_key = { 0, NULL };
    gquic_str_t verify_data = { 0, NULL };
    gquic_tls_mac_t mac;
    gquic_tls_mac_t tmp;
    gquic_tls_mac_init(&mac);
    gquic_tls_mac_init(&tmp);
    static const gquic_str_t label = { 8, "finished" };
    if (hash == NULL || cipher_suite == NULL || base_key == NULL || transport == NULL) {
        return -1;
    }
    cipher_suite->mac(&tmp, GQUIC_TLS_VERSION_13, NULL);
    if (gquic_tls_cipher_suite_expand_label(&finished_key, cipher_suite, base_key, &label, NULL, EVP_MD_size(tmp.md)) != 0) {
        ret = -2;
        goto failure;
    }
    if (cipher_suite->mac(&mac, 0, &finished_key) != 0) {
        ret = -3;
        goto failure;
    }
    if (gquic_tls_mac_md_sum(&verify_data, transport) != 0) {
        ret = -4;
        goto failure;
    }
    if (gquic_tls_mac_hmac_hash(hash, &mac, NULL, NULL, &verify_data, NULL) != 0) {
        ret = -5;
        goto failure;
    }

    gquic_str_reset(&finished_key);
    gquic_str_reset(&verify_data);
    gquic_tls_mac_release(&mac);
    gquic_tls_mac_release(&tmp);
    return 0;
failure:
    gquic_str_reset(&finished_key);
    gquic_str_reset(&verify_data);
    gquic_tls_mac_release(&mac);
    gquic_tls_mac_release(&tmp);
    return ret;
}

int gquic_tls_ekm_init(gquic_tls_ekm_t *const ekm) {
    if (ekm == NULL) {
        return -1;
    }
    ekm->ekm = NULL;
    ekm->release = NULL;
    ekm->self = NULL;
    return 0;
}

int gquic_tls_ekm_release(gquic_tls_ekm_t *const ekm) {
    if (ekm == NULL) {
        return -1;
    }
    if (ekm->self == NULL) {
        return 0;
    }
    if (ekm->release != NULL) {
        ekm->release(ekm->self);
    }
    free(ekm->self);
    return 0;
}

int gquic_tls_ekm_invoke(gquic_str_t *const ret,
                         gquic_tls_ekm_t *const ekm,
                         const gquic_str_t *const cnt,
                         const gquic_str_t *const label,
                         const size_t length) {
    if (ekm == NULL || ekm->ekm == NULL) {
        return -1;
    }
    return ekm->ekm(ret, ekm->self, cnt, label, length);
}

typedef struct gquic_tls_ekm_keying_material_s gquic_tls_ekm_keying_material_t;
struct gquic_tls_ekm_keying_material_s {
    const gquic_tls_cipher_suite_t *cipher_suite;
    gquic_str_t exp_master_sec;
};

static int gquic_tls_ekm_keying_material_invoke(gquic_str_t *const ret,
                                                void *self,
                                                const gquic_str_t *const cnt,
                                                const gquic_str_t *const label,
                                                const size_t length) {
    gquic_tls_mac_t hash;
    gquic_str_t sec = { 0, NULL };
    gquic_str_t cnt_hash = { 0, NULL };
    static const gquic_str_t exporter_label = { 8, "exporter" };
    gquic_tls_ekm_keying_material_t *ekm_self = self;
    if (ret == NULL || self == NULL || cnt == NULL || label == NULL) {
        return -1;
    }
    if (gquic_tls_cipher_suite_derive_secret(&sec, ekm_self->cipher_suite, NULL, &ekm_self->exp_master_sec, label) != 0) {
        return -2;
    }
    gquic_tls_mac_init(&hash);
    if (ekm_self->cipher_suite->mac(&hash, 0, NULL) != 0) {
        gquic_str_reset(&sec);
        return -3;
    }
    if (gquic_tls_mac_md_update(&hash, cnt) != 0) {
        gquic_str_reset(&sec);
        gquic_tls_mac_release(&hash);
        return -4;
    }
    if (gquic_tls_mac_md_sum(&cnt_hash, &hash) != 0) {
        gquic_str_reset(&sec);
        gquic_tls_mac_release(&hash);
        return -5;
    }
    if (gquic_tls_cipher_suite_expand_label(ret, ekm_self->cipher_suite, &sec, &exporter_label, &cnt_hash, length) != 0) {
        gquic_str_reset(&sec);
        gquic_str_reset(&cnt_hash);
        gquic_tls_mac_release(&hash);
        return -6;
    }
    gquic_str_reset(&sec);
    gquic_str_reset(&cnt_hash);
    gquic_tls_mac_release(&hash);
    return 0;
}

static int gquic_tls_ekm_keying_material_release(void *self) {
    gquic_tls_ekm_keying_material_t *ekm_self = self;
    if (self == NULL) {
        return -1;
    }
    gquic_str_reset(&ekm_self->exp_master_sec);
    return 0;
}

int gquic_tls_cipher_suite_export_keying_material(gquic_tls_ekm_t *const ekm,
                                                  const gquic_tls_cipher_suite_t *const cipher_suite,
                                                  const gquic_str_t *const master_sec,
                                                  gquic_tls_mac_t *const transport) {
    static const gquic_str_t exporter_label = { 10, "exp master" };
    if (ekm == NULL || cipher_suite == NULL || master_sec == NULL || transport == NULL) {
        return -1;
    }
    gquic_tls_ekm_keying_material_t *self = malloc(sizeof(gquic_tls_ekm_keying_material_t));
    self->cipher_suite = cipher_suite;
    gquic_str_init(&self->exp_master_sec);
    if (gquic_tls_cipher_suite_derive_secret(&self->exp_master_sec, cipher_suite, transport, master_sec, &exporter_label) != 0) {
        free(self);
        return -1;
    }

    ekm->self = self;
    ekm->ekm = gquic_tls_ekm_keying_material_invoke;
    ekm->release = gquic_tls_ekm_keying_material_release;
    return 0;
}
