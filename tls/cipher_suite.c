#include "tls/cipher_suite.h"
#include <malloc.h>
#include <string.h>

static int cipher_common(EVP_CIPHER_CTX **const,
                         const EVP_CIPHER *const,
                         const gquic_str_t *const,
                         const gquic_str_t *const,
                         const int);
static int cipher_rc4(EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);
static int cipher_3des(EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);
static int cipher_aes(EVP_CIPHER_CTX **const, const gquic_str_t *const, const gquic_str_t *const, const int);

static int mac_sha1_init(gquic_tls_mac_func_t *const, const u_int16_t, const gquic_str_t *const);
static size_t mac_sha1_size();
static int mac_sha1(gquic_str_t *const,
                    const gquic_tls_mac_func_t *const,
                    const gquic_str_t *const,
                    const gquic_str_t *const,
                    const gquic_str_t *const,
                    const gquic_str_t *const);
static int mac_sha256_init(gquic_tls_mac_func_t *const, const u_int16_t, const gquic_str_t *const);
static size_t mac_sha256_size();
static int mac_sha256(gquic_str_t *const,
                      const gquic_tls_mac_func_t *const,
                      const gquic_str_t *const,
                      const gquic_str_t *const,
                      const gquic_str_t *const,
                      const gquic_str_t *const);


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
                               const gquic_str_t *const);

static int gquic_tls_aead_open(gquic_str_t *const,
                               gquic_tls_aead_ctx_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const,
                               const gquic_str_t *const);

static int aead_alloc(gquic_tls_aead_t *const);

static int aead_aes_gcm_init(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);
static int aead_chacha20_poly1305_init(gquic_tls_aead_t *const, const gquic_str_t *const, const gquic_str_t *const);

int gquic_tls_mac_func_init(gquic_tls_mac_func_t *const mac_func) {
    if (mac_func == NULL) {
        return -1;
    }
    mac_func->ctx = NULL;
    mac_func->mac = NULL;
    mac_func->size = NULL;
    return 0;
}

int gquic_tls_mac_func_reset(gquic_tls_mac_func_t *const mac_func) {
    if (mac_func == NULL) {
        return -1;
    }
    if (mac_func->ctx != NULL) {
        HMAC_CTX_reset(mac_func->ctx);
    }
    return 0;
}

int gquic_tls_aead_release(gquic_tls_aead_t *const aead) {
    if (aead == NULL) {
        return -1;
    }
    EVP_CIPHER_CTX_free(aead->ctx.dec);
    EVP_CIPHER_CTX_free(aead->ctx.enc);

    return 0;
}

static int gquic_tls_aead_seal(gquic_str_t *const tag,
                               gquic_str_t *const cipher_text,
                               gquic_tls_aead_ctx_t *const aead,
                               const gquic_str_t *const plain_text,
                               const gquic_str_t *const addata) {

    if (tag == NULL || cipher_text == NULL || aead == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    return aead_seal(tag, cipher_text, aead->enc, plain_text, addata);
}

static int gquic_tls_aead_open(gquic_str_t *const plain_text,
                               gquic_tls_aead_ctx_t *const aead,
                               const gquic_str_t *const tag,
                               const gquic_str_t *const cipher_text,
                               const gquic_str_t *const addata) {
    if (plain_text == NULL || tag == NULL || cipher_text == NULL || aead == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    if (aead_open(plain_text, aead->dec, tag, cipher_text, addata) <= 0) {
        return -2;
    }
    return 0;
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

static int mac_sha1_init(gquic_tls_mac_func_t *const mac_func, const u_int16_t ver, const gquic_str_t *const key) {
    (void) ver;
    if (mac_func == NULL || key == NULL) {
        return -1;
    }
    mac_func->ctx = HMAC_CTX_new();
    mac_func->size = mac_sha1_size;
    mac_func->mac = mac_sha1;
    HMAC_Init_ex(mac_func->ctx, GQUIC_STR_VAL(key), GQUIC_STR_SIZE(key), EVP_sha1(), NULL);
    return 0;
}

static size_t mac_sha1_size() {
    return EVP_MD_size(EVP_sha1());
}

static int mac_sha1(gquic_str_t *const ret,
                    const gquic_tls_mac_func_t *const mac_func,
                    const gquic_str_t *const seq,
                    const gquic_str_t *const header,
                    const gquic_str_t *const data,
                    const gquic_str_t *const extra) {
    unsigned int size;
    (void) extra;
    if (ret == NULL || mac_func == NULL || seq == NULL || header == NULL || data == NULL) {
        return -1;
    }
    if (gquic_str_alloc(ret, mac_func->size()) != 0) {
        return -2;
    }
    HMAC_Update(mac_func->ctx, GQUIC_STR_VAL(seq), GQUIC_STR_SIZE(seq));
    HMAC_Update(mac_func->ctx, GQUIC_STR_VAL(header), GQUIC_STR_SIZE(header));
    HMAC_Update(mac_func->ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data));
    HMAC_Final(mac_func->ctx, GQUIC_STR_VAL(ret), &size);
    return 0;
}

static int mac_sha256_init(gquic_tls_mac_func_t *const mac_func, const u_int16_t ver, const gquic_str_t *const key) {
    (void) ver;
    if (mac_func == NULL || key == NULL) {
        return -1;
    }
    mac_func->ctx = HMAC_CTX_new();
    mac_func->size = mac_sha256_size;
    mac_func->mac = mac_sha256;
    HMAC_Init_ex(mac_func->ctx, GQUIC_STR_VAL(key), GQUIC_STR_SIZE(key), EVP_sha256(), NULL);
    return 0;
}

static size_t mac_sha256_size() {
    return EVP_MD_size(EVP_sha256());
}

static int mac_sha256(gquic_str_t *const ret,
                      const gquic_tls_mac_func_t *const mac_func,
                      const gquic_str_t *const seq,
                      const gquic_str_t *const header,
                      const gquic_str_t *const data,
                      const gquic_str_t *const extra) {
    unsigned int size;
    (void) extra;
    if (ret == NULL || mac_func == NULL || seq == NULL || header == NULL || data == NULL) {
        return -1;
    }
    if (gquic_str_alloc(ret, mac_func->size()) != 0) {
        return -2;
    }
    HMAC_Update(mac_func->ctx, GQUIC_STR_VAL(seq), GQUIC_STR_SIZE(seq));
    HMAC_Update(mac_func->ctx, GQUIC_STR_VAL(header), GQUIC_STR_SIZE(header));
    HMAC_Update(mac_func->ctx, GQUIC_STR_VAL(data), GQUIC_STR_SIZE(data));
    HMAC_Final(mac_func->ctx, GQUIC_STR_VAL(ret), &size);
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

static int aead_aes_gcm_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (aead_alloc(ret) != 0) {
        return -2;
    }

    EVP_EncryptInit_ex(ret->ctx.enc, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ret->ctx.enc, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(nonce), NULL);
    EVP_EncryptInit_ex(ret->ctx.enc, NULL, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(nonce));

    EVP_DecryptInit_ex(ret->ctx.dec, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ret->ctx.dec, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(nonce), NULL);
    EVP_DecryptInit_ex(ret->ctx.dec, NULL, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(nonce));

    return 0;
}

static int aead_chacha20_poly1305_init(gquic_tls_aead_t *const ret, const gquic_str_t *const key, const gquic_str_t *const nonce) {
    if (ret == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    if (aead_alloc(ret) != 0) {
        return -2;
    }

    EVP_EncryptInit_ex(ret->ctx.enc, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ret->ctx.enc, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(nonce), NULL);
    EVP_EncryptInit_ex(ret->ctx.enc, NULL, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(nonce));

    EVP_DecryptInit_ex(ret->ctx.dec, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ret->ctx.dec, EVP_CTRL_AEAD_SET_IVLEN, GQUIC_STR_SIZE(nonce), NULL);
    EVP_DecryptInit_ex(ret->ctx.dec, NULL, NULL, GQUIC_STR_VAL(key), GQUIC_STR_VAL(nonce));

    return 0;
}

static int aead_alloc(gquic_tls_aead_t *const ret) {
    if (ret == NULL) {
        return -1;
    }
    if ((ret->ctx.enc = EVP_CIPHER_CTX_new()) == NULL) {
        return -2;
    }
    if ((ret->ctx.dec = EVP_CIPHER_CTX_new()) == NULL) {
        return -3;
    }
    ret->open = gquic_tls_aead_open;
    ret->seal = gquic_tls_aead_seal;
    return 0;
}
