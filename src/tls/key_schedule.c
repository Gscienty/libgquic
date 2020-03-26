#include "tls/common.h"
#include "tls/key_schedule.h"
#include "util/str.h"
#include "util/big_endian.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

typedef struct gquic_tls_x25519_params_s gquic_tls_x25519_params_t;
struct gquic_tls_x25519_params_s {
    gquic_str_t pri_key;
    gquic_str_t pub_key;
};

static u_int16_t gquic_x25519_params_curve_id(const void *const);
static int gquic_x25519_params_public_key(const void *const, gquic_str_t *);
static int gquic_x25519_params_shared_key(const void *const, gquic_str_t *, const gquic_str_t *);

static int gquic_tls_ecdhe_params_x25519_generate(gquic_tls_ecdhe_params_t *param);
static int gquic_tls_ecdhe_params_x25519_dtor(void *const);

int gquic_tls_ecdhe_params_generate(gquic_tls_ecdhe_params_t *param, const u_int16_t curve_id) {
    if (param == NULL) {
        return -1;
    }
    if (curve_id != GQUIC_TLS_CURVE_X25519) {
        return -2;
    }

    return gquic_tls_ecdhe_params_x25519_generate(param);
}

int gquic_tls_ecdhe_params_init(gquic_tls_ecdhe_params_t *param) {
    if (param == NULL) {
        return -1;
    }
    param->self = NULL;
    param->curve_id = NULL;
    param->public_key = NULL;
    param->shared_key = NULL;
    param->dtor = NULL;

    return 0;
}

int gquic_tls_ecdhe_params_dtor(gquic_tls_ecdhe_params_t *param) {
    if (param == NULL) {
        return -1;
    }
    if (param->self == NULL) {
        return 0;
    }
    if (param->dtor != NULL) {
        GQUIC_TLS_ECDHE_PARAMS_DTOR(param);
        free(param->self);
    }

    return 0;
}

static int gquic_tls_ecdhe_params_x25519_generate(gquic_tls_ecdhe_params_t *param) {
    if (param == NULL) {
        return -1;
    }

    gquic_tls_x25519_params_t *x25519_param = malloc(sizeof(gquic_tls_ecdhe_params_t));
    if (x25519_param == NULL) {
        return -2;
    }
    param->self = x25519_param;
    param->curve_id = gquic_x25519_params_curve_id;
    param->public_key = gquic_x25519_params_public_key;
    param->shared_key = gquic_x25519_params_shared_key;
    param->dtor = gquic_tls_ecdhe_params_x25519_dtor;

    gquic_str_init(&x25519_param->pri_key);
    gquic_str_init(&x25519_param->pub_key);
    if (gquic_str_alloc(&x25519_param->pri_key, 32) != 0) {
        return -3;
    }
    if (gquic_str_alloc(&x25519_param->pub_key, 32) != 0) {
        return -4;
    }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL) {
        return -5;
    }
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    if (pkey == NULL) {
        return -6;
    }
    EVP_PKEY_get_raw_public_key(pkey, GQUIC_STR_VAL(&x25519_param->pub_key), &x25519_param->pub_key.size);
    EVP_PKEY_get_raw_private_key(pkey, GQUIC_STR_VAL(&x25519_param->pri_key), &x25519_param->pri_key.size);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static u_int16_t gquic_x25519_params_curve_id(const void *const param) {
    (void) param;
    return GQUIC_TLS_CURVE_X25519;
}

static int gquic_x25519_params_public_key(const void *const self, gquic_str_t *ret) {
    const gquic_tls_x25519_params_t *const param = self;
    if (self == NULL) {
        return -1;
    }
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    return gquic_str_copy(ret, &param->pub_key);
}

static int gquic_x25519_params_shared_key(const void *const self, gquic_str_t *ret, const gquic_str_t *ref) {
    const gquic_tls_x25519_params_t *const param = self;
    if (ret == NULL || ref == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(ref) != 32) {
        return -2;
    }
    gquic_str_init(ret);
    EVP_PKEY *peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, GQUIC_STR_VAL(ref), GQUIC_STR_SIZE(ref));
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, GQUIC_STR_VAL(&param->pri_key), GQUIC_STR_SIZE(&param->pri_key));
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        return -3;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        return -4;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        return -5;
    }
    if (EVP_PKEY_derive(ctx, NULL, &ret->size) <= 0) {
        return -6;
    }
    if (gquic_str_alloc(ret, GQUIC_STR_SIZE(ret)) != 0) {
        return -7;
    }
    if (EVP_PKEY_derive(ctx, GQUIC_STR_VAL(ret), &ret->size) <= 0) {
        return -8;
    }
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int gquic_tls_ecdhe_params_x25519_dtor(void *const self) {
    if (self == NULL) {
        return -1;
    }
    gquic_tls_x25519_params_t *x25519_self = self;
    gquic_str_reset(&x25519_self->pri_key);
    gquic_str_reset(&x25519_self->pub_key);
    return 0;
}

int gquic_tls_hkdf_extract(gquic_str_t *const ret, gquic_tls_mac_t *const hash, const gquic_str_t *const secret, const gquic_str_t *const salt) {
    gquic_str_t default_secret = { 0, NULL };
    EVP_PKEY_CTX *ctx = NULL;
    if (ret == NULL || hash == NULL || hash->md == NULL) {
        return -1;
    }
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL) {
        return -3;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        return -4;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, hash->md) <= 0) {
        return -5;
    }
    if (secret == NULL) {
        if (gquic_str_alloc(&default_secret, EVP_MD_size(hash->md)) != 0) {
            return -6;
        }
        memset(GQUIC_STR_VAL(&default_secret), 0, GQUIC_STR_SIZE(&default_secret));
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, GQUIC_STR_VAL(&default_secret), GQUIC_STR_SIZE(&default_secret)) <= 0) {
            return -7;
        }
    }
    else {
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, GQUIC_STR_VAL(secret), GQUIC_STR_SIZE(secret)) <= 0) {
            return -8;
        }
    }
    if (salt != NULL) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, GQUIC_STR_VAL(salt), GQUIC_STR_SIZE(salt)) <= 0) {
            gquic_str_reset(&default_secret);
            return -9;
        }
    }
    if (gquic_str_alloc(ret, EVP_MD_size(hash->md)) != 0) {
        gquic_str_reset(&default_secret);
        return -10;
    }
    if (EVP_PKEY_derive(ctx, GQUIC_STR_VAL(ret), &ret->size) <= 0) {
        gquic_str_reset(&default_secret);
        return -11;
    }
    EVP_PKEY_CTX_free(ctx);
    gquic_str_reset(&default_secret);
    return 0;
}

int gquic_tls_hkdf_expand_label(gquic_str_t *const ret,
                                gquic_tls_mac_t *const hash,
                                const gquic_str_t *const secret,
                                const gquic_str_t *const content,
                                const gquic_str_t *const label,
                                const size_t length) {
    static const gquic_str_t default_label = { 6, (void *) "tls13 " };
    EVP_PKEY_CTX *ctx = NULL;
    gquic_str_t info = { 0, NULL };
    size_t tmp = 0;
    if (ret == NULL || hash == NULL || hash->md == NULL || secret == NULL || label == NULL) {
        return -1;
    }
    if (length > (size_t) EVP_MD_size(hash->md)) {
        return -1;
    }
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL) {
        return -3;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        return -4;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, hash->md) <= 0) {
        return -5;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, GQUIC_STR_VAL(secret), GQUIC_STR_SIZE(secret)) <= 0) {
        return -6;
    }
    info.size = 2 + 1 + GQUIC_STR_SIZE(&default_label) + GQUIC_STR_SIZE(label) + 1 + GQUIC_STR_SIZE(content);
    if (gquic_str_alloc(&info, GQUIC_STR_SIZE(&info)) != 0) {
        return -7;
    }

    gquic_big_endian_transfer(GQUIC_STR_VAL(&info), &length, 2);
    tmp = GQUIC_STR_SIZE(&default_label) + GQUIC_STR_SIZE(label);
    gquic_big_endian_transfer(GQUIC_STR_VAL(&info) + 2, &tmp, 1);
    memcpy(GQUIC_STR_VAL(&info) + 3, GQUIC_STR_VAL(&default_label), GQUIC_STR_SIZE(&default_label));
    memcpy(GQUIC_STR_VAL(&info) + 3 + GQUIC_STR_SIZE(&default_label), GQUIC_STR_VAL(label), GQUIC_STR_SIZE(label));
    tmp = GQUIC_STR_SIZE(content);
    gquic_big_endian_transfer(GQUIC_STR_VAL(&info) + 3 + GQUIC_STR_SIZE(&default_label) + GQUIC_STR_SIZE(label), &tmp, 1);
    memcpy(GQUIC_STR_VAL(&info) + 3 + GQUIC_STR_SIZE(&default_label) + GQUIC_STR_SIZE(label) + 1, GQUIC_STR_VAL(content), GQUIC_STR_SIZE(content));

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, GQUIC_STR_VAL(&info), GQUIC_STR_SIZE(&info)) <= 0) {
        return -8;
    }
    if (gquic_str_alloc(ret, EVP_MD_size(hash->md)) != 0) {
        return -10;
    }
    if (EVP_PKEY_derive(ctx, GQUIC_STR_VAL(ret), &ret->size) <= 0) {
        return -11;
    }
    ret->size = length;
    EVP_PKEY_CTX_free(ctx);
    gquic_str_reset(&info);
    return 0;
}

