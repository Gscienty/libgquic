#include "tls/common.h"
#include "tls/key_schedule.h"
#include "util/str.h"
#include "util/big_endian.h"
#include <openssl/evp.h>

typedef struct gquic_tls_x25519_params_s gquic_tls_x25519_params_t;
struct gquic_tls_x25519_params_s {
    gquic_str_t pri_key;
    gquic_str_t pub_key;
};

static u_int16_t gquic_x25519_params_curve_id(const void *const);
static int gquic_x25519_params_public_key(const void *const, gquic_str_t *);
static int gquic_x25519_params_shared_key(const void *const, gquic_str_t *, const gquic_str_t *);

static int gquic_tls_ecdhe_params_generate_x25519(gquic_tls_ecdhe_params_t *param);
static int gquic_tls_ecdhe_params_release_x25519(void *const);

int gquic_tls_ecdhe_params_generate(gquic_tls_ecdhe_params_t *param, const u_int16_t curve_id) {
    if (param == NULL) {
        return -1;
    }
    if (curve_id != GQUIC_TLS_CURVE_X25519) {
        return -2;
    }

    return gquic_tls_ecdhe_params_generate_x25519(param);
}

int gquic_tls_ecdhe_params_init(gquic_tls_ecdhe_params_t *param) {
    if (param == NULL) {
        return -1;
    }
    param->self = NULL;
    param->curve_id = NULL;
    param->public_key = NULL;
    param->shared_key = NULL;
    param->release = NULL;

    return 0;
}

int gquic_tls_ecdhe_params_release(gquic_tls_ecdhe_params_t *param) {
    if (param == NULL) {
        return -1;
    }
    if (param->self == NULL) {
        return 0;
    }
    if (param->release != NULL) {
        param->release(param->self);
    }

    return 0;
}

static int gquic_tls_ecdhe_params_generate_x25519(gquic_tls_ecdhe_params_t *param) {
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
    param->release = gquic_tls_ecdhe_params_release_x25519;

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

static int gquic_tls_ecdhe_params_release_x25519(void *const self) {
    if (self == NULL) {
        return -1;
    }
    gquic_tls_x25519_params_t *x25519_self = self;
    gquic_str_reset(&x25519_self->pri_key);
    gquic_str_reset(&x25519_self->pub_key);
    return 0;
}

