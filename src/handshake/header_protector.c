#include "handshake/header_protector.h"
#include "tls/key_schedule.h"
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

typedef struct gquic_aes_header_protector_s gquic_aes_header_protector_t;
struct gquic_aes_header_protector_s {
    gquic_str_t mask;
    AES_KEY key;
    int is_long_header;
};

static int gquic_aes_header_protector_init(gquic_aes_header_protector_t *const);
static int gquic_aes_header_protector_ctor(gquic_aes_header_protector_t *const,
                                           const gquic_tls_cipher_suite_t *const,
                                           const gquic_str_t *const,
                                           int);
static int gquic_aes_header_protector_set_key(void *const, gquic_str_t *const);
static int gquic_aes_header_protector_encrypt(gquic_str_t *const, u_int8_t *const, void *const);
static int gquic_aes_header_protector_decrypt(gquic_str_t *const, u_int8_t *const, void *const);
static int gquic_aes_header_protector_apply(gquic_str_t *const,
                                            u_int8_t *const,
                                            gquic_aes_header_protector_t *const);
static int gquic_aes_header_protector_dtor(void *const);

int gquic_header_protector_init(gquic_header_protector_t *const protector) {
    if (protector == NULL) {
        return -1;
    }
    protector->self = NULL;
    protector->encrypt = NULL;
    protector->decrypt = NULL;
    protector->dtor = NULL;
    return 0;
}

int gquic_header_protector_ctor(gquic_header_protector_t *const protector,
                                const gquic_tls_cipher_suite_t *const suite,
                                const gquic_str_t *const traffic_sec,
                                int is_long_header) {
    if (protector == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }

    switch (suite->id) {
    case GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
    case GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
        if ((protector->self = malloc(sizeof(gquic_aes_header_protector_t))) == NULL) {
            return -2;
        }
        gquic_aes_header_protector_init(protector->self);
        if (gquic_aes_header_protector_ctor(protector->self, suite, traffic_sec, is_long_header) != 0) {
            return -3;
        }
        protector->set_key = gquic_aes_header_protector_set_key;
        protector->encrypt = gquic_aes_header_protector_encrypt;
        protector->decrypt = gquic_aes_header_protector_decrypt;
        protector->dtor = gquic_aes_header_protector_dtor;
        break;
    case GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        // TODO
    default:
        return -4;
    }

    return 0;
}

static int gquic_aes_header_protector_init(gquic_aes_header_protector_t *const protector) {
    if (protector == NULL) {
        return -1;
    }
    gquic_str_init(&protector->mask);
    protector->is_long_header = 0;

    return 0;
}

static int gquic_aes_header_protector_ctor(gquic_aes_header_protector_t *const protector,
                                                     const gquic_tls_cipher_suite_t *const suite,
                                                     const gquic_str_t *const traffic_sec,
                                                     int is_long_header) {
    gquic_tls_mac_t hash;
    gquic_str_t header_protector_key = { 0, NULL };
    static const gquic_str_t label = { 7, "quic hp" };
    if (protector == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_tls_mac_init(&hash);
    suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL);
    gquic_tls_hkdf_expand_label(&header_protector_key, &hash, traffic_sec, NULL, &label, suite->key_len);
    if (AES_set_encrypt_key(GQUIC_STR_VAL(&header_protector_key), suite->key_len * 8, &protector->key) < 0) {
        return -2;
    }
    if (gquic_str_alloc(&protector->mask, suite->key_len) != 0) {
        return -3;
    }
    protector->is_long_header = is_long_header;

    gquic_tls_mac_dtor(&hash);
    gquic_str_reset(&header_protector_key);
    return 0;
}

static int gquic_aes_header_protector_set_key(void *const self_, gquic_str_t *const sample) {
    gquic_aes_header_protector_t *const self = self_;
    if (self == NULL || sample == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(sample) != GQUIC_STR_SIZE(&self->mask)) {
        return -2;
    }
    AES_encrypt(GQUIC_STR_VAL(sample), GQUIC_STR_VAL(&self->mask), &self->key);
    return 0;
}

static int gquic_aes_header_protector_encrypt(gquic_str_t *const header,
                                              u_int8_t *const first_byte,
                                              void *const self) {
    return gquic_aes_header_protector_apply(header, first_byte, self);
}

static int gquic_aes_header_protector_decrypt(gquic_str_t *const header,
                                              u_int8_t *const first_byte,
                                              void *const self) {
    return gquic_aes_header_protector_apply(header, first_byte, self);
}

static int gquic_aes_header_protector_apply(gquic_str_t *const header,
                                            u_int8_t *const first_byte,
                                            gquic_aes_header_protector_t *const self) {
    size_t i;
    if (self == NULL || (header == NULL && first_byte == NULL)) {
        return -1;
    }
    if (first_byte != NULL) {
        if (self->is_long_header) {
            *first_byte ^= GQUIC_STR_FIRST_BYTE(&self->mask) & 0x0f;
        }
        else {
            *first_byte ^= GQUIC_STR_FIRST_BYTE(&self->mask) & 0x1f;
        }
    }
    if (header != NULL) {
        for (i = 0; i < GQUIC_STR_SIZE(header); i++) {
            ((u_int8_t *) GQUIC_STR_VAL(header))[i] ^= ((u_int8_t *) GQUIC_STR_VAL(&self->mask))[i % GQUIC_STR_SIZE(&self->mask)];
        }
    }

    return 0;
}

static int gquic_aes_header_protector_dtor(void *const protector) {
    if (protector == NULL) {
        return -1;
    }
    gquic_str_reset(&((gquic_aes_header_protector_t *) protector)->mask);
    return 0;
}

int gquic_header_protector_dtor(gquic_header_protector_t *const protector) {
    if (protector == NULL) {
        return -1;
    }

    if (protector->dtor != NULL && protector->self != NULL) {
        if (protector->dtor(protector->self) != 0) {
            return -2;
        }
        free(protector->self);
    }
    return 0;
}
