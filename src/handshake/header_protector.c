/* src/handshake/header_protector.c 头部保护模块实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "handshake/header_protector.h"
#include "tls/key_schedule.h"
#include "exception.h"
#include "util/malloc.h"
#include <openssl/evp.h>
#include <openssl/aes.h>

/**
 * AES类加密套件的header_protector实现
 */
typedef struct gquic_aes_header_protector_s gquic_aes_header_protector_t;
struct gquic_aes_header_protector_s {
    gquic_str_t mask;
    AES_KEY key;
    bool is_long_header;
};

static gquic_exception_t gquic_aes_header_protector_init(gquic_aes_header_protector_t *const);
static gquic_exception_t gquic_aes_header_protector_ctor(gquic_aes_header_protector_t *const,
                                                         const gquic_tls_cipher_suite_t *const, const gquic_str_t *const, const bool);
static gquic_exception_t gquic_aes_header_protector_set_key(void *const, gquic_str_t *const);
static gquic_exception_t gquic_aes_header_protector_encrypt(gquic_str_t *const, u_int8_t *const, void *const);
static gquic_exception_t gquic_aes_header_protector_decrypt(gquic_str_t *const, u_int8_t *const, void *const);
static gquic_exception_t gquic_aes_header_protector_apply(gquic_str_t *const, u_int8_t *const, gquic_aes_header_protector_t *const);
static gquic_exception_t gquic_aes_header_protector_dtor(void *const);

gquic_exception_t gquic_header_protector_init(gquic_header_protector_t *const protector) {
    if (protector == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    protector->self = NULL;
    protector->encrypt = NULL;
    protector->decrypt = NULL;
    protector->dtor = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_header_protector_ctor(gquic_header_protector_t *const protector,
                                              const gquic_tls_cipher_suite_t *const suite,
                                              const gquic_str_t *const traffic_sec, const bool is_long_header) {
    if (protector == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    switch (suite->id) {
    case GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
    case GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
        GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&protector->self, gquic_aes_header_protector_t));
        gquic_aes_header_protector_init(protector->self);
        GQUIC_ASSERT_FAST_RETURN(gquic_aes_header_protector_ctor(protector->self, suite, traffic_sec, is_long_header));
        protector->set_key = gquic_aes_header_protector_set_key;
        protector->encrypt = gquic_aes_header_protector_encrypt;
        protector->decrypt = gquic_aes_header_protector_decrypt;
        protector->dtor = gquic_aes_header_protector_dtor;
        break;
    case GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        // TODO
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNSUPPORT_CIPHER_SUITE);
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNSUPPORT_CIPHER_SUITE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_aes_header_protector_init(gquic_aes_header_protector_t *const protector) {
    if (protector == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&protector->mask);
    protector->is_long_header = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_aes_header_protector_ctor(gquic_aes_header_protector_t *const protector,
                                                         const gquic_tls_cipher_suite_t *const suite,
                                                         const gquic_str_t *const traffic_sec, const bool is_long_header) {
    gquic_tls_mac_t hash;
    gquic_str_t header_protector_key = { 0, NULL };
    static const gquic_str_t label = { 7, "quic hp" };
    if (protector == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(&hash);
    suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL);
    gquic_tls_hkdf_expand_label(&header_protector_key, &hash, traffic_sec, NULL, &label, suite->key_len);
    if (AES_set_encrypt_key(GQUIC_STR_VAL(&header_protector_key), suite->key_len * 8, &protector->key) < 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SET_ENCRYPT_KEY_ERROR);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&protector->mask, suite->key_len));
    protector->is_long_header = is_long_header;

    gquic_tls_mac_dtor(&hash);
    gquic_str_reset(&header_protector_key);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_aes_header_protector_set_key(void *const self_, gquic_str_t *const sample) {
    gquic_aes_header_protector_t *const self = self_;
    if (self == NULL || sample == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(sample) != GQUIC_STR_SIZE(&self->mask)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SIMPLE_MASK_INCONSISTENT);
    }
    AES_encrypt(GQUIC_STR_VAL(sample), GQUIC_STR_VAL(&self->mask), &self->key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_aes_header_protector_encrypt(gquic_str_t *const header, u_int8_t *const first_byte, void *const self) {
    return gquic_aes_header_protector_apply(header, first_byte, self);
}

static gquic_exception_t gquic_aes_header_protector_decrypt(gquic_str_t *const header, u_int8_t *const first_byte, void *const self) {
    return gquic_aes_header_protector_apply(header, first_byte, self);
}

static gquic_exception_t gquic_aes_header_protector_apply(gquic_str_t *const header, u_int8_t *const first_byte,
                                                          gquic_aes_header_protector_t *const self) {
    size_t i;
    if (self == NULL || (header == NULL && first_byte == NULL)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_aes_header_protector_dtor(void *const protector) {
    if (protector == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&((gquic_aes_header_protector_t *) protector)->mask);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_header_protector_dtor(gquic_header_protector_t *const protector) {
    if (protector == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (protector->dtor != NULL && protector->self != NULL) {
        GQUIC_ASSERT_FAST_RETURN(protector->dtor(protector->self));
        gquic_free(protector->self);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
