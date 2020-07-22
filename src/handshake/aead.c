/* src/handshake/aead.c 针对quic的包加密，对AEAD加密模块的封装
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "handshake/aead.h"
#include "util/big_endian.h"
#include "exception.h"

gquic_exception_t gquic_long_header_sealer_init(gquic_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_aead_init(&sealer->aead);
    gquic_header_protector_init(&sealer->protector);
    gquic_str_init(&sealer->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_sealer_ctor(gquic_long_header_sealer_t *const sealer,
                                                const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_header_protector_ctor(&sealer->protector, protector_suite, traffic_sec, true);
    GQUIC_ASSERT_FAST_RETURN(aead_suite->aead(&sealer->aead, key, iv));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&sealer->nonce_buf, 12));
    gquic_str_clear(&sealer->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_sealer_traffic_ctor(gquic_long_header_sealer_t *const sealer,
                                                        const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_header_protector_ctor(&sealer->protector, suite, traffic_sec, true);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_create_aead(&sealer->aead, suite, traffic_sec));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&sealer->nonce_buf, 12));
    gquic_str_clear(&sealer->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_sealer_dtor(gquic_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_aead_dtor(&sealer->aead);
    gquic_header_protector_dtor(&sealer->protector);
    gquic_str_reset(&sealer->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_sealer_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                                gquic_long_header_sealer_t *const sealer,
                                                const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata) {
    if (cipher_text == NULL || tag == NULL || sealer == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(GQUIC_STR_VAL(&sealer->nonce_buf) + GQUIC_STR_SIZE(&sealer->nonce_buf) - 8, &pn, 8));
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_AEAD_SEAL(tag, cipher_text, &sealer->aead, &sealer->nonce_buf, plain_text, addata));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_opener_init(gquic_long_header_opener_t *const opener) {
    if (opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_aead_init(&opener->aead);
    gquic_header_protector_init(&opener->protector);
    gquic_str_init(&opener->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_opener_ctor(gquic_long_header_opener_t *const opener,
                                                const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec) {
    if (opener == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_header_protector_ctor(&opener->protector, protector_suite, traffic_sec, true);
    GQUIC_ASSERT_FAST_RETURN(aead_suite->aead(&opener->aead, key, iv));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&opener->nonce_buf, 12));
    gquic_str_clear(&opener->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_opener_traffic_ctor(gquic_long_header_opener_t *const opener,
                                                        const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_header_protector_ctor(&opener->protector, suite, traffic_sec, true);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_create_aead(&opener->aead, suite, traffic_sec));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&opener->nonce_buf, 12));
    gquic_str_clear(&opener->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_opener_dtor(gquic_long_header_opener_t *const opener) {
    if (opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_aead_dtor(&opener->aead);
    gquic_header_protector_dtor(&opener->protector);
    gquic_str_reset(&opener->nonce_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_long_header_opener_open(gquic_str_t *const plain_text,
                                                gquic_long_header_opener_t *const opener,
                                                const u_int64_t pn, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    if (plain_text == NULL || opener == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(GQUIC_STR_VAL(&opener->nonce_buf) + GQUIC_STR_SIZE(&opener->nonce_buf) - 8, &pn, 8));
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_AEAD_OPEN(plain_text, &opener->aead, &opener->nonce_buf, tag, cipher_text, addata));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_sealer_init(gquic_handshake_sealer_t *const sealer) {
    if (sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_long_header_sealer_init(&sealer->sealer);
    sealer->drop_keys.cb = NULL;
    sealer->drop_keys.self = NULL;
    sealer->dropped = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_sealer_ctor(gquic_handshake_sealer_t *const sealer,
                                              const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                              const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                              void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const)) {
    if (sealer == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_cb == NULL
        || drop_keys_self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_long_header_sealer_ctor(&sealer->sealer, aead_suite, key, iv, protector_suite, traffic_sec);
    sealer->drop_keys.cb = drop_keys_cb;
    sealer->drop_keys.self = drop_keys_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
gquic_exception_t gquic_handshake_sealer_traffic_ctor(gquic_handshake_sealer_t *const sealer,
                                                      const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                      void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const)) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_long_header_sealer_traffic_ctor(&sealer->sealer, suite, traffic_sec);
    sealer->drop_keys.cb = drop_keys_cb;
    sealer->drop_keys.self = drop_keys_self;
    sealer->dropped = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_sealer_dtor(gquic_handshake_sealer_t *const sealer) {
    if (sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_sealer_dtor(&sealer->sealer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_sealer_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                              gquic_handshake_sealer_t *const sealer,
                                              const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || sealer == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_sealer_seal(tag, cipher_text, &sealer->sealer, pn, plain_text, addata));
    if (!sealer->dropped) {
        GQUIC_HANDSHAKE_SEALER_DROP_KEYS(sealer);
        sealer->dropped = true;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_opener_init(gquic_handshake_opener_t *const opener) {
    if (opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_long_header_opener_init(&opener->opener);
    opener->drop_keys.self = NULL;
    opener->drop_keys.cb = NULL;
    opener->dropped = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_opener_ctor(gquic_handshake_opener_t *const opener,
                                              const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                              const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                              void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const)) {
    if (opener == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_self == NULL
        || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_long_header_opener_ctor(&opener->opener, aead_suite, key, iv, protector_suite, traffic_sec);
    opener->drop_keys.cb = drop_keys_cb;
    opener->drop_keys.self = drop_keys_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);

}

gquic_exception_t gquic_handshake_opener_traffic_ctor(gquic_handshake_opener_t *const opener,
                                                      const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                      void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const)) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_long_header_opener_traffic_ctor(&opener->opener, suite, traffic_sec);
    opener->drop_keys.cb = drop_keys_cb;
    opener->drop_keys.self = drop_keys_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_opener_dtor(gquic_handshake_opener_t *const opener) {
    if (opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_opener_dtor(&opener->opener));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_opener_open(gquic_str_t *const plain_text,
                                              gquic_handshake_opener_t *const opener,
                                              const u_int64_t pn, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || opener == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_opener_open(plain_text, &opener->opener, pn, tag, cipher_text, addata));
    if (!opener->dropped) {
        GQUIC_HANDSHAKE_OPENER_DROP_KEYS(opener);
        opener->dropped = true;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_init(gquic_common_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sealer->available = false;
    sealer->use_handshake = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_long_header_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                   const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                   const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_sealer_ctor(&sealer->sealer.initial_sealer, aead_suite, key, iv, protector_suite, traffic_sec));
    sealer->available = true;
    sealer->use_handshake = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_long_header_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                           const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_sealer_traffic_ctor(&sealer->sealer.initial_sealer, suite, traffic_sec));
    sealer->available = true;
    sealer->use_handshake = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_handshake_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                 const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                 const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                                                 void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                 const bool is_client) {
    if (sealer == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_self == NULL
        || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!is_client) {
        GQUIC_ASSERT_FAST_RETURN(gquic_common_long_header_sealer_long_header_ctor(sealer, aead_suite, key, iv, protector_suite, traffic_sec));

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_sealer_ctor(&sealer->sealer.handshake_sealer,
                                                         aead_suite, key, iv, protector_suite, traffic_sec, drop_keys_self, drop_keys_cb));
    sealer->available = true;
    sealer->use_handshake = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_handshake_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                                         const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                                         void *drop_keys_self, int (*drop_keys_cb) (void *const),
                                                                         const bool is_client) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!is_client) {
        GQUIC_ASSERT_FAST_RETURN(gquic_common_long_header_sealer_long_header_traffic_ctor(sealer, suite, traffic_sec));

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_sealer_traffic_ctor(&sealer->sealer.handshake_sealer, suite, traffic_sec, drop_keys_self, drop_keys_cb));
    sealer->available = true;
    sealer->use_handshake = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


gquic_exception_t gquic_common_long_header_sealer_dtor(gquic_common_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!sealer->available) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (sealer->use_handshake) {
        gquic_handshake_sealer_dtor(&sealer->sealer.handshake_sealer);
    }
    else {
        gquic_long_header_sealer_dtor(&sealer->sealer.initial_sealer);
    }
    sealer->available = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_seal(gquic_str_t *const tag, gquic_str_t *const cipher_text,
                                                       gquic_common_long_header_sealer_t *const sealer,
                                                       const u_int64_t pn, const gquic_str_t *const plain_text, const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || sealer == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!sealer->available) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SEALER_UNAVAILABLE);
    }
    if (sealer->use_handshake) {
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_sealer_seal(tag, cipher_text, &sealer->sealer.handshake_sealer, pn, plain_text, addata));
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_long_header_sealer_seal(tag, cipher_text, &sealer->sealer.initial_sealer, pn, plain_text, addata));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_sealer_get_header_sealer(gquic_header_protector_t **const protector, gquic_common_long_header_sealer_t *const sealer) {
    if (protector == NULL || sealer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!sealer->available) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SEALER_UNAVAILABLE);
    }
    if (sealer->use_handshake) {
        *protector = &sealer->sealer.handshake_sealer.sealer.protector;
    }
    else {
        *protector = &sealer->sealer.initial_sealer.protector;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_init(gquic_common_long_header_opener_t *const opener) {
    if (opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    opener->available = false;
    opener->use_handshake = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_long_header_ctor(gquic_common_long_header_opener_t *const opener,
                                                                   const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                   const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec) {
    if (opener == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_opener_ctor(&opener->opener.initial_opener, aead_suite, key, iv, protector_suite, traffic_sec));
    opener->available = true;
    opener->use_handshake = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_long_header_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                                           const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_long_header_opener_traffic_ctor(&opener->opener.initial_opener, suite, traffic_sec));
    opener->available = true;
    opener->use_handshake = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_handshake_ctor(gquic_common_long_header_opener_t *const opener,
                                                                 const gquic_tls_cipher_suite_t *const aead_suite, const gquic_str_t *key, const gquic_str_t *iv,
                                                                 const gquic_tls_cipher_suite_t *const protector_suite, const gquic_str_t *const traffic_sec,
                                                                 void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                 const bool is_client) {
    if (opener == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_self == NULL
        || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (is_client) {
        GQUIC_ASSERT_FAST_RETURN(gquic_common_long_header_opener_long_header_ctor(opener, aead_suite, key, iv, protector_suite, traffic_sec));

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_opener_ctor(&opener->opener.handshake_opener,
                                                         aead_suite, key, iv, protector_suite, traffic_sec, drop_keys_self, drop_keys_cb));
    opener->available = true;
    opener->use_handshake = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_handshake_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                                         const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec,
                                                                         void *drop_keys_self, gquic_exception_t (*drop_keys_cb) (void *const),
                                                                         const bool is_client) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (is_client) {
        GQUIC_ASSERT_FAST_RETURN(gquic_common_long_header_opener_long_header_traffic_ctor(opener, suite, traffic_sec));

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_opener_traffic_ctor(&opener->opener.handshake_opener, suite, traffic_sec, drop_keys_self, drop_keys_cb));
    opener->available = true;
    opener->use_handshake = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_dtor(gquic_common_long_header_opener_t *const opener) {
    if (opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!opener->available) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (opener->use_handshake) {
        gquic_handshake_opener_dtor(&opener->opener.handshake_opener);
    }
    else {
        gquic_long_header_opener_dtor(&opener->opener.initial_opener);
    }
    opener->available = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_open(gquic_str_t *const plain_text,
                                                       gquic_common_long_header_opener_t *const opener,
                                                       const u_int64_t pn, const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    if (plain_text == NULL || opener == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!opener->available) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_OPENER_UNAVAILABLE);
    }
    if (opener->use_handshake) {
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_opener_open(plain_text, &opener->opener.handshake_opener, pn, tag, cipher_text, addata));
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_long_header_opener_open(plain_text, &opener->opener.initial_opener, pn, tag, cipher_text, addata));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_common_long_header_opener_get_header_opener(gquic_header_protector_t **const protector, gquic_common_long_header_opener_t *const opener) {
    if (protector == NULL || opener == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!opener->available) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_OPENER_UNAVAILABLE);
    }
    if (opener->use_handshake) {
        *protector = &opener->opener.handshake_opener.opener.protector;
    }
    else {
        *protector = &opener->opener.initial_opener.protector;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
