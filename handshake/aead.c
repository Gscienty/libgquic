#include "handshake/aead.h"
#include "util/big_endian.h"

int gquic_long_header_sealer_init(gquic_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    gquic_tls_aead_init(&sealer->aead);
    gquic_header_protector_init(&sealer->protector);
    gquic_str_init(&sealer->nonce_buf);

    return 0;
}

int gquic_long_header_sealer_ctor(gquic_long_header_sealer_t *const sealer,
                                  const gquic_tls_cipher_suite_t *const aead_suite,
                                  const gquic_str_t *key,
                                  const gquic_str_t *iv,
                                  const gquic_tls_cipher_suite_t *const protector_suite,
                                  const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_header_protector_ctor(&sealer->protector, protector_suite, traffic_sec, 1);
    if (aead_suite->aead(&sealer->aead, key, iv) != 0) {
        return -2;
    }
    if (gquic_str_alloc(&sealer->nonce_buf, 12) != 0) {
        return -3;
    }
    gquic_str_clear(&sealer->nonce_buf);

    return 0;
}

int gquic_long_header_sealer_traffic_ctor(gquic_long_header_sealer_t *const sealer,
                                          const gquic_tls_cipher_suite_t *const suite,
                                          const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_header_protector_ctor(&sealer->protector, suite, traffic_sec, 1);
    if (gquic_tls_create_aead(&sealer->aead, suite, traffic_sec) != 0) {
        return -2;
    }
    if (gquic_str_alloc(&sealer->nonce_buf, 12) != 0) {
        return -3;
    }
    gquic_str_clear(&sealer->nonce_buf);

    return 0;
}

int gquic_long_header_sealer_dtor(gquic_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    gquic_tls_aead_dtor(&sealer->aead);
    gquic_header_protector_dtor(&sealer->protector);
    gquic_str_reset(&sealer->nonce_buf);

    return 0;
}

int gquic_long_header_sealer_seal(gquic_str_t *const tag,
                                  gquic_str_t *const cipher_text,
                                  gquic_long_header_sealer_t *const sealer,
                                  const u_int64_t pn,
                                  const gquic_str_t *const plain_text,
                                  const gquic_str_t *const addata) {
    if (cipher_text == NULL || tag == NULL || sealer == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(&sealer->nonce_buf) + GQUIC_STR_SIZE(&sealer->nonce_buf) - 8, &pn, 8) != 0) {
        return -2;
    }
    if (GQUIC_TLS_AEAD_SEAL(tag, cipher_text, &sealer->aead, &sealer->nonce_buf, plain_text, addata) != 0) {
        return -3;
    }
    return 0;
}

int gquic_long_header_opener_init(gquic_long_header_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    gquic_tls_aead_init(&opener->aead);
    gquic_header_protector_init(&opener->protector);
    gquic_str_init(&opener->nonce_buf);

    return 0;
}

int gquic_long_header_opener_ctor(gquic_long_header_opener_t *const opener,
                                  const gquic_tls_cipher_suite_t *const aead_suite,
                                  const gquic_str_t *key,
                                  const gquic_str_t *iv,
                                  const gquic_tls_cipher_suite_t *const protector_suite,
                                  const gquic_str_t *const traffic_sec) {
    if (opener == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_header_protector_ctor(&opener->protector, protector_suite, traffic_sec, 1);
    if (aead_suite->aead(&opener->aead, key, iv) != 0) {
        return -2;
    }
    if (gquic_str_alloc(&opener->nonce_buf, 12) != 0) {
        return -3;
    }
    gquic_str_clear(&opener->nonce_buf);
    return 0;
}

int gquic_long_header_opener_traffic_ctor(gquic_long_header_opener_t *const opener,
                                          const gquic_tls_cipher_suite_t *const suite,
                                          const gquic_str_t *const traffic_sec) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_header_protector_ctor(&opener->protector, suite, traffic_sec, 1);
    if (gquic_tls_create_aead(&opener->aead, suite, traffic_sec) != 0) {
        return -2;
    }
    if (gquic_str_alloc(&opener->nonce_buf, 12) != 0) {
        return -3;
    }
    gquic_str_clear(&opener->nonce_buf);
    return 0;
}

int gquic_long_header_opener_dtor(gquic_long_header_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    gquic_tls_aead_dtor(&opener->aead);
    gquic_header_protector_dtor(&opener->protector);
    gquic_str_reset(&opener->nonce_buf);

    return 0;
}

int gquic_long_header_opener_open(gquic_str_t *const plain_text,
                                  gquic_long_header_opener_t *const opener,
                                  const u_int64_t pn,
                                  const gquic_str_t *const tag,
                                  const gquic_str_t *const cipher_text,
                                  const gquic_str_t *const addata) {
    if (plain_text == NULL || opener == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(&opener->nonce_buf) + GQUIC_STR_SIZE(&opener->nonce_buf) - 8, &pn, 8) != 0) {
        return -2;
    }
    if (GQUIC_TLS_AEAD_OPEN(plain_text, &opener->aead, &opener->nonce_buf, tag, cipher_text, addata) != 0) {
        return -3;
    }
    return 0;
}

int gquic_handshake_sealer_init(gquic_handshake_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    gquic_long_header_sealer_init(&sealer->sealer);
    sealer->drop_keys.cb = NULL;
    sealer->drop_keys.self = NULL;
    sealer->dropped = 0;
    return 0;
}

int gquic_handshake_sealer_ctor(gquic_handshake_sealer_t *const sealer,
                                const gquic_tls_cipher_suite_t *const aead_suite,
                                const gquic_str_t *key,
                                const gquic_str_t *iv,
                                const gquic_tls_cipher_suite_t *const protector_suite,
                                const gquic_str_t *const traffic_sec,
                                void *drop_keys_self,
                                int (*drop_keys_cb) (void *const)) {
    if (sealer == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_cb == NULL
        || drop_keys_self == NULL) {
        return -1;
    }
    gquic_long_header_sealer_ctor(&sealer->sealer, aead_suite, key, iv, protector_suite, traffic_sec);
    sealer->drop_keys.cb = drop_keys_cb;
    sealer->drop_keys.self = drop_keys_self;

    return 0;
}
int gquic_handshake_sealer_traffic_ctor(gquic_handshake_sealer_t *const sealer,
                                        const gquic_tls_cipher_suite_t *const suite,
                                        const gquic_str_t *const traffic_sec,
                                        void *drop_keys_self,
                                        int (*drop_keys_cb) (void *const)) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        return -1;
    }
    gquic_long_header_sealer_traffic_ctor(&sealer->sealer, suite, traffic_sec);
    sealer->drop_keys.cb = drop_keys_cb;
    sealer->drop_keys.self = drop_keys_self;
    return 0;
}

int gquic_handshake_sealer_dtor(gquic_handshake_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    if (gquic_long_header_sealer_dtor(&sealer->sealer) != 0) {
        return -2;
    }
    return 0;
}

int gquic_handshake_sealer_seal(gquic_str_t *const tag,
                                gquic_str_t *const cipher_text,
                                gquic_handshake_sealer_t *const sealer,
                                const u_int64_t pn,
                                const gquic_str_t *const plain_text,
                                const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || sealer == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    if (gquic_long_header_sealer_seal(tag, cipher_text, &sealer->sealer, pn, plain_text, addata) != 0) {
        return -2;
    }
    if (!sealer->dropped) {
        GQUIC_HANDSHAKE_SEALER_DROP_KEYS(sealer);
        sealer->dropped = 1;
    }
    return 0;
}

int gquic_handshake_opener_init(gquic_handshake_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    gquic_long_header_opener_init(&opener->opener);
    opener->drop_keys.self = NULL;
    opener->drop_keys.cb = NULL;
    opener->dropped = 0;
    return 0;
}

int gquic_handshake_opener_ctor(gquic_handshake_opener_t *const opener,
                                const gquic_tls_cipher_suite_t *const aead_suite,
                                const gquic_str_t *key,
                                const gquic_str_t *iv,
                                const gquic_tls_cipher_suite_t *const protector_suite,
                                const gquic_str_t *const traffic_sec,
                                void *drop_keys_self,
                                int (*drop_keys_cb) (void *const)) {
    if (opener == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_self == NULL
        || drop_keys_cb == NULL) {
        return -1;
    }
    gquic_long_header_opener_ctor(&opener->opener, aead_suite, key, iv, protector_suite, traffic_sec);
    opener->drop_keys.cb = drop_keys_cb;
    opener->drop_keys.self = drop_keys_self;

    return 0;

}

int gquic_handshake_opener_traffic_ctor(gquic_handshake_opener_t *const opener,
                                        const gquic_tls_cipher_suite_t *const suite,
                                        const gquic_str_t *const traffic_sec,
                                        void *drop_keys_self,
                                        int (*drop_keys_cb) (void *const)) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        return -1;
    }
    gquic_long_header_opener_traffic_ctor(&opener->opener, suite, traffic_sec);
    opener->drop_keys.cb = drop_keys_cb;
    opener->drop_keys.self = drop_keys_self;
    return 0;

}

int gquic_handshake_opener_dtor(gquic_handshake_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    if (gquic_long_header_opener_dtor(&opener->opener) != 0) {
        return -2;
    }
    return 0;
}

int gquic_handshake_opener_open(gquic_str_t *const plain_text,
                                gquic_handshake_opener_t *const opener,
                                const u_int64_t pn,
                                const gquic_str_t *const tag,
                                const gquic_str_t *const cipher_text,
                                const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || opener == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    if (gquic_long_header_opener_open(plain_text, &opener->opener, pn, tag, cipher_text, addata) != 0) {
        return -2;
    }
    if (!opener->dropped) {
        GQUIC_HANDSHAKE_OPENER_DROP_KEYS(opener);
        opener->dropped = 1;
    }
    return 0;
}

int gquic_common_long_header_sealer_init(gquic_common_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    sealer->available = 0;
    sealer->use_handshake = 0;

    return 0;
}

int gquic_common_long_header_sealer_long_header_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                     const gquic_tls_cipher_suite_t *const aead_suite,
                                                     const gquic_str_t *key,
                                                     const gquic_str_t *iv,
                                                     const gquic_tls_cipher_suite_t *const protector_suite,
                                                     const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    if (gquic_long_header_sealer_ctor(&sealer->sealer.long_header_sealer, aead_suite, key, iv, protector_suite, traffic_sec) != 0) {
        return -2;
    }
    sealer->available = 1;
    sealer->use_handshake = 0;
    return 0;
}

int gquic_common_long_header_sealer_long_header_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                             const gquic_tls_cipher_suite_t *const suite,
                                                             const gquic_str_t *const traffic_sec) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    if (gquic_long_header_sealer_traffic_ctor(&sealer->sealer.long_header_sealer, suite, traffic_sec) != 0) {
        return -2;
    }
    sealer->available = 1;
    sealer->use_handshake = 0;
    return 0;
}

int gquic_common_long_header_sealer_handshake_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                   const gquic_tls_cipher_suite_t *const aead_suite,
                                                   const gquic_str_t *key,
                                                   const gquic_str_t *iv,
                                                   const gquic_tls_cipher_suite_t *const protector_suite,
                                                   const gquic_str_t *const traffic_sec,
                                                   void *drop_keys_self,
                                                   int (*drop_keys_cb) (void *const),
                                                   int is_client) {
    if (sealer == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_self == NULL
        || drop_keys_cb == NULL) {
        return -1;
    }
    if (!is_client) {
        return gquic_common_long_header_sealer_long_header_ctor(sealer, aead_suite, key, iv, protector_suite, traffic_sec);
    }
    if (gquic_handshake_sealer_ctor(&sealer->sealer.handshake_sealer, aead_suite, key, iv, protector_suite, traffic_sec, drop_keys_self, drop_keys_cb) != 0) {
        return -2;
    }
    sealer->available = 1;
    sealer->use_handshake = 1;
    return 0;
}

int gquic_common_long_header_sealer_handshake_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                           const gquic_tls_cipher_suite_t *const suite,
                                                           const gquic_str_t *const traffic_sec,
                                                           void *drop_keys_self,
                                                           int (*drop_keys_cb) (void *const),
                                                           int is_client) {
    if (sealer == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        return -1;
    }
    if (!is_client) {
        return gquic_common_long_header_sealer_long_header_traffic_ctor(sealer, suite, traffic_sec);
    }
    if (gquic_handshake_sealer_traffic_ctor(&sealer->sealer.handshake_sealer, suite, traffic_sec, drop_keys_self, drop_keys_cb) != 0) {
        return -2;
    }
    sealer->available = 1;
    sealer->use_handshake = 1;
    return 0;
}


int gquic_common_long_header_sealer_dtor(gquic_common_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    if (!sealer->available) {
        return 0;
    }
    if (sealer->use_handshake) {
        gquic_handshake_sealer_dtor(&sealer->sealer.handshake_sealer);
    }
    else {
        gquic_long_header_sealer_dtor(&sealer->sealer.long_header_sealer);
    }
    sealer->available = 0;
    return 0;
}

int gquic_common_long_header_sealer_seal(gquic_str_t *const tag,
                                         gquic_str_t *const cipher_text,
                                         gquic_common_long_header_sealer_t *const sealer,
                                         const u_int64_t pn,
                                         const gquic_str_t *const plain_text,
                                         const gquic_str_t *const addata) {
    if (tag == NULL || cipher_text == NULL || sealer == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    if (!sealer->available) {
        return -2;
    }
    if (sealer->use_handshake) {
        return gquic_handshake_sealer_seal(tag, cipher_text, &sealer->sealer.handshake_sealer, pn, plain_text, addata);
    }
    else {
        return gquic_long_header_sealer_seal(tag, cipher_text, &sealer->sealer.long_header_sealer, pn, plain_text, addata);
    }
}

int gquic_common_long_header_sealer_get_header_sealer(gquic_header_protector_t **const protector,
                                                      gquic_common_long_header_sealer_t *const sealer) {
    if (protector == NULL || sealer == NULL) {
        return -1;
    }
    if (!sealer->available) {
        return -2;
    }
    if (sealer->use_handshake) {
        *protector = &sealer->sealer.handshake_sealer.sealer.protector;
    }
    else {
        *protector = &sealer->sealer.long_header_sealer.protector;
    }

    return 0;
}

int gquic_common_long_header_opener_init(gquic_common_long_header_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    opener->available = 0;
    opener->use_handshake = 0;

    return 0;
}

int gquic_common_long_header_opener_long_header_ctor(gquic_common_long_header_opener_t *const opener,
                                                     const gquic_tls_cipher_suite_t *const aead_suite,
                                                     const gquic_str_t *key,
                                                     const gquic_str_t *iv,
                                                     const gquic_tls_cipher_suite_t *const protector_suite,
                                                     const gquic_str_t *const traffic_sec) {
    if (opener == NULL || aead_suite == NULL || key == NULL || iv == NULL || protector_suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    if (gquic_long_header_opener_ctor(&opener->opener.long_header_opener, aead_suite, key, iv, protector_suite, traffic_sec) != 0) {
        return -2;
    }
    opener->available = 1;
    opener->use_handshake = 0;
    return 0;
}

int gquic_common_long_header_opener_long_header_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                             const gquic_tls_cipher_suite_t *const suite,
                                                             const gquic_str_t *const traffic_sec) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    if (gquic_long_header_opener_traffic_ctor(&opener->opener.long_header_opener, suite, traffic_sec) != 0) {
        return -2;
    }
    opener->available = 1;
    opener->use_handshake = 0;
    return 0;
}

int gquic_common_long_header_opener_handshake_ctor(gquic_common_long_header_opener_t *const opener,
                                                   const gquic_tls_cipher_suite_t *const aead_suite,
                                                   const gquic_str_t *key,
                                                   const gquic_str_t *iv,
                                                   const gquic_tls_cipher_suite_t *const protector_suite,
                                                   const gquic_str_t *const traffic_sec,
                                                   void *drop_keys_self,
                                                   int (*drop_keys_cb) (void *const),
                                                   int is_client) {
    if (opener == NULL
        || aead_suite == NULL
        || key == NULL
        || iv == NULL
        || protector_suite == NULL
        || traffic_sec == NULL
        || drop_keys_self == NULL
        || drop_keys_cb == NULL) {
        return -1;
    }
    if (is_client) {
        return gquic_common_long_header_opener_long_header_ctor(opener, aead_suite, key, iv, protector_suite, traffic_sec);
    }
    if (gquic_handshake_opener_ctor(&opener->opener.handshake_opener, aead_suite, key, iv, protector_suite, traffic_sec, drop_keys_self, drop_keys_cb) != 0) {
        return -2;
    }
    opener->available = 1;
    opener->use_handshake = 1;
    return 0;
}

int gquic_common_long_header_opener_handshake_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                           const gquic_tls_cipher_suite_t *const suite,
                                                           const gquic_str_t *const traffic_sec,
                                                           void *drop_keys_self,
                                                           int (*drop_keys_cb) (void *const),
                                                           int is_client) {
    if (opener == NULL || suite == NULL || traffic_sec == NULL || drop_keys_self == NULL || drop_keys_cb == NULL) {
        return -1;
    }
    if (is_client) {
        return gquic_common_long_header_opener_long_header_traffic_ctor(opener, suite, traffic_sec);
    }
    if (gquic_handshake_opener_traffic_ctor(&opener->opener.handshake_opener, suite, traffic_sec, drop_keys_self, drop_keys_cb) != 0) {
        return -2;
    }
    opener->available = 1;
    opener->use_handshake = 1;
    return 0;
}

int gquic_common_long_header_opener_dtor(gquic_common_long_header_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    if (!opener->available) {
        return 0;
    }
    if (opener->use_handshake) {
        gquic_handshake_opener_dtor(&opener->opener.handshake_opener);
    }
    else {
        gquic_long_header_opener_dtor(&opener->opener.long_header_opener);
    }
    opener->available = 0;
    return 0;
}

int gquic_common_long_header_opener_open(gquic_str_t *const plain_text,
                                         gquic_common_long_header_opener_t *const opener,
                                         const u_int64_t pn,
                                         const gquic_str_t *const tag,
                                         const gquic_str_t *const cipher_text,
                                         const gquic_str_t *const addata) {
    if (plain_text == NULL || opener == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    if (!opener->available) {
        return -2;
    }
    if (opener->use_handshake) {
        return gquic_handshake_opener_open(plain_text, &opener->opener.handshake_opener, pn, tag, cipher_text, addata);
    }
    else {
        return gquic_long_header_opener_open(plain_text, &opener->opener.long_header_opener, pn, tag, cipher_text, addata);
    }
}

int gquic_common_long_header_opener_get_header_opener(gquic_header_protector_t **const protector,
                                                      gquic_common_long_header_opener_t *const opener) {
    if (protector == NULL || opener == NULL) {
        return -1;
    }
    if (!opener->available) {
        return -2;
    }
    if (opener->use_handshake) {
        *protector = &opener->opener.handshake_opener.opener.protector;
    }
    else {
        *protector = &opener->opener.long_header_opener.protector;
    }

    return 0;
}
