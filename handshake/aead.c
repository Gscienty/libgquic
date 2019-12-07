#include "handshake/aead.h"
#include "util/big_endian.h"

int gquic_long_header_sealer_init(gquic_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    gquic_tls_aead_init(&sealer->aead);
    gquic_header_protector_init(&sealer->protector);
    gquic_str_init(&sealer->nonce_buf);
    if (gquic_str_alloc(&sealer->nonce_buf, 12) != 0) {
        return -2;
    }

    return 0;
}

int gquic_long_header_sealer_release(gquic_long_header_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    gquic_tls_aead_release(&sealer->aead);
    gquic_header_protector_release(&sealer->protector);
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
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(&sealer->nonce_buf) - 8, &pn, 8) != 0) {
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
    if (gquic_str_alloc(&opener->nonce_buf, 12) != 0) {
        return -2;
    }

    return 0;
}

int gquic_long_header_opener_release(gquic_long_header_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    gquic_tls_aead_release(&opener->aead);
    gquic_header_protector_release(&opener->protector);
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
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(&opener->nonce_buf) - 8, &pn, 8) != 0) {
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
    if (gquic_long_header_sealer_init(&sealer->sealer) != 0) {
        return -2;
    }
    sealer->drop_keys_self = NULL;
    sealer->drop_keys = NULL;
    sealer->dropped = 0;
    sealer->is_client = 0;
    return 0;
}

int gquic_handshake_sealer_release(gquic_handshake_sealer_t *const sealer) {
    if (sealer == NULL) {
        return -1;
    }
    if (gquic_long_header_sealer_release(&sealer->sealer) != 0) {
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
    if (sealer->is_client) {
        return 0;
    }
    if (!sealer->dropped) {
        sealer->drop_keys(sealer->drop_keys_self);
        sealer->dropped = 1;
    }
    return 0;
}

int gquic_handshake_opener_init(gquic_handshake_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    if (gquic_long_header_opener_init(&opener->opener) != 0) {
        return -2;
    }
    opener->drop_keys_self = NULL;
    opener->drop_keys = NULL;
    opener->dropped = 0;
    opener->is_client = 0;
    return 0;
}

int gquic_handshake_opener_release(gquic_handshake_opener_t *const opener) {
    if (opener == NULL) {
        return -1;
    }
    if (gquic_long_header_opener_release(&opener->opener) != 0) {
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
    if (opener->is_client) {
        return 0;
    }
    if (!opener->dropped) {
        opener->drop_keys(opener->drop_keys_self);
        opener->dropped = 1;
    }
    return 0;
}
