#include "handshake/initial_aead.h"
#include "tls/key_schedule.h"
#include "tls/cipher_suite.h"
#include "exception.h"

static int gquic_handshake_generate_secs(gquic_str_t *const, gquic_str_t *const, const gquic_str_t *const);
static int gquic_handshake_generate_key_iv(gquic_str_t *const, gquic_str_t *const, const gquic_str_t *const);

int gquic_handshake_initial_aead_init(gquic_common_long_header_sealer_t *const sealer,
                                      gquic_common_long_header_opener_t *const opener,
                                      const gquic_str_t *const conn_id,
                                      int is_client) {
    int exception = GQUIC_SUCCESS;
    gquic_str_t cli_sec = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    gquic_str_t cli_key = { 0, NULL };
    gquic_str_t cli_iv = { 0, NULL };
    gquic_str_t ser_key = { 0, NULL };
    gquic_str_t ser_iv = { 0, NULL };
    const gquic_tls_cipher_suite_t *suite = NULL;
    if (sealer == NULL || opener == NULL || conn_id == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_get_cipher_suite(&suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256));
    gquic_common_long_header_sealer_init(sealer);
    gquic_common_long_header_opener_init(opener);
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_generate_secs(&cli_sec, &ser_sec, conn_id));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_handshake_generate_key_iv(&cli_key, &cli_iv, &cli_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_handshake_generate_key_iv(&ser_key, &ser_iv, &ser_sec))) {
        goto failure;
    }
    if (is_client) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_sealer_long_header_ctor(sealer, suite, &cli_key, &cli_iv, suite, &cli_sec))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_opener_long_header_ctor(opener, suite, &ser_key, &ser_iv, suite, &ser_sec))) {
            goto failure;
        }
    }
    else {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_sealer_long_header_ctor(sealer, suite, &ser_key, &ser_iv, suite, &ser_sec))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_opener_long_header_ctor(opener, suite, &cli_key, &cli_iv, suite, &cli_sec))) {
            goto failure;
        }
    }

    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_str_reset(&cli_key);
    gquic_str_reset(&cli_iv);
    gquic_str_reset(&ser_key);
    gquic_str_reset(&ser_iv);
    return GQUIC_SUCCESS;

failure:
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_str_reset(&cli_key);
    gquic_str_reset(&cli_iv);
    gquic_str_reset(&ser_key);
    gquic_str_reset(&ser_iv);
    return exception;
}

static int gquic_handshake_generate_secs(gquic_str_t *const cli_sec, gquic_str_t *const ser_sec, const gquic_str_t *const conn_id) {
    static const u_int8_t salt_cnt[] = {
        0xc3, 0xee, 0xf7, 0x12,
        0xc7, 0x2e, 0xbb, 0x5a,
        0x11, 0xa7, 0xd2, 0x43,
        0x2b, 0xb4, 0x63, 0x65,
        0xbe, 0xf9, 0xf5, 0x02
    };
    static const gquic_str_t salt = { sizeof(salt_cnt), (void *) salt_cnt };
    static const gquic_str_t cli_sec_label = { 9, "client in" };
    static const gquic_str_t ser_sec_label = { 9, "server in" };
    int exception = GQUIC_SUCCESS;
    gquic_str_t initial_sec = { 0, NULL };
    const gquic_tls_cipher_suite_t *suite = NULL;
    gquic_tls_mac_t hash;
    if (cli_sec == NULL || ser_sec == NULL || conn_id == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_str_init(cli_sec);
    gquic_str_init(ser_sec);
    gquic_tls_mac_init(&hash);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_get_cipher_suite(&suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256));
    GQUIC_ASSERT_FAST_RETURN(suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_extract(&initial_sec, &hash, conn_id, &salt))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(cli_sec, &hash, &initial_sec, NULL, &cli_sec_label, EVP_MD_size(hash.md)))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(ser_sec, &hash, &initial_sec, NULL, &ser_sec_label, EVP_MD_size(hash.md)))) {
        goto failure;
    }
    
    gquic_str_reset(&initial_sec);
    gquic_tls_mac_dtor(&hash);
    return 0;
failure:

    gquic_str_reset(&initial_sec);
    gquic_tls_mac_dtor(&hash);
    return exception;
}

static int gquic_handshake_generate_key_iv(gquic_str_t *const key, gquic_str_t *const iv, const gquic_str_t *const sec) {
    int exception = GQUIC_SUCCESS;
    static const gquic_str_t key_label = { 8, "quic key" };
    static const gquic_str_t iv_label = { 7, "quic iv" };
    const gquic_tls_cipher_suite_t *suite = NULL;
    gquic_tls_mac_t hash;
    if (key == NULL || iv == NULL || sec == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_tls_mac_init(&hash);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_get_cipher_suite(&suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256));
    GQUIC_ASSERT_FAST_RETURN(suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(key, &hash, sec, NULL, &key_label, 16))) {
        gquic_tls_mac_dtor(&hash);
        return exception;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hkdf_expand_label(iv, &hash, sec, NULL, &iv_label, 16))) {
        gquic_tls_mac_dtor(&hash);
        return exception;
    }

    gquic_tls_mac_dtor(&hash);
    return GQUIC_SUCCESS;
}
