#include "tls/conn.h"

int main() {
    gquic_tls_half_conn_t enc_half_conn;
    gquic_tls_half_conn_init(&enc_half_conn);
    enc_half_conn.ver = GQUIC_TLS_VERSION_13;

    const gquic_tls_cipher_suite_t *cipher_suite;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    gquic_str_alloc(&enc_half_conn.seq, 8);
    size_t i;
    for (i = 0; i < 8; i++) { ((u_int8_t *) GQUIC_STR_VAL(&enc_half_conn.seq))[i] = 0; }

    u_int8_t key_content[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    gquic_str_t key = { sizeof(key_content), key_content };
    u_int8_t iv_content[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    gquic_str_t iv = { sizeof(iv_content), iv_content };

    int ret = gquic_tls_suite_ctor(&enc_half_conn.suite, cipher_suite, &iv, &key, NULL, 0);
    printf("suite assign: %d\n", ret);

    u_int8_t plain_text_content[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    gquic_str_t plain_text = { sizeof(plain_text_content), plain_text_content };
    gquic_str_t cipher_text = { 0, NULL };
    u_int8_t record_content[] = { 0, 1, 2, 3, 4 };
    gquic_str_t record = { sizeof(record_content), record_content };

    ret = gquic_tls_half_conn_encrypt(&cipher_text, &enc_half_conn, &record, &plain_text);
    for (i = 0; i < GQUIC_STR_SIZE(&cipher_text); i++) { printf("%02x ", ((u_int8_t *) GQUIC_STR_VAL(&cipher_text))[i]); }
    printf("\n");

    // ===================================

    gquic_tls_half_conn_t dec_half_conn;
    gquic_tls_half_conn_init(&dec_half_conn);
    dec_half_conn.ver = GQUIC_TLS_VERSION_13;
    gquic_str_alloc(&dec_half_conn.seq, 8);
    for (i = 0; i < 8; i++) { ((u_int8_t *) GQUIC_STR_VAL(&dec_half_conn.seq))[i] = 0; }
    ret = gquic_tls_suite_assign(&dec_half_conn.suite, cipher_suite, &iv, &key, NULL, 1);
    printf("suite assign: %d\n", ret);
    gquic_str_t dec_plain_text = { 0, NULL };
    u_int8_t reco_type;
    ret = gquic_tls_half_conn_decrypt(&dec_plain_text, &reco_type, &dec_half_conn, &cipher_text);
    printf("%d\n", ret);
    for (i = 0; i < GQUIC_STR_SIZE(&dec_plain_text); i++) { printf("%02x ", ((u_int8_t *) GQUIC_STR_VAL(&dec_plain_text))[i]); }
    printf("\n");

    return 0;
}

