#include "tls/cipher_suite.h"

int main() {
    gquic_str_t sec = { 5, "hello" };
    gquic_str_t label = { 5 , "world" };
    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    gquic_tls_mac_t mac;
    gquic_tls_mac_init(&mac);
    cipher_suite->mac(&mac, 0, NULL);

    gquic_tls_mac_md_update(&mac, &sec);

    gquic_str_t ret = { 0, NULL };
    int status = gquic_tls_cipher_suite_derive_secret(&ret, cipher_suite, &mac, &sec, &label);
    printf("%d\n", status);

    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(&ret); i++) {
        printf("%02x ", ((u_int8_t *) GQUIC_STR_VAL(&ret))[i]);
    }
    printf("\n");

    return 0;
}
