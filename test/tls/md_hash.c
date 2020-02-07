#include "tls/cipher_suite.h"

int main() {
    gquic_tls_mac_t mac;
    gquic_tls_mac_init(&mac);
    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    cipher_suite->mac(&mac, 0, NULL);

    gquic_str_t hello = { 5, "hello" };

    gquic_tls_mac_md_update(&mac, &hello);
    gquic_str_t result1 = { 0, NULL };
    gquic_tls_mac_md_sum(&result1, &mac);
    gquic_str_test_echo(&result1);

    gquic_tls_mac_md_update(&mac, &hello);
    gquic_str_t result2 = { 0, NULL };
    gquic_tls_mac_md_sum(&result2, &mac);
    gquic_str_test_echo(&result2);

    return 0;
}
