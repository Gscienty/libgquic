#include "tls/key_schedule.h"

int main() {
    gquic_str_t secret = { 16, "0123456789abcdef" };
    gquic_str_t label = { 5, "hello" };
    gquic_str_t ret = { 0, NULL };
    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    gquic_tls_cipher_suite_extract(&ret, cipher_suite, &secret, &label);

    printf("%ld\n", GQUIC_STR_SIZE(&ret));
    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(&ret); i++) {
        printf("%02x ", ((u_int8_t *) GQUIC_STR_VAL(&ret))[i]);
    }
    printf("\n");

    return 0;
}
