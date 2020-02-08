#include "handshake/header_protector.h"
#include <stdio.h>

int main() {
    int ret;
    const gquic_tls_cipher_suite_t *suite;
    gquic_str_t traffic_sec = { 32, "0123456789abcdef0123456789abcdef" };
    gquic_tls_get_cipher_suite(&suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    gquic_header_protector_t protector;
    gquic_header_protector_init(&protector);
    gquic_header_protector_assign(&protector, suite, &traffic_sec, 0);

    gquic_str_t sample = { 16, "0123456789abcdef" };
    u_int8_t first_byte = 0x05;
    char header_cnt[] = "0123456789abcdef0123456789abcdef";
    gquic_str_t header = { 32, header_cnt };
    printf("%02x\n", first_byte);
    gquic_str_test_echo(&header);

    ret = GQUIC_HEADER_PROTECTOR_ENCRYPT(&header, &first_byte, &protector, &sample);
    printf("%02x\n", first_byte);
    gquic_str_test_echo(&header);

    ret = GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &first_byte, &protector, &sample);
    printf("%02x\n", first_byte);
    gquic_str_test_echo(&header);

    return 0;
}
