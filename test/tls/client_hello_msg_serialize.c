#include "tls/client_hello_msg.h"
#include <malloc.h>
#include <stdio.h>
#include <string.h>

int main() {

    size_t i = 0;
    gquic_tls_client_hello_msg_t m;

    gquic_tls_client_hello_msg_init(&m);

    m.vers = 0x1234;
    gquic_str_alloc(&m.sess_id, 16);
    for (i = 0; i < 16; i++) ((unsigned char *) m.sess_id.val)[i] = i;

    gquic_str_alloc(&m.random, 32);
    for (i = 0; i < 32; i++) ((unsigned char *) m.random.val)[i] = i;

    gquic_list_insert_after(&m.cipher_suites, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cipher_suites)) = 0x2234;

    gquic_str_alloc(&m.compression_methods, 16);
    for (i = 0; i < 16; i++) ((unsigned char *) m.compression_methods.val)[i] = i;

    size_t result_size = gquic_tls_client_hello_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_client_hello_msg_serialize(&m, result, result_size);

    for (i = 0; i < result_size; i++) printf("%02x", ((unsigned char *) result)[i]);
    printf("\n");

    return 0;
}
