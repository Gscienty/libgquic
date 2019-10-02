#include "tls/server_key_exchange_msg.h"
#include <malloc.h>
#include <string.h>

int main() {
    size_t i;
    gquic_tls_server_key_exchange_msg_t m;
    gquic_tls_server_key_exchange_msg_init(&m);

    gquic_str_alloc(&m.key, 10);
    for (i = 0; i < 10; i++) ((unsigned char *) GQUIC_STR_VAL(&m.key))[i] = i;

    size_t result_size = gquic_tls_server_key_exchange_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_server_key_exchange_msg_serialize(&m, result, result_size);

    gquic_tls_server_key_exchange_msg_t r;
    gquic_tls_server_key_exchange_msg_init(&r);

    printf("%ld\n", gquic_tls_server_key_exchange_msg_deserialize(&r, result, result_size));

    for (i = 0; i < 10; i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&r.key))[i]);
    printf("\n");

    return 0;
}
