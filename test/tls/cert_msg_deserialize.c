#include "tls/cert_msg.h"
#include "util/str.h"
#include <malloc.h>
#include <string.h>

int main() {
    size_t i;
    gquic_tls_cert_msg_t m;
    gquic_tls_cert_msg_init(&m);

    gquic_list_insert_before(&m.certs, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_init(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.certs)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.certs)), 10);
    for (i = 0; i < 10; i++)
        ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.certs))))[i] = i;

    size_t result_size = gquic_tls_cert_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_cert_msg_serialize(&m, result, result_size);

    gquic_tls_cert_msg_t r;
    gquic_tls_cert_msg_init(&r);

    printf("%ld\n", gquic_tls_cert_msg_deserialize(&r, result, result_size));

    for (i = 0; i < 10; i++)
        printf("%02x ",
               ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&r.certs))))[i]);
    printf("\n");

    return 0;
}
