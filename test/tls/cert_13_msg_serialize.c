#include "tls/cert_13_msg.h"
#include <malloc.h>
#include <string.h>

int main() {
    size_t i;
    gquic_tls_cert_13_msg_t m;
    gquic_tls_cert_13_msg_init(&m);

    gquic_str_alloc(&m.cert.ocsp_staple, 10);
    for (i = 0; i < 10; i++) ((unsigned char *) GQUIC_STR_VAL(&m.cert.ocsp_staple))[i] = i;

    gquic_list_insert_before(&m.cert.scts, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_init(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert.scts)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert.scts)), 10);
    for (i = 0; i < 10; i++)
        ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert.scts))))[i] = i;


    gquic_list_insert_before(&m.cert.certs, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_init(gquic_list_prev(GQUIC_LIST_PAYLOAD(&m.cert.certs)));
    gquic_str_alloc(gquic_list_prev(GQUIC_LIST_PAYLOAD(&m.cert.certs)), 10);
    for (i = 0; i < 10; i++)
        ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert.certs))))[i] = i;

    gquic_list_insert_before(&m.cert.certs, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_init(gquic_list_prev(GQUIC_LIST_PAYLOAD(&m.cert.certs)));
    gquic_str_alloc(gquic_list_prev(GQUIC_LIST_PAYLOAD(&m.cert.certs)), 5);
    for (i = 0; i < 5; i++)
        ((unsigned char *) GQUIC_STR_VAL(gquic_list_prev(GQUIC_LIST_PAYLOAD(&m.cert.certs))))[i] = i;

    size_t result_size = gquic_tls_cert_13_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_cert_13_msg_serialize(&m, result, result_size);

    for (i = 0; i < result_size; i++) printf("%02x ", ((unsigned char *) result)[i]);
    printf("\n");

    return 0;
}
