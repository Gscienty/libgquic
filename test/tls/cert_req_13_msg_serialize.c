#include "tls/cert_req_13_msg.h"
#include "util/str.h"
#include <malloc.h>
#include <string.h>

int main() {
    size_t i;
    gquic_tls_cert_req_13_msg_t m;
    gquic_tls_cert_req_13_msg_init(&m);

    m.ocsp_stapling = 1;
    m.scts = 1;
    gquic_list_insert_before(&m.supported_sign_algo, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.supported_sign_algo)) = 0x1234;
    gquic_list_insert_before(&m.supported_sign_algo_cert, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.supported_sign_algo_cert)) = 0x2234;
    gquic_list_insert_before(&m.cert_auths, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_init(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert_auths)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert_auths)), 10);
    for (i = 0; i < 10; i++)
        ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.cert_auths))))[i] = i;

    size_t result_size = gquic_tls_cert_req_13_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_cert_req_13_msg_serialize(&m, result, result_size);

    for (i = 0; i < result_size; i++) printf("%02x ", ((unsigned char *) result)[i]);
    printf("\n");


    return 0;
}
