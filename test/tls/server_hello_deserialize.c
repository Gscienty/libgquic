#include "tls/server_hello_msg.h"
#include "tls/config.h"
#include <malloc.h>
#include <stdio.h>
#include <string.h>

int main() {
    size_t i = 0;
    gquic_tls_server_hello_msg_t m;
    gquic_tls_server_hello_msg_init(&m);

    m.vers = 0x1234;
    gquic_str_alloc(&m.sess_id, 16);
    for (i = 0; i < 16; i++) ((unsigned char *) m.sess_id.val)[i] = i;

    gquic_str_alloc(&m.random, 32);
    for (i = 0; i < 32; i++) ((unsigned char *) m.random.val)[i] = i;

    m.cipher_suite = 0x2234;

    m.compression_method = 0x32;

    m.next_proto_neg = 1;
    gquic_list_insert_before(&m.next_protos, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_init(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.next_protos)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.next_protos)), 3);
    for (i = 0; i < 3; i++) ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.next_protos))))[i] = i;
    m.ocsp_stapling = 1;
    m.ticket_supported = 1;
    m.secure_regegotiation_supported = 1;
    gquic_str_alloc(&m.secure_regegotation, 5);
    for (i = 0; i < 5; i++) ((unsigned char *) GQUIC_STR_VAL(&m.secure_regegotation))[i] = i;
    gquic_str_alloc(&m.alpn_proto, 5);
    for (i = 0; i < 5; i++) ((unsigned char *) GQUIC_STR_VAL(&m.alpn_proto))[i] = i;
    gquic_list_insert_before(&m.scts, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.scts)), 5);
    for (i = 0; i < 5; i++) ((unsigned char *) GQUIC_STR_VAL(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.scts))))[i] = i;
    m.supported_version = 0x6789;
    m.ser_share.group = 0x789a;
    gquic_str_alloc(&m.ser_share.data, 3);
    for (i = 0; i < 3; i++) ((unsigned char *) GQUIC_STR_VAL(&m.ser_share.data))[i] = i;
    m.selected_identity_persent = 1;
    m.selected_identity = 0x89ab;
    gquic_str_alloc(&m.cookie, 5);
    for (i = 0; i < 5; i++) ((unsigned char *) GQUIC_STR_VAL(&m.cookie))[i] = i;
    m.selected_group = 0x9abc;

    size_t result_size = gquic_tls_server_hello_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_server_hello_msg_serialize(&m, result, result_size);


    for (i = 0; i < result_size; i++) printf("%02x ", ((unsigned char *) result)[i]);
    printf("\n");

    return 0;
}
