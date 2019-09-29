#include "tls/client_hello_msg.h"
#include "tls/config.h"
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

    m.next_proto_neg = 1;
    gquic_str_alloc(&m.ser_name, 4);
    for (i = 0; i < 4; i++) ((unsigned char *) m.ser_name.val)[i] = i;
    m.ocsp_stapling = 1;
    gquic_list_insert_after(&m.supported_curves, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.supported_curves)) = 0x3234;
    gquic_str_alloc(&m.supported_points, 5);
    for (i = 0; i < 5; i++) ((unsigned char *) m.supported_points.val)[i] = i;
    m.ticket_supported = 1;
    gquic_str_alloc(&m.sess_ticket, 6);
    for (i = 0; i < 6; i++) ((unsigned char *) m.sess_ticket.val)[i] = i;
    gquic_list_insert_before(&m.supported_sign_algos, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.supported_sign_algos)) = 0x4234;
    gquic_list_insert_before(&m.supported_sign_algos_cert, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.supported_sign_algos_cert)) = 0x5234;
    m.secure_regegotiation_supported = 1;
    gquic_str_alloc(&m.secure_regegotation, 6);
    for (i = 0; i < 6; i++) ((unsigned char *) m.secure_regegotation.val)[i] = i;
    gquic_list_insert_before(&m.alpn_protos, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.alpn_protos)), 3);
    for (i = 0; i < 3; i++) ((unsigned char *) ((gquic_str_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.alpn_protos)))->val)[i] = i;
    m.scts = 1;
    gquic_list_insert_before(&m.supported_versions, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.supported_versions)) = 0x6234;
    gquic_str_alloc(&m.cookie, 6);
    for (i = 0; i < 6; i++) ((unsigned char *) m.cookie.val)[i] = i;
    gquic_list_insert_before(&m.key_shares, gquic_list_alloc(sizeof(gquic_tls_key_share_t)));
    ((gquic_tls_key_share_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.key_shares)))->group = 0x7234;
    gquic_str_alloc(&((gquic_tls_key_share_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.key_shares)))->data, 5);
    for (i = 0; i < 5; i++) ((unsigned char *) ((gquic_tls_key_share_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.key_shares)))->data.val)[i] = i;
    m.early_data = 1;
    gquic_str_alloc(&m.psk_modes, 6);
    for (i = 0; i < 6; i++) ((unsigned char *) m.psk_modes.val)[i] = i;
    gquic_list_insert_before(&m.psk_identities, gquic_list_alloc(sizeof(gquic_tls_psk_identity_t)));
    gquic_str_alloc(&((gquic_tls_psk_identity_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_identities)))->label, 3);
    for (i = 0; i < 3; i++) ((unsigned char *) ((gquic_tls_psk_identity_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_identities)))->label.val)[i] = i;
    ((gquic_tls_psk_identity_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_identities)))->obfuscated_ticket_age = 0x01;
    gquic_list_insert_before(&m.psk_binders, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_binders)), 3);
    for (i = 0; i < 3; i++) ((unsigned char *) ((gquic_str_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_binders)))->val)[i] = i;

    size_t result_size = gquic_tls_client_hello_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_client_hello_msg_serialize(&m, result, result_size);

    for (i = 0; i < result_size; i++) printf("%02x ", ((unsigned char *) result)[i]);
    printf("\n");

    return 0;
}
