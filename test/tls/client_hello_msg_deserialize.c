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
    ((gquic_tls_psk_identity_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_identities)))->obfuscated_ticket_age = 0x82345678;
    gquic_list_insert_before(&m.psk_binders, gquic_list_alloc(sizeof(gquic_str_t)));
    gquic_str_alloc(gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_binders)), 3);
    for (i = 0; i < 3; i++) ((unsigned char *) ((gquic_str_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.psk_binders)))->val)[i] = i;

    size_t result_size = gquic_tls_client_hello_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_client_hello_msg_serialize(&m, result, result_size);

    gquic_tls_client_hello_msg_t r;
    gquic_tls_client_hello_msg_init(&r);
    gquic_tls_client_hello_msg_deserialize(&r, result, result_size);
    printf("%04x\n", r.vers);
    for (i = 0; i < 16; i++) printf("%x", ((unsigned char *) r.sess_id.val)[i]);
    printf("\n");
    for (i = 0; i < 32; i++) printf("%02x", ((unsigned char *) r.random.val)[i]);
    printf("\n");
    void *_;
    GQUIC_LIST_FOREACH(_, &r.cipher_suites) printf("%04x", *(u_int16_t *) _);
    printf("\n");
    for (i = 0; i < 16; i++) printf("%x", ((unsigned char *) r.compression_methods.val)[i]);
    printf("\n");
    printf("%d\n", r.next_proto_neg);
    for (i = 0; i < 4; i++) printf("%x", ((unsigned char *) r.ser_name.val)[i]);
    printf("\n");
    printf("%d\n", r.ocsp_stapling);
    GQUIC_LIST_FOREACH(_, &r.supported_curves) printf("%04x", *(u_int16_t *) _);
    printf("\n");
    for (i = 0; i < 5; i++) printf("%x", ((unsigned char *) r.supported_points.val)[i]);
    printf("\n");
    printf("%d\n", r.ticket_supported);
    for (i = 0; i < 6; i++) printf("%x", ((unsigned char *) r.sess_ticket.val)[i]);
    printf("\n");
    GQUIC_LIST_FOREACH(_, &r.supported_sign_algos) printf("%04x", *(u_int16_t *) _);
    printf("\n");
    GQUIC_LIST_FOREACH(_, &r.supported_sign_algos_cert) printf("%04x", *(u_int16_t *) _);
    printf("\n");
    printf("%d\n", r.secure_regegotiation_supported);
    for (i = 0; i < 6; i++) printf("%x", ((unsigned char *) r.secure_regegotation.val)[i]);
    printf("\n");
    GQUIC_LIST_FOREACH(_, &r.alpn_protos)
        for (i = 0; i < 3; i++) 
            printf("%x", ((unsigned char *) ((gquic_str_t *) _)->val)[i]);
    printf("\n");
    printf("%d\n", r.scts);
    GQUIC_LIST_FOREACH(_, &r.supported_versions) printf("%04x", *(u_int16_t *) _);
    printf("\n");
    for (i = 0; i < 6; i++) printf("%x", ((unsigned char *) r.cookie.val)[i]);
    printf("\n");
    GQUIC_LIST_FOREACH(_, &r.key_shares) {
        printf("%x ", ((gquic_tls_key_share_t *) _)->group);
        for (i = 0; i < 5; i++) 
            printf("%x", ((unsigned char *) ((gquic_tls_key_share_t *) _)->data.val)[i]);
    }
    printf("\n");
    printf("%d\n", r.early_data);
    for (i = 0; i < 6; i++) printf("%x", ((unsigned char *) r.psk_modes.val)[i]);
    printf("\n");
    GQUIC_LIST_FOREACH(_, &r.psk_identities) {
        printf("%x ", ((gquic_tls_psk_identity_t *) _)->obfuscated_ticket_age);
        for (i = 0; i < 3; i++) 
            printf("%x", ((unsigned char *) ((gquic_tls_psk_identity_t *) _)->label.val)[i]);
    }
    printf("\n");
    GQUIC_LIST_FOREACH(_, &r.psk_binders) {
        for (i = 0; i < 3; i++) 
            printf("%x", ((unsigned char *) ((gquic_str_t *) _)->val)[i]);
    }
    printf("\n");

    return 0;
}
