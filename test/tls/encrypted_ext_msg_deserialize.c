#include "tls/encrypt_ext_msg.h"
#include "tls/config.h"
#include <string.h>

int main() {
    size_t i;
    gquic_tls_encrypt_ext_msg_t m;
    gquic_tls_encrypt_ext_msg_init(&m);
    
    gquic_str_alloc(&m.alpn_proto, 5);
    for (i = 0; i < 5; i++)
        ((unsigned char *) GQUIC_STR_VAL(&m.alpn_proto))[i] = i;

    gquic_list_insert_before(&m.addition_exts, gquic_list_alloc(sizeof(gquic_tls_extension_t)));
    ((gquic_tls_extension_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.addition_exts)))->type = 0x5678;
    gquic_str_init(&((gquic_tls_extension_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.addition_exts)))->data);
    gquic_str_alloc(&((gquic_tls_extension_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.addition_exts)))->data, 5);
    for (i = 0; i < 5; i++)
        ((unsigned char *) GQUIC_STR_VAL(&((gquic_tls_extension_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&m.addition_exts)))->data))[i] = i;
    size_t result_size = gquic_tls_encrypt_ext_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_encrypt_ext_msg_serialize(&m, result, result_size);

    gquic_tls_encrypt_ext_msg_t r;
    gquic_tls_encrypt_ext_msg_init(&r);

    gquic_tls_encrypt_ext_msg_deserialize(&r, result, result_size);

    for (i = 0; i < 5; i++)
        printf("%x", ((unsigned char *) GQUIC_STR_VAL(&r.alpn_proto))[i]);
    printf("\n");
    gquic_tls_extension_t *field;
    GQUIC_LIST_FOREACH(field, &r.addition_exts) {
        printf("%x\n", field->type);
        for (i = 0; i < 5; i++)
            printf("%x", ((unsigned char *) field->data.val)[i]);
        printf("\n");
    }


    return 0;
}
