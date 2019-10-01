#include "tls/new_sess_ticket_13_msg.h"
#include <malloc.h>
#include <string.h>

int main() {
    size_t i;
    gquic_tls_new_sess_ticket_13_msg_t m;
    gquic_tls_new_sess_ticket_13_msg_init(&m);

    m.age_add = 0x12345678;
    m.lifetime = 0x22345678;
    m.max_early_data = 0x32345678;
    gquic_str_alloc(&m.label, 5);
    gquic_str_alloc(&m.nonce, 10);
    for (i = 0; i < 5; i++) ((unsigned char *) GQUIC_STR_VAL(&m.label))[i] = i;
    for (i = 0; i < 10; i++) ((unsigned char *) GQUIC_STR_VAL(&m.nonce))[i] = i;

    size_t result_size = gquic_tls_new_sess_ticket_13_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_new_sess_ticket_13_msg_serialize(&m, result, result_size);

    gquic_tls_new_sess_ticket_13_msg_t r;
    gquic_tls_new_sess_ticket_13_msg_init(&r);

    gquic_tls_new_sess_ticket_13_msg_deserialize(&r, result, result_size);

    printf("%x\n", r.age_add);
    printf("%x\n", r.lifetime);
    printf("%x\n", r.max_early_data);
    for (i = 0; i < 5; i++) printf("%x ", ((unsigned char *) GQUIC_STR_VAL(&m.label))[i]);
    printf("\n");
    for (i = 0; i < 10; i++) printf("%x ", ((unsigned char *) GQUIC_STR_VAL(&m.nonce))[i]);
    printf("\n");

    return 0;
}
