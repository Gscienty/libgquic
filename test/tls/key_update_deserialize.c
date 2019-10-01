#include "tls/key_update_msg.h"
#include <malloc.h>
#include <string.h>

int main() {
    gquic_tls_key_update_msg_t m;
    gquic_tls_key_update_msg_init(&m);
    m.req = 1;

    size_t result_size = gquic_tls_key_update_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_key_update_msg_serialize(&m, result, result_size);
    
    gquic_tls_key_update_msg_t r;
    gquic_tls_key_update_msg_init(&r);

    gquic_tls_key_update_msg_deserialize(&r, result, result_size);
    printf("%d\n", r.req);

    return 0;
}
