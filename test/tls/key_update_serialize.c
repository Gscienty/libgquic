#include "tls/key_update_msg.h"
#include <malloc.h>
#include <string.h>

int main() {
    size_t i;
    gquic_tls_key_update_msg_t m;
    m.req = 1;

    size_t result_size = gquic_tls_key_update_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_key_update_msg_serialize(&m, result, result_size);
    
    for (i = 0; i < result_size; i++)
        printf("%02x ", ((unsigned char *) result)[i]);
    printf("\n");

    return 0;
}
