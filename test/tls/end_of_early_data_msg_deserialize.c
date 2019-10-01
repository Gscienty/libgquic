#include "tls/end_of_early_data_msg.h"
#include <malloc.h>
#include <string.h>

int main() {
    gquic_tls_end_of_early_data_msg_t m;
    gquic_tls_end_of_early_data_msg_init(&m);

    size_t result_size = gquic_tls_end_of_early_data_msg_size(&m);
    void *result = malloc(result_size);
    memset(result, 0, result_size);
    gquic_tls_end_of_early_data_msg_serialize(&m, result, result_size);

    gquic_tls_end_of_early_data_msg_t r;
    gquic_tls_end_of_early_data_msg_init(&r);
    printf("%ld\n", gquic_tls_end_of_early_data_msg_deserialize(&r, result, result_size));
    return 0;
}
