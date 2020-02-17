#include "util/conn_id.h"
#include <stddef.h>
#include <openssl/rand.h>

int gquic_conn_id_generate(gquic_str_t *const conn_id, const size_t len) {
    if (conn_id == NULL) {
        return -1;
    }
    if (gquic_str_alloc(conn_id, len) != 0) {
        return -2;
    }
    RAND_bytes(GQUIC_STR_VAL(conn_id), len);
    return 0;
}
