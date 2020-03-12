#include "util/conn_id.h"
#include "exception.h"
#include <stddef.h>
#include <openssl/rand.h>

int gquic_conn_id_generate(gquic_str_t *const conn_id, const size_t len) {
    if (conn_id == NULL || len < 0 || len > 20) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_str_alloc(conn_id, len) != 0) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    RAND_bytes(GQUIC_STR_VAL(conn_id), len);
    return GQUIC_SUCCESS;
}
