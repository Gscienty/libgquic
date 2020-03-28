#include "util/conn_id.h"
#include "exception.h"
#include <stddef.h>
#include <openssl/rand.h>

int gquic_conn_id_generate(gquic_str_t *const conn_id, const size_t len) {
    if (conn_id == NULL || len < 0 || len > 20) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_str_alloc(conn_id, len) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    RAND_bytes(GQUIC_STR_VAL(conn_id), len);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
