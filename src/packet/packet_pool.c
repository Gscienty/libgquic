#include "packet/packet_pool.h"
#include "util/malloc.h"
#include "exception.h"
#include <stddef.h>

static int gquic_packet_buffer_release(void *const);

int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (buffer_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_ALLOC(exception, buffer_storage, gquic_cptr_packet_buffer_t, buffer, cptr, gquic_packet_buffer_release);

    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&((*buffer_storage)->slice), 1452));
    gquic_str_clear(&(*buffer_storage)->slice);
    (*buffer_storage)->writer = (*buffer_storage)->slice;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer) {
    int exception = GQUIC_SUCCESS;
    if (buffer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_TRY_RELEASE(exception, buffer, gquic_cptr_packet_buffer_t, buffer, cptr);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_packet_buffer_assign(gquic_packet_buffer_t **const buffer_storage, gquic_packet_buffer_t *const buffer) {
    int exception = GQUIC_SUCCESS;
    if (buffer_storage == NULL || buffer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_ASSIGN(exception, buffer_storage, buffer, gquic_cptr_packet_buffer_t, buffer, cptr);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_buffer_release(void *const buffer_) {
    if (buffer_ == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&((gquic_packet_buffer_t *) buffer_)->slice);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
