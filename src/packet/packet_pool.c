#include "packet/packet_pool.h"
#include "util/malloc.h"
#include "exception.h"
#include <stddef.h>

static int gquic_packet_buffer_release(void *const);

int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage) {
    gquic_packet_buffer_t *buffer = NULL;
    int exception = GQUIC_SUCCESS;
    if (buffer_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_ALLOC_ORIG(exception, buffer_storage, gquic_packet_buffer_t, sizeof(gquic_packet_buffer_t), cptr, gquic_packet_buffer_release);
    buffer = *buffer_storage;

    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&buffer->slice, 1452));
    gquic_str_clear(&buffer->slice);
    buffer->writer = buffer->slice;

    *buffer_storage = buffer;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer) {
    int exception = GQUIC_SUCCESS;
    if (buffer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    /*GQUIC_CPTR_TRY_RELEASE_ORIG(exception, buffer, cptr);*/

    GQUIC_PROCESS_DONE(exception);
}

int gquic_packet_buffer_assign(gquic_packet_buffer_t **const buffer_storage, gquic_packet_buffer_t *const buffer) {
    int exception = GQUIC_SUCCESS;
    if (buffer_storage == NULL || buffer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_ASSIGN_ORIG(exception, buffer_storage, buffer, cptr);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_buffer_release(void *const buffer_) {
    if (buffer_ == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&((gquic_packet_buffer_t *) buffer_)->slice);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
