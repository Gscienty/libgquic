#include "packet/packet_pool.h"
#include "util/malloc.h"
#include "exception.h"
#include <stddef.h>

static int gquic_packet_buffer_release(void *const);

int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage) {
    gquic_count_pointer_t *buffer_cptr = NULL;
    gquic_packet_buffer_t *buffer = NULL;
    if (buffer_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_CPTR_MALLOC_STRUCT(&buffer_cptr, gquic_packet_buffer_t, gquic_packet_buffer_release));
    buffer = GQUIC_CPTR_REF(buffer_cptr, gquic_packet_buffer_t);

    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&buffer->slice, 1452));
    gquic_str_clear(&buffer->slice);
    buffer->writer = buffer->slice;

    *buffer_storage = buffer;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer) {
    if (buffer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PROCESS_DONE(gquic_count_pointer_try_release(&GQUIC_CPTR_META(buffer)));
}

int gquic_packet_buffer_assign(gquic_packet_buffer_t **const buffer_storage, gquic_packet_buffer_t *const buffer) {
    gquic_count_pointer_t *target = NULL;
    if (buffer_storage == NULL || buffer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_count_pointer_assign(&target, &GQUIC_CPTR_META(buffer));
    *buffer_storage = GQUIC_CPTR_REF(target, gquic_packet_buffer_t);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_buffer_release(void *const buffer_) {
    if (buffer_ == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&((gquic_packet_buffer_t *) buffer_)->slice);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
