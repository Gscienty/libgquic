#include "packet/packet_pool.h"
#include "exception.h"
#include <stddef.h>
#include <malloc.h>

int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage) {
    if (buffer_storage == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((*buffer_storage = malloc(sizeof(gquic_packet_buffer_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    if (gquic_str_alloc(&(*buffer_storage)->slice, 1452) != 0) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    gquic_str_clear(&(*buffer_storage)->slice);
    (*buffer_storage)->writer = (*buffer_storage)->slice;
    (*buffer_storage)->ref = 1;
    return GQUIC_SUCCESS;
}

int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer) {
    if (buffer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    buffer->ref--;
    if (buffer->ref == 0) {
        gquic_str_reset(&buffer->slice);
        free(buffer);
    }
    return GQUIC_SUCCESS;
}

int gquic_packet_buffer_try_put(gquic_packet_buffer_t *const buffer) {
    if (buffer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (buffer->ref == 0) {
        gquic_str_reset(&buffer->slice);
        free(buffer);
    }
    return GQUIC_SUCCESS;
}
