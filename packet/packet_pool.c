#include "packet/packet_pool.h"
#include <stddef.h>
#include <malloc.h>

int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage) {
    if (buffer_storage == NULL) {
        return -1;
    }
    if ((*buffer_storage = malloc(sizeof(gquic_packet_buffer_t))) == NULL) {
        return -2;
    }
    if (gquic_str_alloc(&(*buffer_storage)->slice, 1452) != 0) {
        return -3;
    }
    (*buffer_storage)->writer = (*buffer_storage)->slice;
    (*buffer_storage)->ref = 1;
    return 0;
}

int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer) {
    if (buffer == NULL) {
        return -1;
    }
    gquic_str_reset(&buffer->slice);
    free(buffer);
    return 0;
}
