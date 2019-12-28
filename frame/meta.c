#include "frame/meta.h"
#include <malloc.h>

void *gquic_frame_alloc(size_t size) {
    gquic_frame_meta_t *meta = (gquic_frame_meta_t *) malloc(sizeof(gquic_frame_meta_t) + size);
    if (meta == NULL) {
        return NULL;
    }
    meta->init_func = NULL;
    meta->deserialize_func = NULL;
    meta->dtor_func = NULL;
    meta->serialize_func = NULL;
    meta->size_func = NULL;
    meta->type = 0x00;
    meta->payload_size = size;
    return ((void *) meta) + sizeof(gquic_frame_meta_t);
}

int gquic_frame_release(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    GQUIC_FRAME_DTOR(frame);
    free(&GQUIC_FRAME_META(frame));

    return 0;
}
