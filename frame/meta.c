#include "frame/meta.h"
#include <malloc.h>

gquic_abstract_frame_ptr_t gquic_frame_alloc(size_t size) {
    gquic_frame_meta_t *meta = (gquic_frame_meta_t *) malloc(sizeof(gquic_frame_meta_t) + size);
    if (meta == NULL) {
        return NULL;
    }
    meta->init_func = NULL;
    meta->deserialize_func = NULL;
    meta->release_func = NULL;
    meta->serialize_func = NULL;
    meta->size_func = NULL;
    meta->type = 0x00;
    meta->payload_size = size;
    return &GQUIC_FRAME_SPEC(void, meta);
}

int gquic_frame_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    free(&GQUIC_FRAME_META(frame));
    return 0;
}
