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
    return ((void *) meta) + sizeof(gquic_frame_meta_t);
}

int gquic_frame_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_META(frame).release_func(frame) <= 0) {
        free(&GQUIC_FRAME_META(frame));
    }
    return 0;
}

int gquic_frame_init(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL || GQUIC_FRAME_META(frame).init_func == NULL) {
        return -1;
    }
    return GQUIC_FRAME_META(frame).init_func(frame);
}

ssize_t gquic_frame_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    if (frame == NULL || GQUIC_FRAME_META(frame).serialize_func == NULL) {
        return -1;
    }
    return GQUIC_FRAME_META(frame).serialize_func(frame, buf, size);
}

ssize_t gquic_frame_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    if (frame == NULL || GQUIC_FRAME_META(frame).deserialize_func == NULL) {
        return -1;
    }
    return GQUIC_FRAME_META(frame).deserialize_func(frame, buf, size);
}

size_t gquic_frame_size(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL || GQUIC_FRAME_META(frame).size_func == NULL) {
        return -1;
    }
    return GQUIC_FRAME_META(frame).size_func(frame);
}

