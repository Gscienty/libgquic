#include "frame/meta.h"
#include "frame/ping.h"

static size_t gquic_frame_ping_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_ping_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_ping_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_ping_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_ping_release(gquic_abstract_frame_ptr_t);

gquic_frame_ping_t *gquic_frame_ping_alloc() {
    static gquic_frame_ping_t *frame = NULL;
    if (frame != NULL) {
        return frame;
    }
    frame = gquic_frame_alloc(0);
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x01;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_ping_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_ping_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_ping_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_ping_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_ping_size;
    return frame;
}

static size_t gquic_frame_ping_size(gquic_abstract_frame_ptr_t frame) {
    (void) frame;
    return 1;
}

static ssize_t gquic_frame_ping_serialize(const gquic_abstract_frame_ptr_t frame, void * offbuf, const size_t remain_size) {
    size_t used_size = GQUIC_FRAME_META(frame).size_func(frame);
    if (used_size > remain_size) {
        return -1;
    }
    ((gquic_frame_type_t *) offbuf)[0] = 0x01;
    return used_size;
}

static ssize_t gquic_frame_ping_deserialize(gquic_abstract_frame_ptr_t frame, const void *offbuf, const size_t remain_size) {
    (void) frame;
    (void) offbuf;
    (void) remain_size;
    return 1;
}

static int gquic_frame_ping_init(gquic_abstract_frame_ptr_t frame) {
    (void) frame;
    return 0;
}

static int gquic_frame_ping_release(gquic_abstract_frame_ptr_t frame) {
    (void) frame;
    return 1;
}

