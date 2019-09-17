#include "frame/path_challenge.h"
#include "frame/meta.h"
#include <string.h>

static size_t gquic_frame_path_challenge_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_path_challenge_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_path_challenge_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_path_challenge_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_path_challenge_release(gquic_abstract_frame_ptr_t);

gquic_frame_path_challenge_t *gquic_frame_path_challenge_alloc() {
    gquic_frame_path_challenge_t *frame = gquic_frame_alloc(sizeof(gquic_frame_path_challenge_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x1a;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_path_challenge_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_path_challenge_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_path_challenge_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_path_challenge_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_path_challenge_size;
    return frame;
}

static size_t gquic_frame_path_challenge_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_path_challenge_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + 8;
}

static ssize_t gquic_frame_path_challenge_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    gquic_frame_path_challenge_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_frame_size(spec) > size) {
        return -3;
    }
    ((gquic_frame_type_t *) buf)[off++] = GQUIC_FRAME_META(spec).type;
    memcpy(buf + off, spec->data, 8);
    return off + 8;
}

static ssize_t gquic_frame_path_challenge_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    gquic_frame_path_challenge_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_frame_size(spec) > size) {
        return -3;
    }
    if (GQUIC_FRAME_META(spec).type != ((gquic_frame_type_t *) buf)[off++]) {
        return -4;
    }
    memcpy(spec->data, buf + off, 8);
    return off + 8;
}

static int gquic_frame_path_challenge_init(gquic_abstract_frame_ptr_t frame) {
    (void) frame;
    return 0;
}

static int gquic_frame_path_challenge_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

