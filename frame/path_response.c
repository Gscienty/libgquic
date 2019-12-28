#include "frame/path_response.h"
#include "frame/meta.h"
#include <string.h>

static size_t gquic_frame_path_response_size(const void *const);
static ssize_t gquic_frame_path_response_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_path_response_deserialize(void *const, const void *, const size_t);
static int gquic_frame_path_response_init(void *const);
static int gquic_frame_path_response_dtor(void *const);

gquic_frame_path_response_t *gquic_frame_path_response_alloc() {
    gquic_frame_path_response_t *frame = gquic_frame_alloc(sizeof(gquic_frame_path_response_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x1b;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_path_response_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_path_response_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_path_response_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_path_response_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_path_response_size;
    return frame;
}

static size_t gquic_frame_path_response_size(const void *const frame) {
    const gquic_frame_path_response_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + 8;
}

static ssize_t gquic_frame_path_response_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    const gquic_frame_path_response_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_SIZE(spec) > size) {
        return -3;
    }
    ((u_int8_t *) buf)[off++] = GQUIC_FRAME_META(spec).type;
    memcpy(buf + off, spec->data, 8);
    return off + 8;
}

static ssize_t gquic_frame_path_response_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    gquic_frame_path_response_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_SIZE(spec) > size) {
        return -3;
    }
    if (GQUIC_FRAME_META(spec).type != ((u_int8_t *) buf)[off++]) {
        return -4;
    }
    memcpy(spec->data, buf + off, 8);
    return off + 8;
}

static int gquic_frame_path_response_init(void *const frame) {
    (void) frame;
    return 0;
}

static int gquic_frame_path_response_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

