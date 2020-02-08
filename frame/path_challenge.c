#include "frame/path_challenge.h"
#include "frame/meta.h"
#include <string.h>

static size_t gquic_frame_path_challenge_size(const void *const);
static int gquic_frame_path_challenge_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_path_challenge_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_path_challenge_init(void *const);
static int gquic_frame_path_challenge_dtor(void *const);

gquic_frame_path_challenge_t *gquic_frame_path_challenge_alloc() {
    gquic_frame_path_challenge_t *frame = gquic_frame_alloc(sizeof(gquic_frame_path_challenge_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x1a;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_path_challenge_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_path_challenge_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_path_challenge_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_path_challenge_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_path_challenge_size;
    return frame;
}

static size_t gquic_frame_path_challenge_size(const void *const frame) {
    const gquic_frame_path_challenge_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + 8;
}

static int gquic_frame_path_challenge_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_path_challenge_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type) != 0) {
        return -3;
    }
    gquic_str_t data = { 8, (void *) spec->data };
    if (gquic_writer_str_write(writer, &data) != 0) {
        return -4;
    }
    return 0;
}

static int gquic_frame_path_challenge_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_path_challenge_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(reader)) {
        return -2;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return -3;
    }
    gquic_str_t data = { 8, spec->data };
    if (gquic_reader_str_read(&data, reader) != 0) {
        return -4;
    }
    return 0;
}

static int gquic_frame_path_challenge_init(void *const frame) {
    (void) frame;
    return 0;
}

static int gquic_frame_path_challenge_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

