#include "frame/new_token.h"
#include "frame/meta.h"
#include <malloc.h>
#include <string.h>

static size_t gquic_frame_new_token_size(const void *const);
static int gquic_frame_new_token_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_new_token_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_new_token_init(void *const);
static int gquic_frame_new_token_dtor(void *const);

gquic_frame_new_token_t *gquic_frame_new_token_alloc() {
    gquic_frame_new_token_t *frame = gquic_frame_alloc(sizeof(gquic_frame_new_token_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x07;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_new_token_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_new_token_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_new_token_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_new_token_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_new_token_size;
    return frame;
}

static size_t gquic_frame_new_token_size(const void *const frame) {
    const gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->len) + spec->len;
}

static int gquic_frame_new_token_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_new_token_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type) != 0) {
        return -3;
    }
    if (gquic_varint_serialize(&spec->len, writer) != 0) {
        return -4;
    }
    gquic_str_t token = { spec->len, spec->token };
    if (gquic_writer_str_write(writer, &token) != 0) {
        return -5;
    }
    return 0;
}

static int gquic_frame_new_token_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return -2;
    }
    if (gquic_varint_deserialize(&spec->len, reader) != 0) {
        return -3;
    }
    if (spec->len > GQUIC_STR_SIZE(reader)) {
        return -4;
    }
    spec->token = malloc(spec->len);
    if (spec->token == NULL) {
        return -5;
    }
    gquic_str_t token = { spec->len, spec->token };
    if (gquic_reader_str_read(&token, reader) != 0) {
        return -6;
    }
    return 0;
}

static int gquic_frame_new_token_init(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->len = 0;
    spec->token = NULL;
    return 0;
}

static int gquic_frame_new_token_dtor(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (spec->token != NULL) {
        free(spec->token);
    }
    return 0;
}
