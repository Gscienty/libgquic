#include "frame/new_token.h"
#include "frame/meta.h"
#include "exception.h"
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
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&spec->len, writer));
    gquic_str_t token = { spec->len, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &token));

    return GQUIC_SUCCESS;
}

static int gquic_frame_new_token_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&spec->len, reader));
    if (spec->len > GQUIC_STR_SIZE(reader)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    if ((spec->token = malloc(spec->len)) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    gquic_str_t token = { spec->len, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&token, reader));

    return GQUIC_SUCCESS;
}

static int gquic_frame_new_token_init(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    spec->len = 0;
    spec->token = NULL;

    return GQUIC_SUCCESS;
}

static int gquic_frame_new_token_dtor(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (spec->token != NULL) {
        free(spec->token);
    }

    return GQUIC_SUCCESS;
}
