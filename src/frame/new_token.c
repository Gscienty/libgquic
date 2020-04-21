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

int gquic_frame_new_token_alloc(gquic_frame_new_token_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_new_token_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x07;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_new_token_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_new_token_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_new_token_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_new_token_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_new_token_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&spec->len, writer));
    gquic_str_t token = { spec->len, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &token));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_new_token_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&spec->len, reader));
    if (spec->len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    if ((spec->token = malloc(spec->len)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_str_t token = { spec->len, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&token, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_new_token_init(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->len = 0;
    spec->token = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_new_token_dtor(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (spec->token != NULL) {
        free(spec->token);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
