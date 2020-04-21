#include "frame/padding.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static size_t gquic_frame_padding_size(const void *const);
static int gquic_frame_padding_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_padding_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_padding_init(void *const);
static int gquic_frame_padding_dtor(void *const);

int gquic_frame_padding_alloc(gquic_frame_padding_t **const frame_storage) {
    static gquic_frame_padding_t *frame = NULL;
    if (frame != NULL) {
        *frame_storage = frame;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(&frame, gquic_frame_padding_t));

    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_padding_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_padding_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_padding_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_padding_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_padding_size;

    *frame_storage = frame;
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_padding_size(const void *const frame) {
    (void) frame;

    return 1;
}

static int gquic_frame_padding_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    size_t used_size = GQUIC_FRAME_SIZE(frame);
    if (used_size > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, 0x00));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_padding_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    (void) frame;
    gquic_reader_str_readed_size(reader, 1);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_padding_init(void *const frame) {
    (void) frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_padding_dtor(void *const frame) {
    (void) frame;
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

