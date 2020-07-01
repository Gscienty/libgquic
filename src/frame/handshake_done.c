#include "frame/meta.h"
#include "frame/handshake_done.h"
#include "exception.h"
#include "log.h"
#include <stddef.h>

static size_t gquic_frame_handshake_done_size(const void *const);
static int gquic_frame_handshake_done_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_handshake_done_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_handshake_done_init(void *const);
static int gquic_frame_handshake_done_dtor(void *const);

int gquic_frame_handshake_done_alloc(gquic_frame_handshake_done_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_handshake_done_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x1e;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_handshake_done_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_handshake_done_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_handshake_done_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_handshake_done_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_handshake_done_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_handshake_done_size(const void *const frame) {
    (void) frame;

    return 1;
}
static int gquic_frame_handshake_done_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    if (GQUIC_FRAME_SIZE(frame) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, 0x1e));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_handshake_done_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    (void) frame;
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 1));

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize HANDSHAKE_DONE frame");

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_handshake_done_init(void *const frame) {
    (void) frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_handshake_done_dtor(void *const frame) {
    (void) frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
