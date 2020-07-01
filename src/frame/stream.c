#include "frame/stream.h"
#include "frame/meta.h"
#include <string.h>
#include "exception.h"
#include "frame/stream_pool.h"

static size_t gquic_frame_stream_size(const void *const);
static int gquic_frame_stream_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_stream_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_stream_init(void *const);
static int gquic_frame_stream_dtor(void *const);

int gquic_frame_stream_alloc(gquic_frame_stream_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_stream_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x00;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_stream_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_stream_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_stream_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_stream_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_stream_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_stream_size(const void *const frame) {
    u_int64_t len = 0;
    const gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    len = GQUIC_STR_SIZE(&spec->data);

    return 1 + gquic_varint_size(&spec->id)
        + ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? gquic_varint_size(&len) : 0)
        + ((GQUIC_FRAME_META(spec).type & 0x04) == 0x04 ? gquic_varint_size(&spec->off) : 0)
        + len;
}

static int gquic_frame_stream_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    int i;
    u_int64_t len = 0;
    const gquic_frame_stream_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    len = GQUIC_STR_SIZE(&spec->data);
    const u_int64_t *vars[] = {
        &spec->id,
        ((GQUIC_FRAME_META(spec).type & 0x04) == 0x04 ? &spec->off : NULL),
        ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? &len : NULL)
    };
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &spec->data));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stream_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    u_int64_t len = 0;
    u_int8_t type;
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    type = gquic_reader_str_read_byte(reader);
    if ((type & 0x08) != 0x08) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = {
        &spec->id,
        ((GQUIC_FRAME_META(spec).type & 0x04) == 0x04 ? &spec->off : NULL),
        ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? &len: NULL)
    };
    int i = 0;
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&spec->data, len));
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&spec->data, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stream_init(void *const frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&spec->data);
    spec->id = 0;
    spec->off = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stream_dtor(void *const frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int64_t gquic_frame_stream_data_capacity(const u_int64_t size, const gquic_frame_stream_t *const frame) {
    u_int64_t header_len = 0;
    u_int64_t data_len = 0;
    u_int64_t capacity_size = 0;
    if (frame == NULL) {
        return 0;
    }
    data_len = GQUIC_STR_SIZE(&frame->data);
    header_len = 1
        + gquic_varint_size(&frame->id)
        + ((GQUIC_FRAME_META(frame).type & 0x04) != 0x00 ? gquic_varint_size(&frame->off) : 0)
        + ((GQUIC_FRAME_META(frame).type & 0x02) != 0x00 ? gquic_varint_size(&data_len) : 0);
    if (header_len > size) {
        return 0;
    }
    capacity_size = size - header_len;
    if ((GQUIC_FRAME_META(frame).type & 0x02) != 0x00 && gquic_varint_size(&capacity_size) != 1) {
        capacity_size--;
    }

    return capacity_size;
}

int gquic_frame_stream_split(gquic_frame_stream_t **new_frame, gquic_frame_stream_t *const frame, const u_int64_t size) {
    u_int64_t capacity_size = 0;
    if (new_frame == NULL || frame == NULL) {
        return 0;
    }
    if (size > GQUIC_FRAME_SIZE(frame)) {
        return 0;
    }
    capacity_size = gquic_frame_stream_data_capacity(size, frame);
    if (capacity_size == 0) {
        *new_frame = NULL;
        return 1;
    }
    gquic_stream_frame_pool_get(new_frame);
    (*new_frame)->id = frame->id;
    (*new_frame)->off = frame->off;
    if (frame->off != 0) {
        GQUIC_FRAME_META(*new_frame).type |= 0x04;
    }
    GQUIC_FRAME_META(*new_frame).type |= 0x02;
    (*new_frame)->data = frame->data;
    frame->data.size = 0;
    frame->data.val = NULL;
    if (gquic_str_alloc(&frame->data, GQUIC_STR_SIZE(&(*new_frame)->data) - capacity_size) != 0) {
        return 0;
    }
    memcpy(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&(*new_frame)->data) + capacity_size, GQUIC_STR_SIZE(&frame->data));
    (*new_frame)->data.size = capacity_size;
    frame->off += capacity_size;
    GQUIC_FRAME_META(frame).type |= 0x04;

    return 1;
}
