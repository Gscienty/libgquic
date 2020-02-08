#include "frame/new_connection_id.h"
#include "frame/meta.h"
#include <string.h>

static size_t gquic_frame_new_connection_id_size(const void *const);
static int gquic_frame_new_connection_id_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_new_connection_id_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_new_connection_id_init(void *const);
static int gquic_frame_new_connection_id_dtor(void *const);

gquic_frame_new_connection_id_t *gquic_frame_new_connection_id_alloc() {
    gquic_frame_new_connection_id_t *frame = gquic_frame_alloc(sizeof(gquic_frame_new_connection_id_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x18;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_new_connection_id_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_new_connection_id_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_new_connection_id_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_new_connection_id_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_new_connection_id_size;
    return frame;
}

static size_t gquic_frame_new_connection_id_size(const void *const frame) {
    const gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->seq) + gquic_varint_size(&spec->prior) + 1 + spec->len + 16;
}

static int gquic_frame_new_connection_id_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type) != 0) {
        return -3;
    }
    const u_int64_t *vars[2] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        if (gquic_varint_serialize(vars[i], writer) != 0) {
            return -4;
        }
    }
    if (gquic_writer_str_write_byte(writer, spec->len) != 0) {
        return -5;
    }
    gquic_str_t conn_id = { spec->len, (void *) spec->conn_id };
    if (gquic_writer_str_write(writer, &conn_id) != 0) {
        return -6;
    }
    gquic_str_t token = { 16, (void *) spec->token };
    if (gquic_writer_str_write(writer, &token) != 0) {
        return -7;
    }
    return 0;
}

static int gquic_frame_new_connection_id_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return -2;
    }
    u_int64_t *vars[] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        if (gquic_varint_deserialize(vars[i], reader) != 0) {
            return -3;
        }
    }
    spec->len = gquic_reader_str_read_byte(reader);
    gquic_str_t conn_id = { spec->len, spec->conn_id };
    if (gquic_reader_str_read(&conn_id, reader) != 0) {
        return -4;
    }
    gquic_str_t token = { 16, spec->token };
    if (gquic_reader_str_read(&token, reader) != 0) {
        return -5;
    }
    return 0;
}

static int gquic_frame_new_connection_id_init(void *const frame) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->prior = 0;
    spec->seq = 0;
    spec->len = 0;
    return 0;
}

static int gquic_frame_new_connection_id_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}
