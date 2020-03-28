#include "util/varint.h"
#include "util/big_endian.h"
#include "exception.h"
#include <stdio.h>

ssize_t gquic_varint_size(const u_int64_t *const val) {
    if (val == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    if (0x3f >= *val) {
        return 1;
    }
    else if (0x3fff >= *val) {
        return 2;
    }
    else if (0x3fffffff >= *val) {
        return 4;
    }
    else if (0x3fffffffffffffff >= *val) {
        return 8;
    }
    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_VARINT_TYPE_UNEXCEPTED);
}

int gquic_varint_serialize(const u_int64_t *const val, gquic_writer_str_t *const writer) {
    size_t length = 0;
    if (val == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    length = gquic_varint_size(val);
    if (length > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    switch (length) {
    case 1:
        gquic_big_endian_writer_1byte(writer, *val);
        break;

    case 2:
        gquic_big_endian_writer_2byte(writer, *val);
        *(u_int8_t *) (GQUIC_STR_VAL(writer) - 2) |= 0x40;
        break;

    case 4:
        gquic_big_endian_writer_4byte(writer, *val);
        *(u_int8_t *) (GQUIC_STR_VAL(writer) - 4) |= 0x80;
        break;

    case 8:
        gquic_big_endian_writer_8byte(writer, *val);
        *(u_int8_t *) (GQUIC_STR_VAL(writer) - 8) |= 0xc0;
        break;

    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_VARINT_SIZE_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_varint_deserialize(u_int64_t *const val, gquic_reader_str_t *const reader) {
    if (val == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *val = 0;
    switch (((unsigned char *) GQUIC_STR_VAL(reader))[0] & 0xc0) {
    case 0x00:
        if (1 > GQUIC_STR_SIZE(reader)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        gquic_big_endian_reader_1byte((u_int8_t *) val, reader);
        ((u_int8_t *) val)[0] &= 0x3f;
        break;

    case 0x40:
        if (2 > GQUIC_STR_SIZE(reader)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        gquic_big_endian_reader_2byte((u_int16_t *) val, reader);
        ((u_int8_t *) val)[1] &= 0x3f;
        break;

    case 0x80:
        if (4 > GQUIC_STR_SIZE(reader)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        gquic_big_endian_reader_4byte((u_int32_t *) val, reader);
        ((u_int8_t *) val)[3] &= 0x3f;
        break;

    case 0xc0:
        if (8 > GQUIC_STR_SIZE(reader)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        gquic_big_endian_reader_8byte((u_int64_t *) val, reader);
        ((u_int8_t *) val)[7] &= 0x3f;
        break;

    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_VARINT_TYPE_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

