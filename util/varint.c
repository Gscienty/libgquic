#include "util/varint.h"
#include "util/big_endian.h"

ssize_t gquic_varint_size(const u_int64_t *const val) {
    if (val == NULL) {
        return -1;
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
    else {
        return -2;
    }
    return 0;
}

ssize_t gquic_varint_serialize(const u_int64_t *const val, gquic_writer_str_t *const writer) {
    size_t length = 0;
    if (val == NULL || writer == NULL) {
        return -1;
    }
    length = gquic_varint_size(val);
    if (length > GQUIC_STR_SIZE(writer)) {
        return -2;
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
        return -3;
    }

    return length;
}

ssize_t gquic_varint_deserialize(u_int64_t *const val, gquic_reader_str_t *const reader) {
    if (val == NULL || reader == NULL) {
        return -1;
    }
    *val = 0;
    switch (((unsigned char *) GQUIC_STR_VAL(reader))[0] & 0xc0) {
    case 0x00:
        if (1 > GQUIC_STR_SIZE(reader)) {
            return -3;
        }
        gquic_big_endian_reader_1byte((u_int8_t *) val, reader);
        ((u_int8_t *) val)[0] &= 0x3f;
        return 1;

    case 0x40:
        if (2 > GQUIC_STR_SIZE(reader)) {
            return -3;
        }
        gquic_big_endian_reader_2byte((u_int16_t *) val, reader);
        ((unsigned char *) val)[1] &= 0x3f;
        return 2;

    case 0x80:
        if (4 > GQUIC_STR_SIZE(reader)) {
            return -3;
        }
        gquic_big_endian_reader_4byte((u_int32_t *) val, reader);
        ((unsigned char *) val)[3] &= 0x3f;
        return 4;

    case 0xc0:
        if (8 > GQUIC_STR_SIZE(reader)) {
            return -3;
        }
        gquic_big_endian_reader_8byte((u_int64_t *) val, reader);
        ((unsigned char *) val)[7] &= 0x3f;
        return 8;

    default:
        return -4;
    }
}

