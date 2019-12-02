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

ssize_t gquic_varint_serialize(const u_int64_t *const val, void *const buf, const size_t size) {
    size_t length = 0;
    if (val == NULL || buf == NULL) {
        return -1;
    }
    length = gquic_varint_size(val);
    if (length > size) {
        return -2;
    }
    switch (length) {
    case 1:
        gquic_big_endian_transfer(buf, val, 1);
        break;

    case 2:
        gquic_big_endian_transfer(buf, val, 2);
        ((unsigned char *) buf)[0] |= 0x40;
        break;

    case 4:
        gquic_big_endian_transfer(buf, val, 4);
        ((unsigned char *) buf)[0] |= 0x80;
        break;

    case 8:
        gquic_big_endian_transfer(buf, val, 8);
        ((unsigned char *) buf)[0] |= 0xc0;
        break;

    default:
        return -3;
    }

    return length;
}

ssize_t gquic_varint_deserialize(u_int64_t *const val, const void *const buf, const size_t size) {
    if (val == NULL || buf == NULL) {
        return -1;
    }
    *val = 0;
    switch (((unsigned char *) buf)[0] & 0xc0) {
    case 0x00:
        if (1 > size) {
            return -3;
        }
        gquic_big_endian_transfer(val, buf, 1);
        ((u_int8_t *) val)[0] &= 0x3f;
        return 1;

    case 0x40:
        if (2 > size) {
            return -3;
        }
        gquic_big_endian_transfer(val, buf, 2);
        ((unsigned char *) val)[1] &= 0x3f;
        return 2;

    case 0x80:
        if (4 > size) {
            return -3;
        }
        gquic_big_endian_transfer(val, buf, 4);
        ((unsigned char *) val)[3] &= 0x3f;
        return 4;

    case 0xc0:
        if (8 > size) {
            return -3;
        }
        gquic_big_endian_transfer(val, buf, 8);
        ((unsigned char *) val)[7] &= 0x3f;
        return 8;

    default:
        return -4;
    }
}

