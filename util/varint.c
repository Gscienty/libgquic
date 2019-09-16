#include "util/varint.h"
#include "util/big_endian.h"

int gquic_varint_wrap(gquic_varint_t *varint, const unsigned long value) {
    if (varint == NULL) {
        return -1;
    }
    varint->length = 0;
    varint->value = 0;
    if (0x3f >= value) {
        varint->length = 1;
        varint->value = value;
    }
    else if (0x3fff >= value) {
        varint->length = 2;
        varint->value = value;
    }
    else if (0x3fffffff >= value) {
        varint->length = 4;
        varint->value = value;
    }
    else if (0x3fffffffffffffff >= value) {
        varint->length = 8;
        varint->value = value;
    }
    else {
        return -1;
    }
    return 0;
}

ssize_t gquic_varint_serialize(const gquic_varint_t *varint, void *buf, const size_t size) {
    if (varint == NULL) {
        return -1;
    }
    if (varint->length > size) {
        return -2;
    }
    if (buf == NULL) {
        return -3;
    }
    switch (varint->length) {
    case 1:
        gquic_big_endian_transfer(buf, &varint->value, 1);
        break;

    case 2:
        gquic_big_endian_transfer(buf, &varint->value, 2);
        ((unsigned char *) buf)[0] |= 0x40;
        break;

    case 4:
        gquic_big_endian_transfer(buf, &varint->value, 4);
        ((unsigned char *) buf)[0] |= 0x80;
        break;

    case 8:
        gquic_big_endian_transfer(buf, &varint->value, 8);
        ((unsigned char *) buf)[0] |= 0xc0;
        break;

    default:
        return -4;
    }

    return varint->length;
}

ssize_t gquic_varint_deserialize(gquic_varint_t *varint, const void *buf, const size_t size) {
    if (varint == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    varint->length = 0;
    varint->value = 0;
    switch (((unsigned char *) buf)[0] & 0xc0) {
    case 0x00:
        varint->length = 1;
        if (varint->length > size) {
            return -3;
        }
        gquic_big_endian_transfer(&varint->value, buf, 1);
        ((unsigned char *) &varint->value)[0] &= 0x3f;
        break;

    case 0x40:
        varint->length = 2;
        if (varint->length > size) {
            return -3;
        }
        gquic_big_endian_transfer(&varint->value, buf, 2);
        ((unsigned char *) &varint->value)[1] &= 0x3f;
        break;

    case 0x80:
        varint->length = 4;
        if (varint->length > size) {
            return -3;
        }
        gquic_big_endian_transfer(&varint->value, buf, 4);
        ((unsigned char *) &varint->value)[3] &= 0x3f;
        break;

    case 0xc0:
        varint->length = 8;
        if (varint->length > size) {
            return -3;
        }
        gquic_big_endian_transfer(&varint->value, buf, 8);
        ((unsigned char *) &varint->value)[7] &= 0x3f;
        break;

    default:
        return -4;
    }

    return varint->length;
}

