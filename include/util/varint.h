#ifndef _LIBGQUIC_UTIL_VARINT_H
#define _LIBGQUIC_UTIL_VARINT_H

#include "util/str.h"
#include <sys/types.h>

ssize_t gquic_varint_size(const u_int64_t *const val);
int gquic_varint_serialize(const u_int64_t *const val, gquic_writer_str_t *const writer);
int gquic_varint_deserialize(u_int64_t *const val, gquic_reader_str_t *const reader);

static inline size_t gquic_varint_serialized_size(const u_int8_t first_byte) {
    switch (first_byte & 0xc0) {
    case 0x00:
        return 1;
    case 0x40:
        return 2;
    case 0x80:
        return 4;
    case 0xc0:
        return 8;
    }
    return 0;
}

#endif
