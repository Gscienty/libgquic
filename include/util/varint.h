#ifndef _LIBGQUIC_UTIL_VARINT_H
#define _LIBGQUIC_UTIL_VARINT_H

#include <unistd.h>

typedef struct gquic_varint_s gquic_varint_t;
struct gquic_varint_s {
    unsigned char length;
    unsigned long value;
};

int gquic_varint_wrap(gquic_varint_t *, const unsigned long);

ssize_t gquic_varint_serialize(const gquic_varint_t *, void *, const size_t);

ssize_t gquic_varint_deserialize(gquic_varint_t *, const void *, const size_t);

#endif
