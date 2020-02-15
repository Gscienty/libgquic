#ifndef _LIBGQUIC_UTIL_VARINT_H
#define _LIBGQUIC_UTIL_VARINT_H

#include "util/str.h"
#include <sys/types.h>

ssize_t gquic_varint_size(const u_int64_t *const val);
int gquic_varint_serialize(const u_int64_t *const val, gquic_writer_str_t *const writer);
int gquic_varint_deserialize(u_int64_t *const val, gquic_reader_str_t *const reader);

#endif
