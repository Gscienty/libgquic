#ifndef _LIBGQUIC_UTIL_VARINT_H
#define _LIBGQUIC_UTIL_VARINT_H

#include <sys/types.h>

ssize_t gquic_varint_size(const u_int64_t *const val);
ssize_t gquic_varint_serialize(const u_int64_t *const val, void *const buf, const size_t size);
ssize_t gquic_varint_deserialize(u_int64_t *const val, const void *const buf, const size_t size);

#endif
