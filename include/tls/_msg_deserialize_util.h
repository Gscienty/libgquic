#include "util/big_endian.h"
#include "util/str.h"
#include <unistd.h>
#include <string.h>

static inline int __gquic_recovery_bytes(void *, const size_t, const void *, const size_t, size_t *);
static inline int __gquic_recovery_str(gquic_str_t *, const size_t, const void *, const size_t, size_t *);

static inline int __gquic_recovery_bytes(void *ret, const size_t bytes, const void *buf, const size_t size, size_t *off) {
    if (bytes > size - *off) {
        return -1;
    }
    if (gquic_big_endian_transfer(ret, buf + *off, bytes) != 0) {
        return -2;
    }
    *off += bytes;
    return 0;
}

static inline int __gquic_recovery_str(gquic_str_t *str, const size_t bytes, const void *buf, const size_t size, size_t *off) {
    if (str == NULL || buf == NULL) {
        return -1;
    }
    if (bytes > size - *off) {
        return -2;
    }
    if (gquic_str_alloc(str, bytes) != 0) {
        return -3;
    }
    memcpy(str->val, buf + *off, bytes);
    *off += bytes;

    return 0;
}
