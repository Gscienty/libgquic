#include "util/big_endian.h"
#include "util/str.h"
#include <unistd.h>
#include <string.h>

static inline int __gquic_recovery_bytes(void *, const size_t, gquic_reader_str_t *const reader);
static inline int __gquic_recovery_str(gquic_str_t *, const size_t, gquic_reader_str_t *const reader);

static inline int __gquic_recovery_bytes(void *ret, const size_t bytes, gquic_reader_str_t *const reader) {
    if (bytes > GQUIC_STR_SIZE(reader)) {
        return -1;
    }
    if (gquic_big_endian_transfer(ret, GQUIC_STR_VAL(reader), bytes) != 0) {
        return -2;
    }
    gquic_reader_str_readed_size(reader, bytes);
    return 0;
}

static inline int __gquic_recovery_str(gquic_str_t *str, const size_t bytes, gquic_reader_str_t *const reader) {
    if (str == NULL || reader == NULL) {
        return -1;
    }
    if (bytes > GQUIC_STR_SIZE(reader)) {
        return -2;
    }
    gquic_str_init(str);
    if (__gquic_recovery_bytes(&str->size, bytes, reader) != 0) {
        return -3;
    }
    if (str->size > GQUIC_STR_SIZE(reader)) {
        return -4;
    }
    if (gquic_str_alloc(str, str->size) != 0) {
        return -5;
    }
    if (gquic_reader_str_read(str, reader) != 0) {
        return -6;
    }
    return 0;
}
