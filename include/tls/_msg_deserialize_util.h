#include "util/big_endian.h"
#include "util/str.h"
#include "exception.h"
#include <unistd.h>
#include <string.h>

static inline int __gquic_recovery_bytes(void *, const size_t, gquic_reader_str_t *const reader);
static inline int __gquic_recovery_str(gquic_str_t *, const size_t, gquic_reader_str_t *const reader);
static inline int __gquic_recovery_x509(X509 **, const size_t, gquic_reader_str_t *const reader);

static inline int __gquic_recovery_bytes(void *ret, const size_t bytes, gquic_reader_str_t *const reader) {
    if (bytes > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(ret, GQUIC_STR_VAL(reader), bytes));
    gquic_reader_str_readed_size(reader, bytes);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_recovery_str(gquic_str_t *str, const size_t bytes, gquic_reader_str_t *const reader) {
    if (str == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (bytes > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_str_init(str);
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&str->size, bytes, reader));

    if (str->size > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(str, str->size));
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(str, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_recovery_x509(X509 ** x509_storage, const size_t bytes, gquic_reader_str_t *const reader) {
    gquic_str_t str = { 0, NULL };
    const u_int8_t *tmp = NULL;
    if (x509_storage == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&str, bytes, reader));
    tmp = GQUIC_STR_VAL(&str);
    if (d2i_X509(x509_storage, &tmp, GQUIC_STR_SIZE(&str)) == NULL) {
        gquic_str_reset(&str);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_BAD_X509);
    }
    gquic_str_reset(&str);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
