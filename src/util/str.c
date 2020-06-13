#include "util/str.h"
#include "util/malloc.h"
#include "exception.h"
#include <unistd.h>
#include <string.h>

int gquic_str_init(gquic_str_t *str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str->size = 0;
    str->val = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_alloc(gquic_str_t *str, size_t size) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (size > 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &str->val, size));
        str->size = size;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_reset(gquic_str_t *str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str->val != NULL) {
        gquic_free(str->val);
    }
    gquic_str_init(str);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_copy(gquic_str_t *str, const gquic_str_t *ref) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(str);
    if (GQUIC_STR_SIZE(ref) == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT(gquic_str_alloc(str, GQUIC_STR_SIZE(ref)))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    memcpy(GQUIC_STR_VAL(str), GQUIC_STR_VAL(ref), GQUIC_STR_SIZE(str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_set(gquic_str_t *const str, const char *const val) {
    if (str == NULL || val == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT(gquic_str_alloc(str, strlen(val)))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    memcpy(GQUIC_STR_VAL(str), val, GQUIC_STR_SIZE(str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_test_echo(const gquic_str_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    u_int32_t off = 0;
    size_t i;
    printf("     ");
    for (i = 0; i < 16; i++) {
        printf("%02X ", (u_int8_t) i);
    }
    for (i = 0; i < GQUIC_STR_SIZE(str); i++) {
        if (i % 16 == 0) {
            printf("\n%04X ", off);
            off += 16;
        }
        printf("%02X ", ((unsigned char *) GQUIC_STR_VAL(str))[i]);
    }
    printf("\n");

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_cmp(const gquic_str_t *const str_a, const gquic_str_t *const str_b) {
    if (GQUIC_STR_SIZE(str_a) == 0 && GQUIC_STR_SIZE(str_b) == 0) {
        return 0;
    }
    if (GQUIC_STR_SIZE(str_a) != GQUIC_STR_SIZE(str_b)) {
        return (int) GQUIC_STR_SIZE(str_a) - (int) GQUIC_STR_SIZE(str_b);
    }

    return memcmp(GQUIC_STR_VAL(str_a), GQUIC_STR_VAL(str_b), GQUIC_STR_SIZE(str_a));
}

int gquic_str_concat(gquic_str_t *const ret, const gquic_str_t *const a, const gquic_str_t *const b) {
    if (ret == NULL || a == NULL || b == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT(gquic_str_alloc(ret, GQUIC_STR_SIZE(a) + GQUIC_STR_SIZE(b)))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_writer_str_t writer = *ret;
    if (GQUIC_ASSERT(gquic_writer_str_write(&writer, a))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    if (GQUIC_ASSERT(gquic_writer_str_write(&writer, b))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_str_clear(gquic_str_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    memset(GQUIC_STR_VAL(str), 0, GQUIC_STR_SIZE(str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_reader_str_readed_size(gquic_reader_str_t *const reader, const size_t n) {
    if (reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(reader) < n) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    reader->size -= n;
    reader->val += n;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int8_t gquic_reader_str_read_byte(gquic_reader_str_t *const reader) {
    u_int8_t ret = 0;
    if (reader == NULL) {
        return 0;
    }
    if (GQUIC_STR_SIZE(reader) < 1) {
        return 0;
    }
    ret = GQUIC_STR_FIRST_BYTE(reader);
    gquic_reader_str_readed_size(reader, 1);

    return ret;
}

int gquic_reader_str_read(gquic_str_t *const out, gquic_reader_str_t *const reader) {
    if (out == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(out) > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    memcpy(GQUIC_STR_VAL(out), GQUIC_STR_VAL(reader), GQUIC_STR_SIZE(out));
    gquic_reader_str_readed_size(reader, GQUIC_STR_SIZE(out));

    return 0;
}

int gquic_writer_str_writed_size(gquic_writer_str_t *const writer, const size_t n) {
    if (writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(writer) < n) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    writer->size -= n;
    writer->val += n;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_writer_str_write(gquic_writer_str_t *const writer, const gquic_str_t *const buf) {
    u_int64_t writer_size = 0;
    if (writer == NULL || buf == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    writer_size = GQUIC_STR_SIZE(buf);
    if (GQUIC_STR_SIZE(writer) < writer_size) {
        writer_size = GQUIC_STR_SIZE(writer);
    }
    memcpy(GQUIC_STR_VAL(writer), GQUIC_STR_VAL(buf), writer_size);
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, writer_size));
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_writer_str_write_byte(gquic_writer_str_t *const writer, u_int8_t b) {
    if (writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(writer) < 1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_str_t bbuf = { 1, &b };

    return gquic_writer_str_write(writer, &bbuf);
}

int gquic_writer_str_write_padding(gquic_writer_str_t *const writer, u_int8_t padding_cnt, const u_int64_t padding_len) {
    if (writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(writer) < padding_len) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    memset(GQUIC_STR_VAL(writer), padding_cnt, padding_len);
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, padding_len));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_writer_str_write_x509(gquic_writer_str_t *const writer, X509 *const x509) {
    unsigned char *buf = NULL;
    size_t size = 0;
    if (writer == NULL || x509 == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    size = i2d_X509(x509, NULL);
    buf = GQUIC_STR_VAL(writer);
    if (GQUIC_STR_SIZE(writer) < size) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    i2d_X509(x509, &buf);
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, size));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
