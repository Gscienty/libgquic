#include "util/big_endian.h"
#include "exception.h"

int gquic_big_endian_transfer(void *out, const void *in, const size_t size) {
    if (out == NULL || in == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    size_t i = 0;
    for (i = 0; i < size; i++) {
        ((u_int8_t *) out)[size - i - 1] = ((u_int8_t *) in)[i];
    }
    return GQUIC_SUCCESS;
}

int gquic_big_endian_writer_1byte(gquic_writer_str_t *const writer, const u_int8_t bytes) {
    if (GQUIC_STR_SIZE(writer) < 1) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 1);
    gquic_writer_str_writed_size(writer, 1);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_writer_2byte(gquic_writer_str_t *const writer, const u_int16_t bytes) {
    if (GQUIC_STR_SIZE(writer) < 2) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 2);
    gquic_writer_str_writed_size(writer, 2);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_writer_3byte(gquic_writer_str_t *const writer, const u_int32_t bytes) {
    if (GQUIC_STR_SIZE(writer) < 3) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 3);
    gquic_writer_str_writed_size(writer, 3);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_writer_4byte(gquic_writer_str_t *const writer, const u_int32_t bytes) {
    if (GQUIC_STR_SIZE(writer) < 4) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 4);
    gquic_writer_str_writed_size(writer, 4);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_writer_8byte(gquic_writer_str_t *const writer, const u_int64_t bytes) {
    if (GQUIC_STR_SIZE(writer) < 8) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 8);
    gquic_writer_str_writed_size(writer, 8);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_reader_1byte(u_int8_t *bytes, gquic_reader_str_t *const reader) {
    if (GQUIC_STR_SIZE(reader) < 1) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 1);
    gquic_reader_str_readed_size(reader, 1);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_reader_2byte(u_int16_t *bytes, gquic_reader_str_t *const reader) {
    if (GQUIC_STR_SIZE(reader) < 2) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 2);
    gquic_reader_str_readed_size(reader, 2);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_reader_3byte(u_int32_t *bytes, gquic_reader_str_t *const reader) {
    if (GQUIC_STR_SIZE(reader) < 3) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 3);
    gquic_reader_str_readed_size(reader, 3);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_reader_4byte(u_int32_t *bytes, gquic_reader_str_t *const reader) {
    if (GQUIC_STR_SIZE(reader) < 4) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 4);
    gquic_reader_str_readed_size(reader, 4);
    return GQUIC_SUCCESS;
}

int gquic_big_endian_reader_8byte(u_int64_t *bytes, gquic_reader_str_t *const reader) {
    if (GQUIC_STR_SIZE(reader) < 8) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 8);
    gquic_reader_str_readed_size(reader, 8);
    return GQUIC_SUCCESS;
}
