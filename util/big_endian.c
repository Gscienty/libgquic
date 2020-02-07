#include "util/big_endian.h"

int gquic_big_endian_transfer(void *out, const void *in, const size_t size) {
    if (out == NULL) {
        return -1;
    }
    if (in == NULL) {
        return -2;
    }
    size_t i = 0;
    for (i = 0; i < size; i++) {
        ((unsigned char *) out)[size - i - 1] = ((unsigned char *) in)[i];
    }
    return 0;
}

int gquic_big_endian_writer_1byte(gquic_writer_str_t *const writer, const u_int8_t bytes) {
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 1);
    gquic_writer_str_writed_size(writer, 1);
    return 0;
}

int gquic_big_endian_writer_2byte(gquic_writer_str_t *const writer, const u_int16_t bytes) {
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 2);
    gquic_writer_str_writed_size(writer, 2);
    return 0;
}

int gquic_big_endian_writer_4byte(gquic_writer_str_t *const writer, const u_int32_t bytes) {
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 4);
    gquic_writer_str_writed_size(writer, 4);
    return 0;
}

int gquic_big_endian_writer_8byte(gquic_writer_str_t *const writer, const u_int64_t bytes) {
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &bytes, 8);
    gquic_writer_str_writed_size(writer, 8);
    return 0;
}

int gquic_big_endian_reader_1byte(u_int8_t *bytes, gquic_reader_str_t *const reader) {
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 1);
    gquic_reader_str_readed_size(reader, 1);
    return 0;
}

int gquic_big_endian_reader_2byte(u_int16_t *bytes, gquic_reader_str_t *const reader) {
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 2);
    gquic_reader_str_readed_size(reader, 2);
    return 0;
}

int gquic_big_endian_reader_4byte(u_int32_t *bytes, gquic_reader_str_t *const reader) {
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 4);
    gquic_reader_str_readed_size(reader, 4);
    return 0;
}

int gquic_big_endian_reader_8byte(u_int64_t *bytes, gquic_reader_str_t *const reader) {
    gquic_big_endian_transfer(bytes, GQUIC_STR_VAL(reader), 8);
    gquic_reader_str_readed_size(reader, 8);
    return 0;
}
