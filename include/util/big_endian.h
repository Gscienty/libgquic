#ifndef _LIBGQUIC_UTIL_BIG_ENDIAN_H
#define _LIBGQUIC_UTIL_BIG_ENDIAN_H

#include "util/str.h"
#include <unistd.h>

int gquic_big_endian_transfer(void *out, const void *in, const size_t size);
int gquic_big_endian_writer_1byte(gquic_writer_str_t *const writer, const u_int8_t bytes);
int gquic_big_endian_writer_2byte(gquic_writer_str_t *const writer, const u_int16_t bytes);
int gquic_big_endian_writer_4byte(gquic_writer_str_t *const writer, const u_int32_t bytes);
int gquic_big_endian_writer_8byte(gquic_writer_str_t *const writer, const u_int64_t bytes);
int gquic_big_endian_reader_1byte(u_int8_t *bytes, gquic_reader_str_t *const reader);
int gquic_big_endian_reader_2byte(u_int16_t *bytes, gquic_reader_str_t *const reader);
int gquic_big_endian_reader_4byte(u_int32_t *bytes, gquic_reader_str_t *const reader);
int gquic_big_endian_reader_8byte(u_int64_t *bytes, gquic_reader_str_t *const reader);

#endif
