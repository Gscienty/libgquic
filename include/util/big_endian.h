/* include/util/big_endian.h 数字大端序列化
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_UTIL_BIG_ENDIAN_H
#define _LIBGQUIC_UTIL_BIG_ENDIAN_H

#include "util/str.h"
#include "exception.h"
#include <unistd.h>

gquic_exception_t gquic_big_endian_transfer(void *out, const void *in, const size_t size);
gquic_exception_t gquic_big_endian_writer_1byte(gquic_writer_str_t *const writer, const u_int8_t bytes);
gquic_exception_t gquic_big_endian_writer_2byte(gquic_writer_str_t *const writer, const u_int16_t bytes);
gquic_exception_t gquic_big_endian_writer_3byte(gquic_writer_str_t *const writer, const u_int32_t bytes);
gquic_exception_t gquic_big_endian_writer_4byte(gquic_writer_str_t *const writer, const u_int32_t bytes);
gquic_exception_t gquic_big_endian_writer_8byte(gquic_writer_str_t *const writer, const u_int64_t bytes);
gquic_exception_t gquic_big_endian_reader_1byte(u_int8_t *bytes, gquic_reader_str_t *const reader);
gquic_exception_t gquic_big_endian_reader_2byte(u_int16_t *bytes, gquic_reader_str_t *const reader);
gquic_exception_t gquic_big_endian_reader_3byte(u_int32_t *bytes, gquic_reader_str_t *const reader);
gquic_exception_t gquic_big_endian_reader_4byte(u_int32_t *bytes, gquic_reader_str_t *const reader);
gquic_exception_t gquic_big_endian_reader_8byte(u_int64_t *bytes, gquic_reader_str_t *const reader);

#endif
