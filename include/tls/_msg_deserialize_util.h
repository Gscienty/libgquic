/* include/tls/_msg_deserialize_util.h TLS record反序列化工具
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "util/big_endian.h"
#include "util/str.h"
#include "exception.h"
#include <unistd.h>
#include <string.h>

/**
 * 反序列化一个比特串
 *
 * @param ret: 比特串容器
 * @param len: 反序列化的比特串长度
 * @param reader: reader
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_recovery_bytes(void * ret, const size_t len, gquic_reader_str_t *const reader);

/**
 * 反序列化一个字符串
 *
 * @param str: 字符串容器
 * @param len: 字符串长度
 * @param reader: reader
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_recovery_str(gquic_str_t * str, const size_t len, gquic_reader_str_t *const reader);

/**
 * 反序列化一个X509证书
 *
 * @param x509: X509证书容器
 * @param len: X509证书长度
 * @param reader: reader
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_recovery_x509(X509 ** x509, const size_t len, gquic_reader_str_t *const reader);

static inline gquic_exception_t __gquic_recovery_bytes(void *ret, const size_t len, gquic_reader_str_t *const reader) {
    if (len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(ret, GQUIC_STR_VAL(reader), len));
    gquic_reader_str_readed_size(reader, len);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __gquic_recovery_str(gquic_str_t *str, const size_t bytes, gquic_reader_str_t *const reader) {
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

static inline gquic_exception_t __gquic_recovery_x509(X509 ** x509_storage, const size_t bytes, gquic_reader_str_t *const reader) {
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
