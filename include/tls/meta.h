/* include/tls/meta.h TLS record base
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_MSG_META_H
#define _LIBGQUIC_TLS_MSG_META_H

#include "exception.h"
#include "util/str.h"
#include <sys/types.h>
#include <stddef.h>

/**
 * record meta
 */
typedef struct gquic_tls_msg_meta_s gquic_tls_msg_meta_t;
struct gquic_tls_msg_meta_s {
    gquic_exception_t (*init_func) (void *const);
    gquic_exception_t (*dtor_func) (void *const);
    ssize_t (*size_func) (const void *const);
    gquic_exception_t (*serialize_func) (const void *const, gquic_writer_str_t *const);
    gquic_exception_t (*deserialize_func) (void *const, gquic_reader_str_t *const);
    u_int8_t type;

    size_t payload_size;
};

#define GQUIC_TLS_MSG_META(ptr) (*((gquic_tls_msg_meta_t *) (((void *) ptr) - sizeof(gquic_tls_msg_meta_t))))
#define GQUIC_TLS_MSG_SPEC(msg_type_t, ptr) (*((msg_type_t *) (((void *) ptr) + sizeof(gquic_tls_msg_meta_t))))

#define GQUIC_TLS_MSG_INIT(ptr) (GQUIC_TLS_MSG_META((ptr)).init_func((ptr)))
#define GQUIC_TLS_MSG_DTOR(ptr) (GQUIC_TLS_MSG_META((ptr)).dtor_func((ptr)))
#define GQUIC_TLS_MSG_SIZE(ptr) (GQUIC_TLS_MSG_META((ptr)).size_func((ptr)))
#define GQUIC_TLS_MSG_SERIALIZE(ptr, writer) (GQUIC_TLS_MSG_META((ptr)).serialize_func((ptr), (writer)))
#define GQUIC_TLS_MSG_DESERIALIZE(ptr, reader) (GQUIC_TLS_MSG_META((ptr)).deserialize_func((ptr), (reader)))

/**
 * 申请一个record空间
 *
 * @param size: record长度
 *
 * @return: result: record
 * @return: exception
 */
gquic_exception_t gquic_tls_msg_alloc(void **const result, const size_t size);

/**
 * 释放一个record空间
 *
 * @param msg: record
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_msg_release(void *const msg);

/**
 * 对record进行序列化
 *
 * @param buf: 存储序列化后的数据
 * @param msg: TLS record
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_tls_msg_combine_serialize(gquic_str_t *const buf, const void *const msg) {
    if (buf == NULL || msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(buf, GQUIC_TLS_MSG_SIZE(msg)));
    gquic_writer_str_t writer = *buf;
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_MSG_SERIALIZE(msg, &writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
