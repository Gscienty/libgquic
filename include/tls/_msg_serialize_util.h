/* include/tls/_msg_deserialize_util.h TLS record序列化工具
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "util/big_endian.h"
#include "util/str.h"
#include "util/list.h"
#include "exception.h"
#include <sys/types.h>
#include <string.h>
#include <openssl/x509.h>

typedef struct gquic_serialize_stack_s gquic_serialize_stack_t;
struct gquic_serialize_stack_s {
    void *ptr;
    u_int8_t size;
};


/**
 * 写字段时入栈操作（用于计算字段长度）
 *
 * @param stack: stack
 * @param writer: writer
 * @param size: 字段前缀长度所占长度
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_stack_push(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t size);

/**
 * 写字段时获取填写字段长度的位置
 *
 * @param stack: stack
 *
 * @return ptr: 填写长度的位置
 * @return prefix_len: 字段长度所占大小
 * @return: exception
 */
static inline gquic_exception_t __gquic_stack_pop(void **const ptr, u_int8_t *const prefix_len, gquic_list_t *const stack);

/**
 * 填充字段长度
 *
 * @param stack: stack
 * @param writer: writer
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_fill_prefix_len(gquic_list_t *const stack, gquic_writer_str_t *const writer);

/**
 * 暂存当前位置为字段长度
 *
 * @param stack: stack
 * @param writer: writer
 * @param len: 字段长度所占大小
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_store_prefix_len(gquic_list_t *const stack, gquic_writer_str_t *const writer, const u_int8_t len);

/**
 * 填充一个字符串
 *
 * @param writer: writer
 * @param str: 字符串
 * @param len: 字符串长度所占大小
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_fill_str(gquic_writer_str_t *const writer, const gquic_str_t *const str, const u_int8_t len);

/**
 * 填充一个X509证书
 *
 * @param writer: writer
 * @param x509: X509证书
 * @param len: 证书长度所占大小
 *
 * @return: exception
 */
static inline gquic_exception_t __gquic_fill_x509(gquic_writer_str_t *const writer, X509 *const x509, const u_int8_t len);

static inline gquic_exception_t __gquic_stack_push(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t size) {
    gquic_serialize_stack_t *elem = NULL;
    gquic_list_alloc((void **) &elem, sizeof(gquic_serialize_stack_t));
    gquic_list_insert_after(stack, elem);
    elem->ptr = GQUIC_STR_VAL(writer);
    elem->size = size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __gquic_stack_pop(void **const ptr, u_int8_t *const prefix_len, gquic_list_t *stack) {
    gquic_serialize_stack_t *ele = GQUIC_LIST_FIRST(stack);
    *ptr = ele->ptr;
    *prefix_len = ele->size;
    gquic_list_release(GQUIC_LIST_FIRST(stack));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __gquic_fill_prefix_len(gquic_list_t *stack, gquic_writer_str_t *const writer) {
    void *prefix_len_storage = NULL;
    u_int8_t prefix_len = 0;
    GQUIC_ASSERT_FAST_RETURN(__gquic_stack_pop(&prefix_len_storage, &prefix_len, stack));
    size_t payload_len = GQUIC_STR_VAL(writer) - prefix_len_storage - prefix_len;
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(prefix_len_storage, &payload_len, prefix_len));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __gquic_store_prefix_len(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t len) {
    GQUIC_ASSERT_FAST_RETURN(__gquic_stack_push(stack, writer, len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, len));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __gquic_fill_str(gquic_writer_str_t *const writer, const gquic_str_t *str, const u_int8_t prefix_len) {
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &str->size, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __gquic_fill_x509(gquic_writer_str_t *const writer, X509 *const x509, const u_int8_t prefix_len) {
    size_t size = i2d_X509(x509, NULL);
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &size, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_x509(writer, x509));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
