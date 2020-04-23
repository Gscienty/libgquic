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


static inline int __gquic_stack_push(gquic_list_t *, gquic_writer_str_t *const, const u_int8_t);
static inline int __gquic_stack_pop(void **const, u_int8_t *const, gquic_list_t *);
static inline int __gquic_fill_prefix_len(gquic_list_t *, gquic_writer_str_t *const);
static inline int __gquic_store_prefix_len(gquic_list_t *, gquic_writer_str_t*const, const u_int8_t);
static inline int __gquic_fill_str(gquic_writer_str_t *const, const gquic_str_t *, const u_int8_t);
static inline int __gquic_fill_x509(gquic_writer_str_t *const, X509 *const, const u_int8_t);

static inline int __gquic_stack_push(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t size) {
    gquic_serialize_stack_t *elem = NULL;
    gquic_list_alloc((void **) &elem, sizeof(gquic_serialize_stack_t));
    gquic_list_insert_after(stack, elem);
    elem->ptr = GQUIC_STR_VAL(writer);
    elem->size = size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_stack_pop(void **const ptr, u_int8_t *const prefix_len, gquic_list_t *stack) {
    gquic_serialize_stack_t *ele = GQUIC_LIST_FIRST(stack);
    *ptr = ele->ptr;
    *prefix_len = ele->size;
    gquic_list_release(GQUIC_LIST_FIRST(stack));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_fill_prefix_len(gquic_list_t *stack, gquic_writer_str_t *const writer) {
    void *prefix_len_storage = NULL;
    u_int8_t prefix_len = 0;
    GQUIC_ASSERT_FAST_RETURN(__gquic_stack_pop(&prefix_len_storage, &prefix_len, stack));
    size_t payload_len = GQUIC_STR_VAL(writer) - prefix_len_storage - prefix_len;
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(prefix_len_storage, &payload_len, prefix_len));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_store_prefix_len(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t len) {
    GQUIC_ASSERT_FAST_RETURN(__gquic_stack_push(stack, writer, len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, len));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_fill_str(gquic_writer_str_t *const writer, const gquic_str_t *str, const u_int8_t prefix_len) {
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &str->size, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int __gquic_fill_x509(gquic_writer_str_t *const writer, X509 *const x509, const u_int8_t prefix_len) {
    size_t size = i2d_X509(x509, NULL);
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &size, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, prefix_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_x509(writer, x509));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
