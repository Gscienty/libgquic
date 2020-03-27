#include "util/big_endian.h"
#include "util/str.h"
#include "util/list.h"
#include <sys/types.h>
#include <string.h>
#include <openssl/x509.h>

typedef struct gquic_serialize_stack_s gquic_serialize_stack_t;
struct gquic_serialize_stack_s {
    void *ptr;
    u_int8_t size;
};


static inline void __gquic_stack_push(gquic_list_t *, gquic_writer_str_t *const, const u_int8_t);
static inline void __gquic_stack_pop(void **const, u_int8_t *const, gquic_list_t *);
static inline void __gquic_fill_prefix_len(gquic_list_t *, gquic_writer_str_t *const);
static inline void __gquic_store_prefix_len(gquic_list_t *, gquic_writer_str_t*const, const u_int8_t);
static inline void __gquic_fill_str(gquic_writer_str_t *const, const gquic_str_t *, const u_int8_t);
static inline void __gquic_fill_x509(gquic_writer_str_t *const, X509 *const, const u_int8_t);

static inline void __gquic_stack_push(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t size) {
    gquic_list_insert_after(stack, gquic_list_alloc(sizeof(gquic_serialize_stack_t)));
    ((gquic_serialize_stack_t *) GQUIC_LIST_FIRST(stack))->ptr = GQUIC_STR_VAL(writer);
    ((gquic_serialize_stack_t *) GQUIC_LIST_FIRST(stack))->size = size;
}

static inline void __gquic_stack_pop(void **const ptr, u_int8_t *const prefix_len, gquic_list_t *stack) {
    gquic_serialize_stack_t *ele = GQUIC_LIST_FIRST(stack);
    *ptr = ele->ptr;
    *prefix_len = ele->size;
    gquic_list_release(GQUIC_LIST_FIRST(stack));
}

static inline void __gquic_fill_prefix_len(gquic_list_t *stack, gquic_writer_str_t *const writer) {
    void *prefix_len_storage = NULL;
    u_int8_t prefix_len = 0;
    __gquic_stack_pop(&prefix_len_storage, &prefix_len, stack);
    size_t payload_len = GQUIC_STR_VAL(writer) - prefix_len_storage - prefix_len;
    gquic_big_endian_transfer(prefix_len_storage, &payload_len, prefix_len);
}

static inline void __gquic_store_prefix_len(gquic_list_t *stack, gquic_writer_str_t *const writer, const u_int8_t len) {
    __gquic_stack_push(stack, writer, len);
    gquic_writer_str_writed_size(writer, len);
}

static inline void __gquic_fill_str(gquic_writer_str_t *const writer, const gquic_str_t *str, const u_int8_t prefix_len) {
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &str->size, prefix_len);
    gquic_writer_str_writed_size(writer, prefix_len);
    gquic_writer_str_write(writer, str);
}

static inline void __gquic_fill_x509(gquic_writer_str_t *const writer, X509 *const x509, const u_int8_t prefix_len) {
    size_t size = i2d_X509(x509, NULL);
    gquic_big_endian_transfer(GQUIC_STR_VAL(writer), &size, prefix_len);
    gquic_writer_str_writed_size(writer, prefix_len);
    gquic_writer_str_write_x509(writer, x509);
}
