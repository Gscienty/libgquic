#include "util/big_endian.h"
#include "util/str.h"
#include "util/list.h"
#include <sys/types.h>
#include <string.h>

static inline void __gquic_stack_push(gquic_list_t *, const size_t);
static inline size_t __gquic_stack_pop(gquic_list_t *);
static inline void __gquic_fill_prefix_len(gquic_list_t *, void *, const size_t, const size_t);
static inline void __gquic_store_prefix_len(gquic_list_t *, size_t *, const size_t);
static inline void __gquic_fill_4byte(void *, size_t *, const u_int32_t);
static inline void __gquic_fill_2byte(void *, size_t *, const u_int16_t);
static inline void __gquic_fill_1byte(void *, size_t *, const u_int8_t);
static inline void __gquic_fill_str(void *, size_t *, const gquic_str_t *);
static inline void __gquic_fill_str_full(void *, size_t *, const gquic_str_t *, const size_t);

static inline void __gquic_stack_push(gquic_list_t *stack, const size_t val) {
    gquic_list_insert_after(stack, gquic_list_alloc(sizeof(size_t)));
    *(size_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(stack)) = val;
}

static inline size_t __gquic_stack_pop(gquic_list_t *stack) {
    size_t ret = *(size_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(stack));
    gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(stack)));
    return ret;
}

static inline void __gquic_fill_prefix_len(gquic_list_t *stack, void *buf, const size_t off, const size_t len) {
    size_t prefix_len_off = __gquic_stack_pop(stack);
    size_t prefix_len = off - len - prefix_len_off;
    gquic_big_endian_transfer(buf + prefix_len_off, &prefix_len, len);
}

static inline void __gquic_store_prefix_len(gquic_list_t *stack, size_t *off, const size_t len) {
    __gquic_stack_push(stack, *off);
    *off += len;
}

static inline void __gquic_fill_4byte(void *buf, size_t *off, const u_int32_t val) {
    gquic_big_endian_transfer(buf + *off, &val, 4);
    *off += 4;
}

static inline void __gquic_fill_2byte(void *buf, size_t *off, const u_int16_t val) {
    gquic_big_endian_transfer(buf + *off, &val, 2);
    *off += 2;
}

static inline void __gquic_fill_1byte(void *buf, size_t *off, const u_int8_t val) {
    gquic_big_endian_transfer(buf + *off, &val, 1);
    *off += 1;
}

static inline void __gquic_fill_str(void *buf, size_t *off, const gquic_str_t *str) {
    memcpy(buf + *off, str->val, str->size);
    *off += str->size;
}

static inline void __gquic_fill_str_full(void *buf, size_t *off, const gquic_str_t *str, const size_t prefix_len) {
    gquic_list_t prefix_len_off;
    gquic_list_head_init(&prefix_len_off);
    __gquic_store_prefix_len(&prefix_len_off, off, prefix_len);
    __gquic_fill_str(buf, off, str);
    __gquic_fill_prefix_len(&prefix_len_off, buf, *off, prefix_len);
}
