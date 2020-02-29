#ifndef _LIBGQUIC_UTIL_STR_H
#define _LIBGQUIC_UTIL_STR_H

#include <sys/types.h>

typedef struct gquic_str_s gquic_str_t;
struct gquic_str_s {
    size_t size;
    void *val;
};

#define GQUIC_STR_VAL(p) (\
                          ({\
                           gquic_str_t *__str = NULL;\
                           (void) (__str == (p));\
                           }),\
                           (p) == NULL ? NULL : (((gquic_str_t *) (p))->val)\
                           )
#define GQUIC_STR_SIZE(p) (\
                           ({\
                            gquic_str_t *__str = NULL;\
                            (void) (__str == (p));\
                            }),\
                            (p) == NULL ? 0 : (((gquic_str_t *) (p))->size)\
                            )
#define GQUIC_STR_FIRST_BYTE(p) (\
                                 ({\
                                  gquic_str_t *__str = NULL;\
                                  (void) (__str == (p)); \
                                  }),\
                                  (p) == NULL ? 0 : *((u_int8_t *) GQUIC_STR_VAL((p))) \
                                  )

int gquic_str_init(gquic_str_t *str);
int gquic_str_alloc(gquic_str_t *str, size_t size);
int gquic_str_reset(gquic_str_t *str);
int gquic_str_copy(gquic_str_t *str, const gquic_str_t *ref);
int gquic_str_set(gquic_str_t *const str, const char *const val);
int gquic_str_test_echo(const gquic_str_t *const str);
int gquic_str_cmp(const gquic_str_t *const str_a, const gquic_str_t *const str_b);
int gquic_str_concat(gquic_str_t *const ret, const gquic_str_t *const a, const gquic_str_t *const b);
int gquic_str_clear(gquic_str_t *const str);

typedef gquic_str_t gquic_reader_str_t;
int gquic_reader_str_readed_size(gquic_reader_str_t *const reader, const size_t n);
u_int8_t gquic_reader_str_read_byte(gquic_reader_str_t *const reader);
int gquic_reader_str_read(gquic_str_t *const out, gquic_reader_str_t *const reader);

typedef gquic_str_t gquic_writer_str_t;
int gquic_writer_str_writed_size(gquic_writer_str_t *const writer, const size_t n);
int gquic_writer_str_write(gquic_writer_str_t *const writer, const gquic_str_t *const buf);
int gquic_writer_str_write_byte(gquic_writer_str_t *const writer, u_int8_t b);
int gquic_writer_str_write_padding(gquic_writer_str_t *const writer, u_int8_t padding_cnt, const u_int64_t padding_len);

#endif
