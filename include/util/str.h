#ifndef _LIBGQUIC_UTIL_STR_H
#define _LIBGQUIC_UTIL_STR_H

#include <sys/types.h>

typedef struct gquic_str_s gquic_str_t;
struct gquic_str_s {
    size_t size;
    void *val;
};

#define GQUIC_STR_VAL(p) ({\
                          gquic_str_t *_ = NULL; \
                          ((p) == _); \
                          (p) == NULL ? NULL : (((gquic_str_t *) (p))->val);\
                          })
#define GQUIC_STR_SIZE(p) ({\
                          gquic_str_t *_ = NULL; \
                          ((p) == _); \
                          (p) == NULL ? 0 : (((gquic_str_t *) (p))->size);\
                           })

int gquic_str_init(gquic_str_t *str);

int gquic_str_alloc(gquic_str_t *str, size_t size);

int gquic_str_reset(gquic_str_t *str);

int gquic_str_copy(gquic_str_t *str, const gquic_str_t *ref);

int gquic_str_set(gquic_str_t *const str, const char *const val);

int gquic_str_test_echo(const gquic_str_t *const str);

int gquic_str_cmp(const gquic_str_t *const str_a, const gquic_str_t *const str_b);

#endif
