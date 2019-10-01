#ifndef _LIBGQUIC_UTIL_STR_H
#define _LIBGQUIC_UTIL_STR_H

#include <sys/types.h>

typedef struct gquic_str_s gquic_str_t;
struct gquic_str_s {
    size_t size;
    void *val;
};

#define GQUIC_STR_VAL(p) (((gquic_str_t *) (p))->val)
#define GQUIC_STR_SIZE(p) (((gquic_str_t *) (p))->size)

int gquic_str_init(gquic_str_t *str);

int gquic_str_alloc(gquic_str_t *str, size_t size);

int gquic_str_reset(gquic_str_t *str);

#endif
