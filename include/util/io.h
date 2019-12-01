#ifndef _LIBGQUIC_UTIL_IO_H
#define _LIBGQUIC_UTIL_IO_H

#include "util/str.h"

typedef struct gquic_io_s gquic_io_t;
struct gquic_io_s {
    void *self;
    int (*write) (size_t *const, void *const, const gquic_str_t *const);
    int (*read) (size_t *const, void *const, const gquic_str_t *const);
};

int gquic_io_init(gquic_io_t *const output);

#endif
