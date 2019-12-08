#ifndef _LIBGQUIC_UTIL_IO_H
#define _LIBGQUIC_UTIL_IO_H

#include "util/str.h"

typedef struct gquic_io_s gquic_io_t;
struct gquic_io_s {
    void *self;
    int (*write) (size_t *const, void *const, const gquic_str_t *const);
    int (*read) (size_t *const, gquic_str_t *const, void *const);
};

#define GQUIC_IO_WRITE(r, p, s) (((p) == NULL || (p)->write == NULL || (p)->self == NULL) ? -1 : ((p)->write((r), (p)->self, (s))))
#define GQUIC_IO_READ(r, s, p) (((p) == NULL || (p)->read == NULL || (p)->self == NULL) ? -1 : ((p)->read((r), (s), (p)->self)))

int gquic_io_init(gquic_io_t *const output);

#endif
