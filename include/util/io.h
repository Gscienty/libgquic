#ifndef _LIBGQUIC_UTIL_IO_H
#define _LIBGQUIC_UTIL_IO_H

#include "util/str.h"

typedef struct gquic_io_s gquic_io_t;
struct gquic_io_s {
    struct {
        void *self;
        int (*cb) (void *const, gquic_writer_str_t *const);
    } writer;

    struct {
        void *self;
        int (*cb) (void *const, gquic_reader_str_t *const);
    } reader;
    
    struct {
        void *self;
        int (*cb) (void *const);
    } closer;
};

#define GQUIC_IO_WRITE(p, w) (((p) == NULL || (p)->writer.self == NULL || (p)->writer.self == NULL) \
                              ? -1 \
                              : ((p)->writer.cb((p)->writer.self, (w))))

int gquic_io_init(gquic_io_t *const output);
int gquic_io_writer_implement(gquic_io_t *const output,
                              void *const self,
                              int (*cb) (void *const, gquic_writer_str_t *const));

#endif
