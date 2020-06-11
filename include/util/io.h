#ifndef _LIBGQUIC_UTIL_IO_H
#define _LIBGQUIC_UTIL_IO_H

#include "util/str.h"
#include "exception.h"

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
                              ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
                              : ((p)->writer.cb((p)->writer.self, (w))))
#define GQUIC_IO_CLOSE(co, p) (((p) == NULL || (p)->closer.self == NULL || (p)->closer.self == NULL) \
                           ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
                           : ((p)->closer.cb((co), (p)->closer.self)))

int gquic_io_init(gquic_io_t *const output);
int gquic_io_writer_implement(gquic_io_t *const output,
                              void *const self,
                              int (*cb) (void *const, gquic_writer_str_t *const));

#endif
