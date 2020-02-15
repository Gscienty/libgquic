#include "util/io.h"
#include <stddef.h>

int gquic_io_init(gquic_io_t *const io) {
    if (io == NULL) {
        return -1;
    }
    io->writer.cb = NULL;
    io->writer.self = NULL;
    return 0;
}

int gquic_io_implement(gquic_io_t *const output,
                       void *const self,
                       int (*cb) (void *const, gquic_writer_str_t *const)) {
    if (output == NULL || self == NULL || cb == NULL) {
        return -1;
    }
    output->writer.cb = cb;
    output->writer.self = self;

    return 0;
}
