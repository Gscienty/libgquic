#include "util/io.h"
#include "exception.h"
#include <stddef.h>

int gquic_io_init(gquic_io_t *const io) {
    if (io == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    io->writer.cb = NULL;
    io->writer.self = NULL;
    return GQUIC_SUCCESS;
}

int gquic_io_writer_implement(gquic_io_t *const output,
                              void *const self,
                              int (*cb) (void *const, gquic_writer_str_t *const)) {
    if (output == NULL || self == NULL || cb == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    output->writer.cb = cb;
    output->writer.self = self;

    return GQUIC_SUCCESS;
}
