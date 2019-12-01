#include "util/io.h"
#include <stddef.h>

int gquic_io_init(gquic_io_t *const io) {
    if (io == NULL) {
        return -1;
    }
    io->read = NULL;
    io->write = NULL;
    io->self = NULL;
    return 0;
}
