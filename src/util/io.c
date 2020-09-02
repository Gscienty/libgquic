/* src/util/io.c I/O抽象接口
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "util/io.h"
#include "exception.h"
#include <stddef.h>

gquic_exception_t gquic_io_init(gquic_io_t *const io) {
    if (io == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    io->writer.cb = NULL;
    io->writer.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_io_writer_implement(gquic_io_t *const io,
                                            void *const self,
                                            gquic_exception_t (*cb) (void *const, gquic_writer_str_t *const)) {
    if (io == NULL || self == NULL || cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    io->writer.cb = cb;
    io->writer.self = self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
