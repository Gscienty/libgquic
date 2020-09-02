/* include/util/io.h I/O抽象接口
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_UTIL_IO_H
#define _LIBGQUIC_UTIL_IO_H

#include "util/str.h"
#include "exception.h"

/**
 * I/O抽象接口
 */
typedef struct gquic_io_s gquic_io_t;
struct gquic_io_s {
    struct {
        void *self;
        int (*cb) (void *const, gquic_reader_str_t *const);
    } writer;

    struct {
        void *self;
        int (*cb) (void *const, gquic_writer_str_t *const);
    } reader;
    
    struct {
        void *self;
        int (*cb) (void *const);
    } closer;
};

#define GQUIC_IO_WRITE(p, w) (((p) == NULL || (p)->writer.self == NULL || (p)->writer.self == NULL) \
                              ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
                              : ((p)->writer.cb((p)->writer.self, (w))))
#define GQUIC_IO_CLOSE(p) (((p) == NULL || (p)->closer.self == NULL || (p)->closer.self == NULL) \
                           ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
                           : ((p)->closer.cb((p)->closer.self)))

/**
 * 初始化I/O接口
 *
 * @param io: I/O接口
 *
 * @return: exception
 */
gquic_exception_t gquic_io_init(gquic_io_t *const io);

/**
 * 抽象写操作
 *
 * @param io: I/O接口
 * @param self: 写操作self参数
 * @param cb: 写操作
 */
gquic_exception_t gquic_io_writer_implement(gquic_io_t *const io,
                                            void *const self,
                                            gquic_exception_t (*cb) (void *const, gquic_writer_str_t *const));

#endif
