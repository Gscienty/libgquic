/* include/packet/packet_pool.h 数据包内存池
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_PACKET_POOL_H
#define _LIBGQUIC_PACKET_PACKET_POOL_H

#include "util/count_pointer.h"
#include "util/str.h"

typedef struct gquic_packet_buffer_s gquic_packet_buffer_t;
struct gquic_packet_buffer_s {
    gquic_str_t slice;
    gquic_writer_str_t writer;
};

typedef struct gquic_cptr_packet_buffer_s gquic_cptr_packet_buffer_t;
struct gquic_cptr_packet_buffer_s {
    gquic_packet_buffer_t buffer;
    gquic_count_pointer_t cptr;
};


/**
 * 从数据包内存池中获取一块存储数据包的内存
 *
 * @return buffer_storage: 数据包内存块
 * @return: exception
 */
gquic_exception_t gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage);

/**
 * 归还内存区域
 *
 * @param buffer: 数据包内存块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer);

/**
 * 内存块赋值
 *
 * @param buffer: 内存块
 * 
 * @return buffer_storage: 内存块
 * @return exception
 */
gquic_exception_t gquic_packet_buffer_assign(gquic_packet_buffer_t **const buffer_storage, gquic_packet_buffer_t *const buffer);

#endif
