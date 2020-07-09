/* include/frame/ack.h ACK frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_ACK_H
#define _LIBGQUIC_FRAME_ACK_H

#include "util/varint.h"
#include "util/list.h"
#include "exception.h"
#include <stdbool.h>

typedef struct gquic_frame_ack_ecn_s gquic_frame_ack_ecn_t;
struct gquic_frame_ack_ecn_s {
    u_int64_t ect[2];
    u_int64_t ecn_ce;
};

typedef struct gquic_frame_ack_s gquic_frame_ack_t;
struct gquic_frame_ack_s {
    u_int64_t largest_ack;
    u_int64_t delay;
    u_int64_t count;
    u_int64_t first_range;

    gquic_list_t ranges;

    gquic_frame_ack_ecn_t ecn;
};

typedef struct gquic_frame_ack_range_s gquic_frame_ack_range_t;
struct gquic_frame_ack_range_s {
    u_int64_t gap;
    u_int64_t range;
};

/**
 * ACK frame range元素
 *
 * @param range: range
 * 
 * @return: exception
 */
gquic_exception_t gquic_frame_ack_range_init(gquic_frame_ack_range_t *const range);

/**
 * ACK frame 区间元素
 */
typedef struct gquic_frame_ack_block_s gquic_frame_ack_block_t;
struct gquic_frame_ack_block_s {
    u_int64_t smallest;
    u_int64_t largest;
};

/**
 * 生成ACK frame
 *
 * @return frame_storage: frame
 * @return: exception
 */
gquic_exception_t gquic_frame_ack_alloc(gquic_frame_ack_t **const frame_storage);

/**
 * 判断ACK接收的区间中是否包含对应的packet number
 *
 * @param blocks: 接收的区间列表
 * @param pn: packet number
 *
 * @return 是否包含对应的packet number
 */
bool gquic_frame_ack_blocks_contain_packet(const gquic_list_t *const blocks, const u_int64_t pn);

/**
 * 将ACK frame中的range转换为接收区间列表
 *
 * @param spec: ACK frame
 *
 * @return blocks: 接收区间列表
 * @return: exception
 */
gquic_exception_t gquic_frame_ack_ranges_to_blocks(gquic_list_t *const blocks, const gquic_frame_ack_t *const spec);

/**
 * 将接收区间填充到ACK frame中
 *
 * @param blocks: 接收区间
 *
 * @return spec: ACK frame
 * @return: exception
 */
gquic_exception_t gquic_frame_ack_ranges_from_blocks(gquic_frame_ack_t *const spec, const gquic_list_t *const blocks);

/**
 * 判断frame集合中是否包含ACK frame
 *
 * @param frames: frame集合
 * 
 * @return: 是否包含ACK frame
 */
bool gquic_frames_has_frame_ack(gquic_list_t *const frames);

#endif
