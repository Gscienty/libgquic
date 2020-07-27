/* include/packet/packet.h 存储发送的数据包实体
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_PACKET_H
#define _LIBGQUIC_PACKET_PACKET_H

#include "util/list.h"
#include "util/count_pointer.h"
#include "exception.h"
#include <sys/types.h>
#include <stdbool.h>

/**
 * 用于确认的数据包实体
 */
typedef struct gquic_packet_s gquic_packet_t;
struct gquic_packet_s {

    // packet number
    u_int64_t pn;

    // frames
    GQUIC_CPTR_TYPE(gquic_list_t) frames; /* void ** */

    // 最大确认数据包packet number
    u_int64_t largest_ack;

    // 数据包长度
    u_int64_t len;

    // 加密级别
    u_int8_t enc_lv;

    // 发送时间
    u_int64_t send_time;

    // 是否包含未确认数据
    bool included_infly;
};


/**
 * 暂存数据包实体初始化
 *
 * @param packet: 数据包
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_init(gquic_packet_t *const packet);

/**
 * 析构数据包
 *
 * @param packet: 数据包
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_dtor(gquic_packet_t *const packet);

/**
 * 引用计数的frames队列封装
 */
typedef struct gquic_cptr_frames_s gquic_cptr_frames_t;
struct gquic_cptr_frames_s {
    gquic_list_t frames;
    gquic_count_pointer_t cptr;
};

gquic_exception_t gquic_cptr_frames_dtor(void *const frames);

/**
 * 引用计数的数据包封装
 */
typedef struct gquic_cptr_packet_s gquic_cptr_packet_t;
struct gquic_cptr_packet_s {
    gquic_packet_t packet;
    gquic_count_pointer_t cptr;
};

gquic_exception_t gquic_cptr_packet_dtor(void *const packet);

#endif
