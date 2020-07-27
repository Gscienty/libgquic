/* include/packet/packet_number.h packet number
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_PACKET_NUMBER_H
#define _LIBGQUIC_PACKET_PACKET_NUMBER_H

#include "util/list.h"
#include "frame/ack.h"
#include "exception.h"
#include <sys/types.h>

/**
 * 获取 packet number 长度
 *
 * @param pn: packet number
 * 
 * @return: packet number
 */
static inline size_t gquic_packet_number_size(const u_int64_t pn) {
    if (pn <= 0xFF) {
        return 1;
    }
    else if (pn <= 0xFFFF) {
        return 2;
    }
    else if (pn <= 0xFFFFFF) {
        return 3;
    }
    else if (pn <= 0x3FFFFFFF) {
        return 4;
    }
    return 0;
}

/**
 * 获取packet number长度在数据包首部第一个字节中的比特位
 *
 * @param pn: packet number
 * 
 * @return: 比特位
 */
static inline u_int8_t gquic_packet_number_flag(const u_int64_t pn) {
    return gquic_packet_number_size(pn) - 1;
}


/**
 * 根据数据包首部第一个字节获取packet number长度
 *
 * @param flag: 第一个字节
 *
 * @return: packet number长度
 */
static inline size_t gquic_packet_number_flag_to_size(const u_int8_t flag) {
    return (flag & 0x03) + 1;
}

/**
 * packet number生成器
 */
typedef struct gquic_packet_number_gen_s gquic_packet_number_gen_t;
struct gquic_packet_number_gen_s {
    u_int64_t average;
    u_int64_t next;
    u_int64_t skip;
    int mem_count;
    gquic_list_t mem; /* u_int64_t */
};

/**
 * 初始化packet number生成器
 *
 * @param gen: packet number生成器
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_number_gen_init(gquic_packet_number_gen_t *const gen);

/**
 * 构造packet number生成器
 *
 * @param gen: packet number生成器
 * @param init_pn: 开始packet number
 * @param average: average参数
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_number_gen_ctor(gquic_packet_number_gen_t *const gen, const u_int64_t init_pn, const u_int64_t average);

/**
 * 析构packet number生成器
 *
 * @param gen: packet number生成器
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_number_gen_dtor(gquic_packet_number_gen_t *const gen);

/**
 * 生成一个新的忽略packet number
 * 
 * @param gen: packet number生成器
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_number_gen_new_skip(gquic_packet_number_gen_t *const gen);

/**
 * 生成一个新的packet number
 *
 * @param gen: packet number生成器
 *
 * @return pn: packet number
 * @return: exception
 */
gquic_exception_t gquic_packet_number_gen_next(u_int64_t *const pn, gquic_packet_number_gen_t *const gen);

/**
 * 判断是否为有效packet number (即在ACK frame的接收区间中不存在生成器中记录的packet number)
 *
 * @param gen: packet number生成器
 * @param blocks: ACK frames接收区间
 *
 * @return: 是否为有效packet number
 */
bool gquic_packet_number_gen_valid(gquic_packet_number_gen_t *const gen, const gquic_list_t *const blocks);

static inline int gquic_packet_number_len(const u_int64_t pn, const u_int64_t lowest_unacked) {
    const u_int64_t diff = pn - lowest_unacked;
    if (diff < (1 << 15)) {
        return 2;
    }
    if (diff < (1 << 23)) {
        return 3;
    }
    return 4;
}

#define GQUIC_PACKET_NUMBER_DELTA(a, b) (((a) > (b)) ? ((a) - (b)) : ((b) - (a)))

static inline u_int64_t gquic_packet_number_close_to(const u_int64_t target, const u_int64_t a, const u_int64_t b) {
    return GQUIC_PACKET_NUMBER_DELTA(target, a) < GQUIC_PACKET_NUMBER_DELTA(target, b) ? a : b;
}

static inline u_int64_t gquic_packet_number_decode(const int pn_len, const u_int64_t last_pn, const u_int64_t pn) {
    u_int64_t epoch_delta = 0;
    u_int64_t epoch = 0;
    u_int64_t prev_epoch_begin = 0;
    u_int64_t next_epoch_begin = 0;
    switch (pn_len) {
    case 1:
        epoch_delta = 1UL << 8;
        break;
    case 2:
        epoch_delta = 1UL << 16;
        break;
    case 3:
        epoch_delta = 1UL << 24;
        break;
    case 4:
        epoch_delta = 1UL << 32;
        break;
    }
    epoch = last_pn & ~(epoch_delta - 1);
    if (epoch > epoch_delta) {
        prev_epoch_begin = epoch - epoch_delta;
    }
    next_epoch_begin = epoch + epoch_delta;
    return gquic_packet_number_close_to(last_pn + 1, epoch + pn,
                                        gquic_packet_number_close_to(last_pn + 1, prev_epoch_begin + pn, next_epoch_begin + pn));
}

#define GQUIC_INVALID_PACKET_NUMBER ((u_int64_t) -1)

#endif
