/* include/flowcontrol/base.h 流量控制基础模块声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FLOWCONTROL_BASE_H
#define _LIBGQUIC_FLOWCONTROL_BASE_H

#include "util/rtt.h"
#include "util/time.h"
#include "exception.h"
#include <sys/types.h>
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * 流量控制基础模块
 */
typedef struct gquic_flowcontrol_base_s gquic_flowcontrol_base_t;
struct gquic_flowcontrol_base_s {

    pthread_mutex_t mtx;

    // 已发送的数据大小
    u_int64_t sent_bytes;

    // 发送窗口
    u_int64_t swnd;

    // 被阻塞时发送数据的偏移量
    u_int64_t last_blocked_at;

    // 已读取的数据大小
    u_int64_t read_bytes;

    // 最大可接受的数据大小
    u_int64_t highest_recv;

    // 接收窗口
    u_int64_t rwnd;

    // 接收窗口容量
    u_int64_t rwnd_size;

    // 最大接收窗口容量
    u_int64_t max_rwnd_size;

    // 流量控制开始时间
    u_int64_t epoch_time;

    // 流量控制开始时已读取的数据大小
    u_int64_t epoch_off;

    // RTT
    const gquic_rtt_t *rtt;
};

/**
 * 基础流量控制模块初始化
 *
 * @param base: base
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_base_init(gquic_flowcontrol_base_t *const base);

/**
 * 析构基础流量控制模块
 *
 * @param base: base
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_base_dtor(gquic_flowcontrol_base_t *const base);

/**
 * 判断是否阻塞发送
 *
 * @param base: base
 * 
 * @return swnd: 阻塞发生时的发送窗口大小
 * @return: exception
 */
bool gquic_flowcontrol_base_is_newly_blocked(u_int64_t *const swnd, gquic_flowcontrol_base_t *const base);

/**
 * 尝试更新流量控制模块中的接收窗口，并返回调整后的接收窗口
 *
 * @param base: base
 *
 * @return: 新的接收窗口大小
 */
u_int64_t gquic_flowcontrol_base_get_wnd_update(gquic_flowcontrol_base_t *const base);

/**
 * 流量控制处理读取指定数据量的处理
 *
 * @param base: base
 * @param bytes: 读取的数据大小
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_flowcontrol_base_read_add_bytes(gquic_flowcontrol_base_t *const base, const u_int64_t bytes) {
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&base->mtx);
    if (base->read_bytes == 0) {
        base->epoch_time = gquic_time_now();
        base->epoch_off = base->read_bytes;
    }
    base->read_bytes += bytes;
    pthread_mutex_unlock(&base->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

/**
 * 流量控制处理发送指定的数据量
 *
 * @param base: base
 * @param bytes: 发送的数据大小
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_flowcontrol_base_sent_add_bytes(gquic_flowcontrol_base_t *const base, const u_int64_t bytes) {
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    base->sent_bytes += bytes;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

/**
 * 通过基础流量控制模块判断接收窗口是否需要更新
 *
 * @param base: base
 * 
 * @return: 是否需要更新
 */
static inline bool gquic_flowcontrol_base_has_wnd_update(const gquic_flowcontrol_base_t *const base) {
    if (base == NULL) {
        return false;
    }

    return base->rwnd - base->read_bytes <= base->rwnd_size * 0.75;
}

/**
 * 更新基础流量控制模块的发送窗口
 *
 * @param base: base
 * @param off: 新的发送窗口
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_flowcontrol_base_update_swnd(gquic_flowcontrol_base_t *const base, const u_int64_t off) {
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (off > base->swnd) {
        base->swnd = off;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

/**
 * 获取基础流量控制模块中发送窗口大小
 * 
 * @param base: base
 *
 * @return: 发送窗口大小
 */
static inline u_int64_t gquic_flowcontrol_base_swnd_size(const gquic_flowcontrol_base_t *const base) {
    if (base == NULL) {
        return 0;
    }
    if (base->sent_bytes > base->swnd) {
        return 0;
    }
    return base->swnd - base->sent_bytes;
}


#endif
