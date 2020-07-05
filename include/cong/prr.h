/* include/cong/prr.h 快速恢复模块定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_CONG_PRR_H
#define _LIBGQUIC_CONG_PRR_H

#include "exception.h"
#include <sys/types.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * 快速恢复实现模块
 */
typedef struct gquic_prr_s gquic_prr_t;
struct gquic_prr_s {

    // 已发送的数据大小
    u_int64_t sent_bytes;

    // 已成功接收的数据大小
    u_int64_t delivered_bytes;

    // 已成功接收次数
    u_int64_t ack_count;

    // 尚未接收的数据大小
    u_int64_t infly_bytes;
};

/**
 * 初始化快速恢复实现模块
 *
 * @param prr: prr
 * 
 * @return exception
 */
gquic_exception_t gquic_prr_init(gquic_prr_t *const prr);

/**
 * 当QUIC探知丢包时，快速恢复模块触发执行
 *
 * @param prr: prr
 * @param infly: 尚未确认接收的数据大小
 *
 * @return: exception
 */
gquic_exception_t gquic_prr_packet_lost(gquic_prr_t *const prr, const u_int64_t infly);

/**
 * 判断快速恢复模块是否允许发送数据
 *
 * @param prr: prr
 * @param cwnd: 当前拥塞窗口
 * @param infly: 未确认接收的数据大小
 * @param slowstart_thd: 慢启动门限
 *
 * @return: 是否允许发送数据
 */
bool gquic_prr_allowable_send(gquic_prr_t *const prr, const u_int64_t cwnd, const u_int64_t infly, const u_int64_t slowstart_thd);

/**
 * 快速恢复阶段接收到ACK frame
 *
 * @param prr: prr
 * @param ack_bytes: 确认接收的数据大小
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_prr_packet_acked(gquic_prr_t *const prr, const u_int64_t ack_bytes) {
    if (prr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    prr->delivered_bytes += ack_bytes;
    prr->ack_count++;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

/**
 * 快速恢复阶段发送指定数据大小
 *
 * @param prr: prr
 * @param sent_bytes: 发送的数据大小
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_prr_packet_sent(gquic_prr_t *const prr, const u_int64_t sent_bytes) {
    if (prr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    prr->sent_bytes += sent_bytes;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
