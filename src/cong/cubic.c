/* src/cong/cubic.c cubic拥塞控制算法实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "cong/cubic.h"
#include "packet/packet_number.h"
#include "exception.h"
#include <math.h>

/**
 * cubic beta 参数
 *
 * @param cubic: congestion cubic
 *
 * @return (conn_count - 1 + 0.7) / conn_count
 */
static float gquic_cubic_beta(const gquic_cubic_t *const cubic);

/**
 * cubic alpha参数
 *
 * @param cubic: congestion cubic
 * 
 * @return 3 * conn_count^2 * (1 - beta) / (1 + beta)
 */
static float gquic_cubic_alpha(const gquic_cubic_t *const cubic);

/**
 * cubic max_beta 参数
 *
 * @param cubic: congestion cubic
 * 
 * @return (conn_count - 1 + 0.85) / conn_count
 */
static float gquic_cubic_bata_last_max(const gquic_cubic_t *const cubic);

/**
 * congestion cubic 尝试增加拥塞窗口大小
 *
 * @param cubic: congestion cubic
 * @param ack_bytes: 确认接收的数据大小
 * @param infly: 未确认接收的数据大小
 * @param event_time: 确认接收数据的时间
 *
 * @return exception
 */
static gquic_exception_t gquic_cong_cubic_try_increase_cwnd(gquic_cong_cubic_t *const cubic,
                                                            const u_int64_t ack_bytes, const u_int64_t infly, const u_int64_t event_time);

/**
 * 判断当前状态是否被拥塞窗口限制不予发送
 * 
 * @param cubic: congestion cubic
 * @param infly_bytes: 未确认数据大小
 *
 * @return 是否被拥塞窗口限制
 */
static bool gquic_cong_cubic_is_cwnd_limited(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes);


gquic_exception_t gquic_cubic_init(gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cubic->conn_count = 1;
    cubic->epoch = 0;
    cubic->last_max_cwnd = 0;
    cubic->ack_bytes_count = 0;
    cubic->reno_cwnd = 0;
    cubic->origin_point_cwnd = 0;
    cubic->origin_point_time = 0;
    cubic->last_target_cwnd = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_cubic_ctor(gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    cubic->conn_count = 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static float gquic_cubic_beta(const gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    return (cubic->conn_count - 1 + 0.7) / cubic->conn_count;
}

static float gquic_cubic_alpha(const gquic_cubic_t *const cubic) {
    float b = 0;
    if (cubic == NULL) {
        return 0;
    }
    b = gquic_cubic_beta(cubic);
    return 3 * cubic->conn_count * cubic->conn_count * (1 - b) / (1 + b);
}

static float gquic_cubic_bata_last_max(const gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    return (cubic->conn_count - 1 + 0.85) / cubic->conn_count;
}

u_int64_t gquic_cubic_cwnd_after_packet_loss(gquic_cubic_t *const cubic, const u_int64_t cwnd) {
    if (cubic == NULL) {
        return 0;
    }

    // 当发生丢包时，判断当前拥塞窗口与记录中最大拥塞窗口大小
    if (cwnd + 1460 < cubic->last_max_cwnd) {
        // 拥塞窗口不足够大时
        // 最大拥塞窗口以max_beta的比例下降
        cubic->last_max_cwnd = gquic_cubic_bata_last_max(cubic) * cwnd;
    }
    else {
        // 拥塞窗口足够大时
        // 最大拥塞窗口即为当前窗口
        cubic->last_max_cwnd = cwnd;
    }

    // 将epoch置为0,标记着一个新的恢复周期的开始
    cubic->epoch = 0;

    // 将当前拥塞窗口以beta为比例下降
    return cwnd * gquic_cubic_beta(cubic);
}

static inline u_int64_t __DELTA__(const u_int64_t a, const u_int64_t b) {
    return a > b ? a - b : b - a;
}

u_int64_t gquic_cubic_cwnd_after_packet_ack(gquic_cubic_t *const cubic,
                                            const u_int64_t acked_bytes, const u_int64_t cwnd, const u_int64_t delay_min, const u_int64_t event_time) {
    u_int64_t elapsed_time = 0;
    int64_t offset = 0;
    u_int64_t delta_cwnd = 0;
    u_int64_t ret = 0;
    if (cubic == NULL) {
        return 0;
    }

    // 判断当前恢复阶段是否为一个新的周期
    if (cubic->epoch == 0) {
        // 如果为新的周期
        // 记录新周期开始时间，当前拥塞窗口，并设置cubic的原点（时间/拥塞窗口）
        cubic->epoch = event_time;
        cubic->ack_bytes_count = acked_bytes;
        cubic->reno_cwnd = cwnd;
        if (cubic->last_max_cwnd <= cwnd) {
            cubic->origin_point_time = 0;
            cubic->origin_point_cwnd = cwnd;
        }
        else {
            cubic->origin_point_time = cbrt((1L << 40) / 410 / 1460 * (cubic->last_max_cwnd - cwnd));
            cubic->origin_point_cwnd = cubic->last_max_cwnd;
        }
    }
    else {
        cubic->ack_bytes_count += acked_bytes;
    }

    // 根据cubic算法中三次曲线在原点处旋转对称的特点
    // 计算获得对应的下一个拥塞控制窗口大小
    elapsed_time = ((event_time + delay_min - cubic->epoch) << 10) / (1000 * 1000);
    offset = __DELTA__(cubic->origin_point_time, elapsed_time);
    delta_cwnd = ((410 * offset * offset * offset) * 1460) >> 40;
    if (elapsed_time > cubic->origin_point_time) {
        ret = cubic->origin_point_cwnd + delta_cwnd;
    }
    else {
        ret = cubic->origin_point_cwnd - delta_cwnd;
    }
    // 将拥塞控制窗口的增长上限限制在确认接收数据大小的一半
    ret = ret < cwnd + cubic->ack_bytes_count / 2 ? ret : cwnd + cubic->ack_bytes_count / 2;

    cubic->reno_cwnd += cubic->ack_bytes_count * gquic_cubic_alpha(cubic) * 1460 / cubic->reno_cwnd;
    cubic->ack_bytes_count = 0;
    cubic->last_target_cwnd = ret;

    // 选择cubic和reno中最大的作为下一个拥塞窗口
    return ret > cubic->reno_cwnd ? ret : cubic->reno_cwnd;
}

gquic_exception_t gquic_cong_cubic_init(gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_cong_hybrid_slow_start_init(&cubic->hybrid_slow_start);
    gquic_prr_init(&cubic->prr);
    cubic->rtt = NULL;
    gquic_cubic_init(&cubic->cubic);
    cubic->stat.lost_bytes = 0;
    cubic->stat.lost_packets = 0;
    cubic->disable_prr = false;
    cubic->largest_sent_pn = GQUIC_INVALID_PACKET_NUMBER;
    cubic->largest_acked_pn = GQUIC_INVALID_PACKET_NUMBER;
    cubic->at_loss.largest_sent = GQUIC_INVALID_PACKET_NUMBER;
    cubic->at_loss.in_slow_start = false;
    cubic->slow_start_large_reduction = false;
    cubic->cwnd = 0;
    cubic->min_cwnd = 2 * 1460;
    cubic->max_cwnd = 0;
    cubic->slow_start_threshold = 0;
    cubic->conn_count = 0;
    cubic->acked_packets_count = 0;
    cubic->initial_cwnd = 0;
    cubic->initial_max_cwnd = 0;
    cubic->min_slow_start_exit_wnd = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_cong_cubic_ctor(gquic_cong_cubic_t *const cubic,
                                        const gquic_rtt_t *const rtt, const u_int64_t initial_cwnd, const u_int64_t initial_max_cwnd) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cubic->initial_cwnd = initial_cwnd;
    cubic->initial_max_cwnd = initial_max_cwnd;
    cubic->cwnd = initial_cwnd;
    cubic->min_cwnd = 1460 * 2;
    cubic->slow_start_threshold = initial_max_cwnd;
    cubic->max_cwnd = initial_max_cwnd;
    cubic->conn_count = 1;
    cubic->rtt = rtt;
    gquic_cubic_ctor(&cubic->cubic);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int64_t gquic_cong_cubic_time_util_send(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes) {
    if (cubic == NULL) {
        return 0;
    }
    if (!cubic->disable_prr && gquic_cong_cubic_in_recovery(cubic)) {
        if (gquic_prr_allowable_send(&cubic->prr, cubic->cwnd, infly_bytes, cubic->slow_start_threshold)) {
            return 0;
        }
    }
    return cubic->rtt->smooth * 1460 / (2 * cubic->cwnd);
}

gquic_exception_t gquic_cong_cubic_on_packet_sent(gquic_cong_cubic_t *const cubic, const u_int64_t pn, const u_int64_t bytes, bool is_retrans) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!is_retrans) {
        // 如果不是重发packet，则不会触发更新机制
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    if (gquic_cong_cubic_in_recovery(cubic)) {
        // 当重发packet，且当前状态为恢复状态时，prr进行累计发送的数据大小
        cubic->prr.sent_bytes += bytes;
    }
    cubic->largest_sent_pn = pn;
    cubic->hybrid_slow_start.last_sent_pn = pn;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_cong_cubic_allowable_send(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes) {
    if (cubic == NULL) {
        return false;
    }
    if (!cubic->disable_prr && gquic_cong_cubic_in_recovery(cubic)) {
        return gquic_prr_allowable_send(&cubic->prr, cubic->cwnd, infly_bytes, cubic->slow_start_threshold);
    }
    return infly_bytes < cubic->cwnd;
}

gquic_exception_t gquic_cong_cubic_on_packet_acked(gquic_cong_cubic_t *const cubic,
                                                   const u_int64_t pn, const u_int64_t acked_bytes, const u_int64_t infly, const u_int64_t event_time) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (cubic->largest_acked_pn == GQUIC_INVALID_PACKET_NUMBER) {
        cubic->largest_acked_pn = pn;
    }
    else {
        cubic->largest_acked_pn = pn > cubic->largest_acked_pn ? pn : cubic->largest_acked_pn;
    }
    if (gquic_cong_cubic_in_recovery(cubic)) {
        if (!cubic->disable_prr) {
            cubic->prr.delivered_bytes += acked_bytes;
            cubic->prr.ack_count++;
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    gquic_cong_cubic_try_increase_cwnd(cubic, acked_bytes, infly, event_time);
    if (gquic_cong_cubic_in_slow_start(cubic)) {
        if (cubic->hybrid_slow_start.end_pn < pn) {
            cubic->hybrid_slow_start.started = 0;
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_cong_cubic_try_increase_cwnd(gquic_cong_cubic_t *const cubic,
                                                            const u_int64_t ack_bytes, const u_int64_t infly, const u_int64_t event_time) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (!gquic_cong_cubic_is_cwnd_limited(cubic, infly)) {
        cubic->cubic.epoch = 0;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (cubic->cwnd >= cubic->max_cwnd) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (gquic_cong_cubic_in_slow_start(cubic)) {
        cubic->cwnd += 1460;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    cubic->cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic->cubic, ack_bytes, cubic->cwnd, cubic->rtt->min, event_time);
    cubic->cwnd = cubic->cwnd < cubic->max_cwnd ? cubic->cwnd : cubic->max_cwnd;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static bool gquic_cong_cubic_is_cwnd_limited(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes) {
    u_int64_t avail_bytes = 0;
    if (cubic == NULL) {
        return false;
    }
    if (infly_bytes >= cubic->cwnd) {
        return true;
    }
    avail_bytes = cubic->cwnd - infly_bytes;

    return (gquic_cong_cubic_in_slow_start(cubic) && infly_bytes > cubic->cwnd / 2) || avail_bytes <= 3 * 1460;
}

gquic_exception_t gquic_cong_cubic_on_packet_lost(gquic_cong_cubic_t *const cubic,
                                                  const u_int64_t pn, const u_int64_t lost_bytes, const u_int64_t infly) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (cubic->at_loss.largest_sent != GQUIC_INVALID_PACKET_NUMBER && pn <= cubic->at_loss.largest_sent) {
        if (cubic->at_loss.in_slow_start) {
            cubic->stat.lost_packets++;
            cubic->stat.lost_bytes += lost_bytes;
            if (cubic->slow_start_large_reduction) {
                cubic->cwnd = cubic->cwnd - lost_bytes;
                cubic->cwnd = cubic->cwnd > cubic->min_slow_start_exit_wnd ? cubic->cwnd : cubic->min_slow_start_exit_wnd;
                cubic->slow_start_threshold = cubic->cwnd;
            }
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    cubic->at_loss.in_slow_start = gquic_cong_cubic_in_slow_start(cubic);
    if (gquic_cong_cubic_in_slow_start(cubic)) {
        cubic->stat.lost_packets++;
    }
    if (!cubic->disable_prr) {
        gquic_prr_packet_lost(&cubic->prr, infly);
    }
    if (cubic->slow_start_large_reduction && gquic_cong_cubic_in_slow_start(cubic)) {
        if (cubic->cwnd >= 2 * cubic->initial_cwnd) {
            cubic->min_slow_start_exit_wnd = cubic->cwnd / 2;
        }
        cubic->cwnd -= 1460;
    }
    else {
        cubic->cwnd = gquic_cubic_cwnd_after_packet_loss(&cubic->cubic, cubic->cwnd);
    }
    if (cubic->cwnd < cubic->min_cwnd) {
        cubic->cwnd = cubic->min_cwnd;
    }
    cubic->slow_start_threshold = cubic->cwnd;
    cubic->at_loss.largest_sent = cubic->largest_sent_pn;
    cubic->acked_packets_count = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

