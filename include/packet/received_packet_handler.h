/* include/packet/received_packet_handler.h 接收数据包处理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_RECEIVED_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_RECEIVED_PACKET_HANDLER_H

#include "util/list.h"
#include "util/rtt.h"
#include "frame/ack.h"
#include "exception.h"
#include <sys/types.h>

/**
 * 接收到的数据包空隙区间实体
 */
typedef struct gquic_packet_interval_s gquic_packet_interval_t;
struct gquic_packet_interval_s {

    // 区间开始的packet number
    u_int64_t start;

    // 区间结束的packet number
    u_int64_t end;
};

/**
 * 接收数据包空隙区间容器
 */
typedef struct gquic_packet_received_mem_s gquic_packet_received_mem_t;
struct gquic_packet_received_mem_s {

    // 区间个数
    int ranges_count;

    // 区间列表
    gquic_list_t ranges; /* gquic_packet_interval_t */

    // packet number 忽略门限
    u_int64_t deleted_below;
};

/**
 * 接收数据包空隙区间容器初始化
 *
 * @param mem: 容器
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_mem_init(gquic_packet_received_mem_t *const mem);

/**
 * 析构接收数据包空隙区间容器
 *
 * @param mem: 容器
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_mem_dtor(gquic_packet_received_mem_t *const mem);

/**
 * 接收数据包空隙区间容器接收一个packet number
 *
 * @param mem: 容器
 * @param pn: packet number
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_reveived_mem_received(gquic_packet_received_mem_t *const mem, const u_int64_t pn);

/**
 * 设定接收数据包空隙区间容器packet number忽略门限
 *
 * @param mem: 容器
 * @param pn: packet number门限
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_mem_delete_below(gquic_packet_received_mem_t *const mem, const u_int64_t pn);

/**
 * 获取接收数据包空隙区间
 *
 * @param mem: 容器
 *
 * @return blocks: 接收数据包区间
 * @return: exception
 */
gquic_exception_t gquic_packet_received_mem_get_blocks(gquic_list_t *const blocks, const gquic_packet_received_mem_t *const mem);


/**
 * 接收数据包处理模块
 */
typedef struct gquic_packet_received_packet_handler_s gquic_packet_received_packet_handler_t;
struct gquic_packet_received_packet_handler_s {

    // 接收到的最大数据包packet number
    u_int64_t largest_observed;

    // 忽略packet number门限
    u_int64_t ignore_below;

    // 接收到最大数据包时的时间
    u_int64_t largest_obeserved_time;

    // 接收数据包空隙区间容器
    gquic_packet_received_mem_t mem;

    // 最大确认延迟时间
    u_int64_t max_ack_delay;

    // RTT
    const gquic_rtt_t *rtt;

    // 在最后确认后的接收数据包内容记录
    struct {
        int packets_count;
        int ack_eliciting_count;
    } since_last_ack;

    // 确认是否要发送ACK frame
    bool ack_queued;

    // 确认超时时间
    u_int64_t ack_alarm;

    // 最新的确认帧
    gquic_frame_ack_t *last_ack;
};

/**
 * 初始化接收数据包处理模块
 *
 * @param handler: handler
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handler_init(gquic_packet_received_packet_handler_t *const handler);

/**
 * 构造接收数据包处理模块
 *
 * @param handler: handler
 * @param rtt: rtt
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handler_ctor(gquic_packet_received_packet_handler_t *const handler, gquic_rtt_t *const rtt);

/**
 * 析构接收数据包处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handler_dtor(gquic_packet_received_packet_handler_t *const handler);

/**
 * 接收一个数据包时的处理
 *
 * @param handler: handler
 * @param pn: packet number
 * @param recv_time: 接收时间
 * @param should_inst_ack: 是否需要确认该数据包
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handler_received_packet(gquic_packet_received_packet_handler_t *const handler,
                                                                       const u_int64_t pn, const u_int64_t recv_time, const bool should_inst_ack);

/**
 * 获取一个确认帧
 *
 * @param handler: handler
 * 
 * @return ack: ACK frame
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handler_get_ack_frame(gquic_frame_ack_t **const ack,
                                                                     gquic_packet_received_packet_handler_t *const handler);

/**
 * 设定忽略packet number门限
 *
 * @param handler: handler
 * @param pn: packet number
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handler_ignore_below(gquic_packet_received_packet_handler_t *const handler, const u_int64_t pn);

/**
 * 接收数据包处理模块
 */
typedef struct gquic_packet_received_packet_handlers_s gquic_packet_received_packet_handlers_t;
struct gquic_packet_received_packet_handlers_s {
    gquic_packet_received_packet_handler_t initial;
    gquic_packet_received_packet_handler_t handshake;
    gquic_packet_received_packet_handler_t one_rtt;

    bool initial_dropped;
    bool handshake_dropped;
    bool one_rtt_dropped;
};

/**
 * 初始化接收数据包处理模块
 *
 * @param handler: handler
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_init(gquic_packet_received_packet_handlers_t *const handlers);

/**
 * 构造接收数据包处理模块
 *
 * @param handler: handler
 * @param rtt: rtt
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_ctor(gquic_packet_received_packet_handlers_t *const handlers, gquic_rtt_t *const rtt);

/**
 * 析构接收数据包处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_dtor(gquic_packet_received_packet_handlers_t *const handlers);

/**
 * 接收一个数据包时的处理
 *
 * @param handler: handler
 * @param pn: packet number
 * @param recv_time: 接收时间
 * @param should_inst_ack: 是否需要确认该数据包
 * @param enc_lv: 加密级别
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_received_packet(gquic_packet_received_packet_handlers_t *const handler,
                                                                        const u_int64_t pn, const u_int64_t recv_time, const bool should_inst_ack,
                                                                        const u_int8_t enc_lv);

/**
 * 设定忽略packet number门限
 *
 * @param handler: handler
 * @param pn: packet number
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_ignore_below(gquic_packet_received_packet_handlers_t *const handlers, const u_int64_t pn);

/**
 * 丢弃一个加密级别的数据包接收处理模块
 *
 * @param handlers: handlers
 * @param enc_lv: 加密级别
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_drop_packets(gquic_packet_received_packet_handlers_t *const handlers, const u_int8_t enc_lv);

/**
 * 获取超时时间
 *
 * @param handlers: handlers
 * 
 * @return: 超时时间
 */
u_int64_t gquic_packet_received_packet_handlers_get_alarm_timeout(gquic_packet_received_packet_handlers_t *const handlers);

/**
 * 获取一个确认帧
 *
 * @param handler: handler
 * @param enc_lv: 加密级别
 * 
 * @return ack: ACK frame
 * @return: exception
 */
gquic_exception_t gquic_packet_received_packet_handlers_get_ack_frame(gquic_frame_ack_t **const ack,
                                                                      gquic_packet_received_packet_handlers_t *const handlers, const u_int8_t enc_lv);

#endif
