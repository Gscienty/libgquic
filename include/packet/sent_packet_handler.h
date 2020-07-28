/* include/packet/sent_packet_handler.h 数据包发送处理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H

#include "packet/packet.h"
#include "packet/packet_number.h"
#include "util/list.h"
#include "util/rbtree.h"
#include "cong/cubic.h"
#include "frame/ack.h"
#include "exception.h"

/**
 * 发送过的数据包存储模块
 */
typedef struct gquic_packet_sent_mem_s gquic_packet_sent_mem_t;
struct gquic_packet_sent_mem_s {
    
    // 存储的数据包数量
    int count;

    // 存储队列
    gquic_list_t list; /* GQUIC_CPTR_TYPE(gquic_packet_t) */

    // 索引
    gquic_rbtree_t *root;
};

/**
 * 数据包存储模块初始化
 *
 * @param mem: 存储模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_mem_init(gquic_packet_sent_mem_t *const mem);

/**
 * 析构数据包存储模块
 *
 * @param mem: 存储模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_mem_dtor(gquic_packet_sent_mem_t *const mem);

/**
 * 向数据包存储模块中存储一个发送的数据包
 *
 * @param mem: 存储模块
 * @param packet: 数据包
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_mem_sent_packet(gquic_packet_sent_mem_t *const mem, const GQUIC_CPTR_TYPE(gquic_packet_t) const packet);

/**
 * 从数据包存储模块中获取一个数据包
 *
 * @param mem: 存储模块
 * @param pn: packet number
 * 
 * @return packet: 数据包
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_mem_get_packet(const GQUIC_CPTR_TYPE(gquic_packet_t) *const packet,
                                                   gquic_packet_sent_mem_t *const mem, const u_int64_t pn);

/**
 * 从数据包存储模块中删除一个数据包
 *
 * @param mem: 存储模块
 * @param pn: packet number
 * @param release_packet_func: 删除数据包的回调函数
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_mem_remove(gquic_packet_sent_mem_t *const mem, const u_int64_t pn,
                                               gquic_exception_t (*release_packet_func) (GQUIC_CPTR_TYPE(gquic_packet_t) const));

/**
 * 判断数据包存储模块是否为空
 *
 * @param mem: 存储模块
 *
 * @return: exception
 */
static inline bool gquic_packet_sent_mem_empty(const gquic_packet_sent_mem_t *const mem) {
    if (mem == NULL) {
        return false;
    }
    return mem->count == 0;
}

/**
 * packet number空间处理模块
 */
typedef struct gquic_packet_sent_pn_s gquic_packet_sent_pn_t;
struct gquic_packet_sent_pn_s {

    // 发送数据包存储模块
    gquic_packet_sent_mem_t mem;

    // packet number生成器
    gquic_packet_number_gen_t pn_gen;

    // 确认丢失的时间
    u_int64_t loss_time;

    // 最后发送确认的时间
    u_int64_t last_sent_ack_time;

    // 最大确认数据包packet number
    u_int64_t largest_ack;

    // 最后发送的数据包packet number
    u_int64_t largest_sent;
};

/**
 * 初始化packet number处理模块
 *
 * @param sent_pn: packet number处理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_pn_init(gquic_packet_sent_pn_t *const sent_pn);

/**
 * 构造packet number处理模块
 *
 * @param sent_pn: packet number处理模块
 * @oaram init_pn: 最初的packet number
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_pn_ctor(gquic_packet_sent_pn_t *const sent_pn, const u_int64_t init_pn);

/**
 * 析构packet number处理模块
 *
 * @param sent_pn: packet number处理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_pn_dtor(gquic_packet_sent_pn_t *const sent_pn);

/**
 * 数据包发送处理模块
 */
typedef struct gquic_packet_sent_packet_handler_s gquic_packet_sent_packet_handler_t;
struct gquic_packet_sent_packet_handler_s {
    
    // 下次数据包发送时间
    u_int64_t next_send_time;

    // initial阶段的packet number空间
    gquic_packet_sent_pn_t *initial_packets;

    // handshake阶段的packet number空间
    gquic_packet_sent_pn_t *handshake_packets;

    // 1rtt阶段的packet number空间
    gquic_packet_sent_pn_t *one_rtt_packets;

    // 是否完成握手阶段
    bool handshake_complete;

    // 最小未被确认的packet number
    u_int64_t lowest_not_confirm_acked;

    // 未被确认接收的字节长度
    u_int64_t infly_bytes;

    // 拥塞控制模块
    gquic_cong_cubic_t cong;

    // RTT
    gquic_rtt_t *rtt;

    // 超时探测次数
    u_int32_t pto_count;

    // 超时探测发送的数据包阶段
    u_int8_t pto_mode;

    // 探测发送数据包个数
    int num_probes_to_send;

    // 超时时间
    u_int64_t alarm;
};

/**
 * 初始化数据包发送处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_init(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 构造数据包发送处理模块
 *
 * @param handler: handler
 * @param initial_pn: 初始packet number
 * @param rtt: rtt
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_ctor(gquic_packet_sent_packet_handler_t *const handler,
                                                        const u_int64_t initial_pn, gquic_rtt_t *const rtt);

/**
 * 析构数据包发送处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_dtor(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 丢弃指定加密级别的数据包
 *
 * @param handler: handler
 * @param enc_lv: 加密级别
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_drop_packets(gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv);

/**
 * 处理一个发送数据包
 *
 * @param handler: handler
 * @param packet: packet
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_sent_packet(gquic_packet_sent_packet_handler_t *const handler, GQUIC_CPTR_TYPE(gquic_packet_t) const packet);

/**
 * 处理一个确认报文
 *
 * @param handler: handler
 * @param ack_frame: 确认数据帧
 * @param enc_lv: 加密级别
 * @param recv_time: 接收到确认报文的时间
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_received_ack(gquic_packet_sent_packet_handler_t *const handler,
                                                                const gquic_frame_ack_t *const ack_frame, const u_int8_t enc_lv, const u_int64_t recv_time);

/**
 * 当超过判断数据包丢失的超时时间的相关处理操作
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_on_loss_detection_timeout(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 获取一个packet number(peek)
 * 
 * @param handler: handler
 * @param enc_lv: 加密级别
 *
 * @return pn: packet number
 * @return pn_len: packet number长度
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_peek_pn(u_int64_t *const pn, int *const pn_len,
                                                           gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv);

/**
 * 获取一个packet number(pop)
 * 
 * @param handler: handler
 * @param enc_lv: 加密级别
 *
 * @return pn: packet number
 * @return pn_len: packet number长度
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_pop_pn(u_int64_t *const ret, gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv);

/**
 * 获取当前的发送类别
 *
 * @param handler: handler
 * 
 * @return: 发送数据包类别
 */
u_int8_t gquic_packet_sent_packet_handler_send_mode(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 获取应发送的数据包个数
 *
 * @param handler: handler
 * 
 * @return: 发送数据包个数
 */
int gquic_packet_sent_packet_handler_should_send_packets_count(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 将探测性数据包添加到超时重发队列中
 *
 * @param handler: handler
 * @param enc_lv: 加密级别
 *
 * @return: 是否有添加到超时重发队列中的数据包
 */
bool gquic_packet_sent_packet_handler_queue_probe_packet(gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv);

/**
 * 重置inital阶段的发送数据包存储模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_reset_for_retry(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 设置握手阶段完成
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_sent_packet_handler_set_handshake_complete(gquic_packet_sent_packet_handler_t *const handler);

/**
 * 判断当前是否全部数据包已确认接收
 *
 * @param handler: handler
 * 
 * @return: 是否已经全部确认接收
 */
static inline bool gquic_packet_sent_packet_handler_acked_all(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        return false;
    }

    return (handler->initial_packets == NULL || gquic_packet_sent_mem_empty(&handler->initial_packets->mem))
        && (handler->handshake_packets == NULL || gquic_packet_sent_mem_empty(&handler->handshake_packets->mem))
        && (handler->one_rtt_packets == NULL || gquic_packet_sent_mem_empty(&handler->one_rtt_packets->mem));
}

#endif
