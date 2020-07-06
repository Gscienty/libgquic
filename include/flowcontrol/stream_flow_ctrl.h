/* include/flowcontrol/stream_flow_ctrl.h stream流量控制模块声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_H
#define _LIBGQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_H

#include "flowcontrol/base.h"
#include "flowcontrol/conn_flow_ctrl.h"
#include "exception.h"
#include <stdbool.h>

/**
 * stream流量控制模块
 */
typedef struct gquic_flowcontrol_stream_flow_ctrl_s gquic_flowcontrol_stream_flow_ctrl_t;
struct gquic_flowcontrol_stream_flow_ctrl_s {

    // 流量控制基础模块
    gquic_flowcontrol_base_t base;

    // 连接流量控制模块
    gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl;

    // stream是否结束标记
    bool recv_final_off;

    // stream id
    u_int64_t stream_id;

    // 接收窗口更新回调函数
    // param stream id
    struct {
        void *self;
        int (*cb) (void *const, const u_int64_t);
    } queue_wnd_update;
};

#define GQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl) \
    ((ctrl)->queue_wnd_update.cb == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (ctrl)->queue_wnd_update.cb((ctrl)->queue_wnd_update.self, (ctrl)->stream_id))

/**
 * stream流量控制模块初始化
 *
 * @param ctrl: ctrl
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_init(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);

/**
 * 构造stream流量控制模块
 *
 * @param ctrl: ctrl
 * @param stream_id: stream id
 * @param conn_flow_ctrl: 连接流量控制模块
 * @param rwnd: 接收窗口
 * @param max_rwnd: 最大接收窗口
 * @param initial_swnd: 初始发送窗口
 * @param queue_wnd_update_self: 接收窗口更新回调self参数
 * @param queue_wnd_update_cb: 接收窗口更新回调函数
 * @param rtt: rtt
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_ctor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                          const u_int64_t stream_id,
                                                          gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl,
                                                          const u_int64_t rwnd,
                                                          const u_int64_t max_rwnd,
                                                          const u_int64_t initial_swnd,
                                                          void *const queue_wnd_update_self,
                                                          int (*queue_wnd_update_cb) (void *const, const u_int64_t),
                                                          gquic_rtt_t *const rtt);

/**
 * 析构stream流量控制模块
 *
 * @param ctrl: ctrl
 *
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_dtor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);

/**
 * 更新最大可接受的数据大小
 *
 * @param ctrl: ctrl
 * @param increment: 更新可接收的数据大小
 * @param final: stream是否结束
 *
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                                         const u_int64_t off, const bool final);

/**
 * stream流量控制模块读取指定数据量的处理
 *
 * @param ctrl: ctrl
 * @param bytes: 读取的数据大小
 *
 * @return exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl, const u_int64_t bytes);

/**
 * stream流量控制处理发送指定的数据量
 *
 * @param ctrl: ctrl
 * @param bytes: 发送的数据大小
 *
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl, const u_int64_t bytes);

/**
 * stream被关闭时，丢弃待发送数据
 *
 * @param ctrl: ctrl
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_stream_flow_ctrl_abandon(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);

/**
 * 获取stream流量控制模块中发送窗口大小
 *
 * @param ctrl: ctrl
 * 
 * @return: 发送窗口大小
 */
u_int64_t gquic_flowcontrol_stream_flow_ctrl_swnd_size(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);

/**
 * 尝试更新流量控制模块中的接收窗口，并返回调整后的接收窗口
 *
 * @param ctrl: ctrl
 *
 * @return: 新的接收窗口大小
 */
u_int64_t gquic_flowcontrol_stream_flow_ctrl_get_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);

#endif
