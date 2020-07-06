/* include/flowcontrol/conn_flow_ctrl.h 连接流量控制模块声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FLOWCONTROL_CONN_FLOW_CTRL_H
#define _LIBGQUIC_FLOWCONTROL_CONN_FLOW_CTRL_H

#include "flowcontrol/base.h"

/**
 * 连接流量控制模块
 */
typedef struct gquic_flowcontrol_conn_flow_ctrl_s gquic_flowcontrol_conn_flow_ctrl_t;
struct gquic_flowcontrol_conn_flow_ctrl_s {
    
    // 流量控制基础模块
    gquic_flowcontrol_base_t base;

    // 接收窗口更新回调函数
    struct {
        void *self;
        int (*cb) (void *const);
    } queue_wnd_update;
};

#define GQUIC_FLOWCONTROL_CONN_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl) ((ctrl)->queue_wnd_update.cb((ctrl)->queue_wnd_update.self))

/**
 * 连接流量控制模块初始化
 * 
 * @param ctrl: ctrl
 *
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_init(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);

/**
 * 构造连接流量控制模块
 *
 * @param ctrl: ctrl
 * @param rwnd: 接收窗口
 * @param rwnd_max: 最大接收窗口
 * @param queue_wnd_update_self: 接收窗口更新回调self参数
 * @param queue_wnd_update_cb: 接收窗口更新回调函数
 * @param rtt: rtt
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_ctor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl,
                                                        const u_int64_t rwnd,
                                                        const u_int64_t max_rwnd,
                                                        void *queue_wnd_update_self,
                                                        int (*queue_wnd_update_cb) (void *const),
                                                        gquic_rtt_t *const rtt);

/**
 * 析构连接流量控制模块
 *
 * @param ctrl: ctrl
 * 
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_dtor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);

/**
 * 增加最大可接受的数据大小
 *
 * @param ctrl: ctrl
 * @param increment: 增加的可接收的数据大小
 *
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_increment_highest_recv(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t increment);

/**
 * 连接流量控制模块读取指定数据量的处理
 *
 * @param ctrl: ctrl
 * @param bytes: 读取的数据大小
 *
 * @return exception
 */
gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t bytes);

/**
 * 尝试更新流量控制模块中的接收窗口，并返回调整后的接收窗口
 *
 * @param ctrl: ctrl
 *
 * @return: 新的接收窗口大小
 */
u_int64_t gquic_flowcontrol_conn_flow_ctrl_get_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);

/**
 * 设定流量控制模块的接收窗口，并开始流量控制
 *
 * @param ctrl: ctrl
 * @param rwnd_size: 接收窗口
 *
 * @return: exception
 */
gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_ensure_min_wnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t rwnd_size);

/**
 * 获取连接流量控制模块中发送窗口大小
 *
 * @param ctrl: ctrl
 * 
 * @return: 发送窗口大小
 */
static inline u_int64_t gquic_flowcontrol_conn_flow_ctrl_swnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        return 0;
    }

    return gquic_flowcontrol_base_swnd_size(&ctrl->base);
}

#endif
