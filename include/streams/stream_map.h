/* include/stream/stream.h 数据流管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAMS_STREAM_MAP_H
#define _LIBGQUIC_STREAMS_STREAM_MAP_H

#include "streams/stream_sender.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "streams/inuni_stream_map.h"
#include "streams/inbidi_stream_map.h"
#include "streams/outuni_stream_map.h"
#include "streams/outbidi_stream_map.h"
#include "frame/max_streams.h"
#include "handshake/transport_parameters.h"
#include "coglobal.h"
#include <stdbool.h>

/**
 * 数据流管理模块
 */
typedef struct gquic_stream_map_s gquic_stream_map_t;
struct gquic_stream_map_s {

    // 是否为客户端
    bool is_client;

    // 发送的后处理接口
    gquic_stream_sender_t sender;

    // 流量控制构造回调函数
    struct {
        void *self;
        int (*cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t);
    } flow_ctrl_ctor;

    gquic_inuni_stream_map_t inuni;
    gquic_inbidi_stream_map_t inbidi;
    gquic_outuni_stream_map_t outuni;
    gquic_outbidi_stream_map_t outbidi;
};

#define GQUIC_STREAM_MAP_FLOW_CTRL_CTOR(ctrl, map, n) ((map)->flow_ctrl_ctor.cb(ctrl, (map)->flow_ctrl_ctor.self, n))

/**
 * 初始化数据流管理模块
 *
 * @param str_map: 数据流管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_map_init(gquic_stream_map_t *const str_map);

/**
 * 构造数据流管理模块
 *
 * @param str_map: 数据流管理模块
 * @param sender_ctor_self: 构造处理接口self参数
 * @param sender_ctor_cb: 构造处理接口回调函数
 * @param flow_ctrl_ctor_self: 构造流量控制self参数
 * @param flow_ctrl_ctor_cb: 构造流量控制回调函数
 * @param max_inbidi_stream_count: 可接受开启的双向数据流个数
 * @param max_inuni_stream_count: 可接受开启的单向数据流个数
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_map_ctor(gquic_stream_map_t *const str_map,
                                        void *const sender_ctor_self,
                                        gquic_exception_t (*sender_ctor_cb) (gquic_stream_sender_t *const, void *const),
                                        void *const flow_ctrl_ctor_self,
                                        gquic_exception_t (*flow_ctrl_ctor_cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t),
                                        const u_int64_t max_inbidi_stream_count,
                                        const u_int64_t max_inuni_stream_count,
                                        const bool is_client);

/**
 * 打开一个数据流
 *
 * @param str_map; 数据流管理模块
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_stream_map_open_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
gquic_exception_t gquic_stream_map_open_stream_sync(gquic_stream_t **const str, gquic_stream_map_t *const str_map, liteco_channel_t *const done_chan);

/**
 * 打开一个单向数据流
 *
 * @param str_map: 数据流管理模块
 * 
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_stream_map_open_uni_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
gquic_exception_t gquic_stream_map_open_uni_stream_sync(gquic_stream_t **const str, gquic_stream_map_t *const str_map, liteco_channel_t *const done_chan);

/**
 * 接收一个数据流
 *
 * @param str_map: 数据流管理模块
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_stream_map_accept_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, liteco_channel_t *const done_chan);
gquic_exception_t gquic_stream_map_accept_uni_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, liteco_channel_t *const done_chan);

/**
 * 释放一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param id: stream id
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_map_release_stream(gquic_stream_map_t *const str_map, const u_int64_t id);

/**
 * 获取或打开一个接收数据流
 *
 * @param str_map: 数据流管理模块
 * @param id: stream id
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_stream_map_get_or_open_recv_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, const u_int64_t id);

/**
 * 获取或打开一个发送数据流
 *
 * @param str_map: 数据流管理模块
 * @param id: stream id
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_stream_map_get_or_open_send_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, const u_int64_t id);

/**
 * 处理MAX_STREAMS frame
 *
 * @param str_map: 数据流管理模块
 * @param frame: MAX_STREAMS frame
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_map_handle_max_streams_frame(gquic_stream_map_t *const str_map, gquic_frame_max_streams_t *const frame);

/**
 * 处理 transport parameters
 *
 * @param str_map: 数据流管理模块
 * @param params: transport parameters
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_map_handle_update_limits(gquic_stream_map_t *const str_map, gquic_transport_parameters_t *const params);

/**
 * 关闭数据流管理模块
 *
 * @param str_map: 数据流管理模块
 * @param err: 关闭原因
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_map_close(gquic_stream_map_t *const str_map, gquic_exception_t err);

#endif
