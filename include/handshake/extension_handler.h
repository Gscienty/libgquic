/* include/handshake/extension_handler.h TLS附加部分处理声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_EXTENSION_HANDLER_H
#define _LIBGQUIC_HANDSHAKE_EXTENSION_HANDLER_H

#include "util/str.h"
#include "handshake/transport_parameters.h"
#include "tls/config.h"
#include "liteco.h"
#include "exception.h"
#include <stdbool.h>

/**
 * TLS附加部分处理模块
 */
typedef struct gquic_handshake_extension_handler_s gquic_handshake_extension_handler_t;
struct gquic_handshake_extension_handler_s {

    // 附加部分通知channel
    liteco_channel_t *param_chain;

    // transport parameters 序列化后的字节串
    gquic_str_t params;

    // 是否为客户端
    bool is_client;
};

/**
 * TLS附加部分处理初始化
 *
 * @param handler: 处理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_extension_handler_init(gquic_handshake_extension_handler_t *const handler);

/**
 * 构造TLS附加部分处理模块
 *
 * @param handler: 处理模块
 * @param param_chain: 附加部分处理完毕通知channel
 * @param params: transport parameters
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_extension_handler_ctor(gquic_handshake_extension_handler_t *const handler,
                                                         liteco_channel_t *const param_chain,
                                                         const gquic_transport_parameters_t *const params,
                                                         const bool is_client);

/**
 * 析构TLS附加部分处理模块
 *
 * @param handler: 处理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_extension_handler_dtor(gquic_handshake_extension_handler_t *const handler);

/**
 * 将transport parameters 序列化后的字符串添加到extensions队列中
 *
 * @param extensions: 待添加队列
 * @param handler: 处理模块
 * @param msg_type: TLS handshake过程中的消息类型
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_extension_handler_get_extensions(gquic_list_t *const extensions,
                                                                   gquic_handshake_extension_handler_t *const handler,
                                                                   const u_int8_t msg_type);

/**
 * 客户端接收到TLS附加部分时的处理部分
 *
 * @param handler: 处理模块
 * @param msg_type: TLS handshake过程中的消息类型
 * @param extensions: 接收到的extensions队列
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_extension_handler_recv_extensions(gquic_handshake_extension_handler_t *const handler,
                                                                    const u_int8_t msg_type,
                                                                    const gquic_list_t *const extensions);

/**
 * 向tls_config中添加相关配置参数
 *
 * @param cfg: tls_config
 * @param handler: 处理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_extension_handler_set_config_extension(gquic_tls_config_t *const cfg,
                                                                         gquic_handshake_extension_handler_t *const handler);

#endif
