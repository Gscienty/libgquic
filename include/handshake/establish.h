/* include/handshake/establish.h TLS握手，建立安全通信信道
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_ESTABLISH_H
#define _LIBGQUIC_HANDSHAKE_ESTABLISH_H

#include "tls/conn.h"
#include "tls/config.h"
#include "util/str.h"
#include "util/io.h"
#include "handshake/auto_update_aead.h"
#include "handshake/aead.h"
#include "handshake/transport_parameters.h"
#include "handshake/extension_handler.h"
#include "liteco.h"
#include <stdbool.h>

/**
 * 完成安全通信信道建立过程的信号
 */
typedef struct gquic_establish_ending_event_s gquic_establish_ending_event_t;
struct gquic_establish_ending_event_s {

    // 信号类型, 信号类型包含如下四个:
    // GQUIC_ESTABLISH_ENDING_EVENT_HANDSHAKE_COMPLETE: 安全通信信道建立完成
    // GQUIC_ESTABLISH_ENDING_EVENT_ALERT: 安全通信信道建立过程中过程出错，发送Alert Record
    // GQUIC_ESTABLISH_ENDING_EVENT_CLOSE: 本身主动关闭安全通信信道建立过程
    // GQUIC_ESTABLISH_ENDING_EVENT_INTERNAL_ERR: 建立安全通信信道过程中发生内部错误
    u_int8_t type;

    union {
        void *event;
        u_int16_t alert_code;
    } payload;
};

#define GQUIC_ESTABLISH_ENDING_EVENT_HANDSHAKE_COMPLETE 1
#define GQUIC_ESTABLISH_ENDING_EVENT_ALERT 2
#define GQUIC_ESTABLISH_ENDING_EVENT_CLOSE 3
#define GQUIC_ESTABLISH_ENDING_EVENT_INTERNAL_ERR 4

/**
 * 安全通信信道建立过程中的信号
 */
typedef struct gquic_establish_process_event_s gquic_establish_process_event_t;
struct gquic_establish_process_event_s {

    // 信号类型，信号类型包含如下五个：
    // GQUIC_ESTABLISH_PROCESS_EVENT_DONE: 安全通信信道建立完毕（可能时是由于中断导致的完毕）
    // GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD: TLS record发送消息
    // GQUIC_ESTABLISH_PROCESS_EVENT_PARAM: transport parameters
    // GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY: 更新加密模块
    // GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY: 更新解密模块
    u_int8_t type;

    // transport parameters
    gquic_str_t param;
};

#define GQUIC_ESTABLISH_PROCESS_EVENT_DONE 1
#define GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD 2
#define GQUIC_ESTABLISH_PROCESS_EVENT_PARAM 3
#define GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY 4
#define GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY 5

/**
 * handshake 过程中的回调事件
 */
typedef struct gquic_handshake_event_s gquic_handshake_event_t;
struct gquic_handshake_event_s {

    // 当接收transport parameters时的相关操作
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const);
    } on_recv_params;

    // 当发生错误时的相关操作
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const u_int16_t, const int);
    } on_err;

    // 当丢弃密钥时的相关操作
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const u_int8_t);
    } drop_keys;

    // 当完成安全通信信道建立时的相关操作
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const);
    } on_handshake_complete;
};

#define GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(p, e) \
    (((p) == NULL || (p)->on_recv_params.cb == NULL || (p)->on_recv_params.self == NULL) \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((p)->on_recv_params.cb((p)->on_recv_params.self, (e))))
#define GQUIC_HANDSHAKE_EVENT_ON_ERR(p, a, e) \
    (((p) == NULL || (p)->on_err.cb == NULL || (p)->on_err.self == NULL) \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((p)->on_err.cb((p)->on_err.self, (a), (e))))
#define GQUIC_HANDSHAKE_EVENT_DROP_KEYS(p, e) \
    (((p) == NULL || (p)->drop_keys.cb == NULL || (p)->drop_keys.self == NULL) \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((p)->drop_keys.cb((p)->drop_keys.self, (e))))
#define GQUIC_HANDSHAKE_EVENT_ON_HANDSHAKE_COMPLETE(p) \
    (((p) == NULL || (p)->on_handshake_complete.cb == NULL || (p)->on_handshake_complete.self == NULL) \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((p)->on_handshake_complete.cb((p)->on_handshake_complete.self)))

/**
 * 初始化handshake回调事件
 */
gquic_exception_t gquic_handshake_event_init(gquic_handshake_event_t *const event);

/**
 * 安全信道建立模块
 */
typedef struct gquic_handshake_establish_s gquic_handshake_establish_t;
struct gquic_handshake_establish_s {

    // TLS config
    gquic_tls_config_t *cfg;

    // TLS 连接
    gquic_tls_conn_t conn;

    // 安全信道连接建立过程中的回调事件
    gquic_handshake_event_t events;

    // err 信号通道
    liteco_channel_t err_chan;
    // TLS 接收消息信号通道
    liteco_channel_t msg_chan;
    // transport parameter 接收信号通道
    liteco_channel_t param_chan;
    // 安全信道建立结束信号通道
    liteco_channel_t done_chan;
    // 安全信道建立完成信号通道
    liteco_channel_t complete_chan;
    // 主动结束安全信道建立过程信号通道
    liteco_channel_t close_chan;
    // TLS alert信号通道
    liteco_channel_t alert_chan;
    // TLS record写操作信号通道
    liteco_channel_t write_record_chan;
    // 更新解密密钥信号通道
    liteco_channel_t received_rkey_chan;
    // 更新加密密钥信号通道
    liteco_channel_t received_wkey_chan;

    // CHELLO 是否已经被发送
    bool cli_hello_written;

    // 是否为客户端
    bool is_client;

    // 互斥锁
    pthread_mutex_t mtx;

    // 解密密钥加密级别
    u_int8_t read_enc_level;

    // 加密密钥加密级别
    u_int8_t write_enc_level;

    // 加密级别为initial的输出通道
    gquic_io_t init_output;

    // 加密级别为initial时的解密组件
    gquic_common_long_header_opener_t initial_opener;
    // 加密级别为initial时的加密组件
    gquic_common_long_header_sealer_t initial_sealer;

    // 加密级别为handshake时的输出通道
    gquic_io_t handshake_output;
    // 加密级别为handshake时的解密组件
    gquic_common_long_header_opener_t handshake_opener;
    // 加密级别为handshake时的加密组件
    gquic_common_long_header_sealer_t handshake_sealer;

    // 加密级别为1RTT时的输出通道
    gquic_io_t one_rtt_output;
    // 1RTT加密/解密组件
    gquic_auto_update_aead_t aead;
    // 是否有1RTT加密组件
    bool has_1rtt_sealer;
    // 是否有1RTT解密组件
    bool has_1rtt_opener;

    // 处理transport parameters的模块
    gquic_handshake_extension_handler_t extension_handler;

    // handshake是否已经结束
    bool handshake_done;

    // CHELLO 发送后的回调函数
    struct {
        void *self;
        int (*cb) (void *const);
    } chello_written;
};

#define GQUIC_HANDSHAKE_ESTABLISH_CHELLO_WRITTEN(est) \
    ((est)->chello_written.cb == NULL \
    ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
    : (est)->chello_written.cb((est)->chello_written.self))

/**
 * 初始化安全信道建立模块
 *
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_init(gquic_handshake_establish_t *const est);

/**
 * 构造安全信道建立模块
 *
 * @param est: 安全信道建立模块
 * @param initial_stream_self: 加密级别为initial时的输出信道写操作时的self参数
 * @param initial_stream_cb: 加密级别为initial时的输出信道写操作
 * @param handshake_stream_self: 加密级别为handshake时的输出信道写操作时的self参数
 * @param handshake_stream_cb: 加密级别为handshake时的输出信道写操作
 * @param one_rtt_stream_self: 加密级别为1RTT时的输出信道写操作时的self参数
 * @param one_rtt_stream_cb: 加密级别为1RTT时的输出信道写操作
 * @param cfg: tls config
 * @param conn_id: connection id
 * @param params: transport parameters
 * @param rtt: rtt
 * @param addr: 对端地址(仅用于TLS存储session cache key)
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_ctor(gquic_handshake_establish_t *const est,
                                                 void *initial_stream_self, int (*initial_stream_cb) (void *const, gquic_writer_str_t *const),
                                                 void *handshake_stream_self, int (*handshake_stream_cb) (void *const, gquic_writer_str_t *const),
                                                 void *one_rtt_self, int (*one_rtt_cb) (void *const, gquic_writer_str_t *const),
                                                 void *chello_written_self, int (*chello_written_cb) (void *const),
                                                 gquic_tls_config_t *const cfg,
                                                 const gquic_str_t *const conn_id,
                                                 const gquic_transport_parameters_t *const params,
                                                 gquic_rtt_t *const rtt,
                                                 const gquic_net_addr_t *const addr,
                                                 const bool is_client);

/**
 * 析构安全信道建立模块
 *
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_dtor(gquic_handshake_establish_t *const est);

/**
 * 安全信道更换connection id
 * 
 * @param est: 安全信道建立模块
 * @param conn_id: connection id
 * 
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_change_conn_id(gquic_handshake_establish_t *const est, const gquic_str_t *const conn_id);

/**
 * 设置最后ACK pecket number
 *
 * @param est: 安全信道建立模块
 * @param pn: packet number
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_1rtt_set_last_acked(gquic_handshake_establish_t *const est, const u_int64_t pn);

/**
 * 开始安全信道建立过程
 *
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_run(gquic_handshake_establish_t *const est);

/**
 * 主动关闭建立安全信道过程
 *
 * @param: est: 安全信道建立模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_close(gquic_handshake_establish_t *const est);

/**
 * 安全信道建立过程获取message（用于接收)
 *
 * @param est: 安全信道建立模块
 * @param data: data
 * @param env_level: 加密级别
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_handle_msg(gquic_handshake_establish_t *const est, const gquic_str_t *const data, const u_int8_t enc_level);

/**
 * 从安全信道建立过程中获取message（用于发送）
 *
 * @param msg: 安全信道建立模块输出的message
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_read_handshake_msg(gquic_str_t *const msg, gquic_handshake_establish_t *const est);

/**
 * 设置解密密钥
 *
 * @param est: 安全信道建立模块
 * @param enc_level: 加密级别
 * @param suite: 加密套件
 * @param traffic_sec: secret
 * 
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_set_rkey(gquic_handshake_establish_t *const est,
                                                     const u_int8_t enc_level, const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 设置加密密钥
 *
 * @param est: 安全信道建立模块
 * @param enc_level: 加密级别
 * @param suite: 加密套件
 * @param traffic_sec: secret
 * 
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_set_wkey(gquic_handshake_establish_t *const est,
                                                     const u_int8_t enc_level, const gquic_tls_cipher_suite_t *const suite, const gquic_str_t *const traffic_sec);

/**
 * 丢弃加密级别为initial的密钥
 *
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
int gquic_handshake_establish_drop_initial_keys(gquic_handshake_establish_t *const est);

/**
 * 丢弃加密级别为handshake的密钥
 *
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
int gquic_handshake_establish_drop_handshake_keys(gquic_handshake_establish_t *const est);

/**
 * TLS record 发送处理
 *
 * @param size: 返回发送的数据长度
 * @param est: 安全信道建立模块
 * @param data: 发送的数据
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_write_record(size_t *const size, gquic_handshake_establish_t *const est, const gquic_str_t *const data);

/**
 * TLS 发送 ALERT 处理
 *
 * @param est: 安全信道建立模块
 * @param alert: ALERT code
 * 
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_send_alert(gquic_handshake_establish_t *const est, const u_int8_t alert);

/**
 * 设置TLS的record层处理回调函数
 *
 * @param record_layer: record层回调函数
 * @param est: 安全信道建立模块
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_set_record_layer(gquic_tls_record_layer_t *const record_layer, gquic_handshake_establish_t *const est);

/**
 * 获取加密级别为initial的解密模块
 *
 * @param: est: 安全信道建立模块
 *
 * @return protector: 头部保护模块
 * @return opener: 解密模块
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_get_initial_opener(gquic_header_protector_t **const protector, gquic_common_long_header_opener_t **const opener,
                                                               gquic_handshake_establish_t *const est);

/**
 * 获取加密级别为handshake的解密模块
 *
 * @param: est: 安全信道建立模块
 *
 * @return protector: 头部保护模块
 * @return opener: 解密模块
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_get_handshake_opener(gquic_header_protector_t **const protector, gquic_common_long_header_opener_t **const opener,
                                                                 gquic_handshake_establish_t *const est);

/**
 * 获取加密级别为1RTT的解密模块
 *
 * @param: est: 安全信道建立模块
 *
 * @return protector: 头部保护模块
 * @return opener: 解密模块
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_get_1rtt_opener(gquic_header_protector_t **const protector, gquic_auto_update_aead_t **const opener,
                                                            gquic_handshake_establish_t *const est);

/**
 * 获取加密级别为initial的加密模块
 *
 * @param: est: 安全信道建立模块
 *
 * @return protector: 头部保护模块
 * @return sealer: 加密模块
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_get_initial_sealer(gquic_header_protector_t **const protector, gquic_common_long_header_sealer_t **const sealer,
                                                               gquic_handshake_establish_t *const est);

/**
 * 获取加密级别为handshake的加密模块
 *
 * @param: est: 安全信道建立模块
 *
 * @return protector: 头部保护模块
 * @return sealer: 加密模块
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_get_handshake_sealer(gquic_header_protector_t **const protector, gquic_common_long_header_sealer_t **const sealer,
                                                                 gquic_handshake_establish_t *const est);

/**
 * 获取加密级别为1RTT的加密模块
 *
 * @param: est: 安全信道建立模块
 *
 * @return protector: 头部保护模块
 * @return sealer: 加密模块
 * @return: exception
 */
gquic_exception_t gquic_handshake_establish_get_1rtt_sealer(gquic_header_protector_t **const protector, gquic_auto_update_aead_t **const sealer,
                                                            gquic_handshake_establish_t *const est);

#endif
