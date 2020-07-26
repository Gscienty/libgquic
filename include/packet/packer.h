/* include/packet/packer.h QUIC数据包packet打包模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_PACKER_H
#define _LIBGQUIC_PACKET_PACKER_H

#include "packet/header.h"
#include "packet/packet_pool.h"
#include "packet/packet.h"
#include "packet/retransmission_queue.h"
#include "packet/received_packet_handler.h"
#include "packet/sent_packet_handler.h"
#include "frame/ack.h"
#include "frame/crypto.h"
#include "frame/connection_close.h"
#include "handshake/establish.h"
#include "streams/framer.h"
#include "streams/crypto.h"
#include "util/list.h"
#include "util/count_pointer.h"
#include <stdbool.h>

/**
 * 打包过的packet
 */
typedef struct gquic_packed_packet_s gquic_packed_packet_t;
struct gquic_packed_packet_s {
    
    // 是否是有效packet
    bool valid;

    // packet头部
    gquic_packet_header_t hdr;

    // 序列化后的packet，含长度
    gquic_str_t raw;

    // packet中的ACK frame
    gquic_frame_ack_t *ack;

    // frame 列表，由于可能在多个实体中
    GQUIC_CPTR_TYPE(gquic_list_t) frames; /* void * */

    // buffer
    gquic_packet_buffer_t *buffer;
};

/**
 * 打包过的packet实体初始化
 *
 * @param packed_packet: packed_packet
 * 
 * @return: exception
 */
gquic_exception_t gquic_packed_packet_init(gquic_packed_packet_t *const packed_packet);

/**
 * 析构打包过的packet实体
 *
 * @param packed_packet: packed_packet
 * 
 * @return: excepton
 */
gquic_exception_t gquic_packed_packet_dtor(gquic_packed_packet_t *const packed_packet);

/**
 * 将打包过的packet转换为用于ACK触发的对数据包处理的packet实体
 *
 * @param: packed_packet: 打包过的packet
 * @param: queue: 重发队列
 * 
 * @return packet: ACK触发处理的packet实体
 * @return: exception
 */
gquic_exception_t gquic_packed_packet_get_ack_packet(GQUIC_CPTR_TYPE(gquic_packet_t) const packet,
                                                     gquic_packed_packet_t *const packed_packet, gquic_retransmission_queue_t *const queue);

/**
 * 获取打包过的packet的加密级别
 *
 * @param packed_packet: packed_packet
 * 
 * @return: 加密级别
 */
inline static u_int8_t gquic_packed_packet_enc_lv(const gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        return 0;
    }

    if (!packed_packet->hdr.is_long) {
        return GQUIC_ENC_LV_1RTT;
    }
    switch (gquic_packet_long_header_type(gquic_packet_header_long(&packed_packet->hdr))) {
    case GQUIC_LONG_HEADER_INITIAL:
        return GQUIC_ENC_LV_INITIAL;
    case GQUIC_LONG_HEADER_HANDSHAKE:
        return GQUIC_ENC_LV_HANDSHAKE;
    default:
        return 0;
    }
}

/**
 * 打包过的packet中是否包含ACK frame
 * 
 * @param packed_packet: packed_packet
 * 
 * @return: 是否包含ACK frame
 */
inline static bool gquic_packed_packet_is_ack_eliciting(gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        return false;
    }

    return gquic_frames_has_frame_ack(packed_packet->frames);
}

/**
 * 在打包packet过程中使用的相关参数
 */
typedef struct gquic_packed_packet_payload_s gquic_packed_packet_payload_t;
struct gquic_packed_packet_payload_s {

    // frames
    GQUIC_CPTR_TYPE(gquic_list_t) frames; /* void * */

    // ACK frame
    gquic_frame_ack_t *ack;

    // 打包后的数据包长度
    u_int64_t len;

    // 打包回调函数
    struct {
        void *self;
        gquic_exception_t (*cb)(gquic_str_t *const, gquic_str_t *const, void *const, const u_int64_t, const gquic_str_t *const, const gquic_str_t *const);
    } sealer;

    // 头部保护模块
    gquic_header_protector_t *header_sealer;

    // 数据包头部
    gquic_packet_header_t hdr;

    // 加密级别
    u_int8_t enc_lv;
};

/**
 * 打包参数初始化
 *
 * @param payload: 参数
 *
 * @return: exception
 */
gquic_exception_t gquic_packed_packet_payload_init(gquic_packed_packet_payload_t *const payload);

/**
 * 析构打包参数
 *
 * @param payload: 参数
 *
 * @return: exception
 */
gquic_exception_t gquic_packed_packet_payload_dtor(gquic_packed_packet_payload_t *const payload);

/**
 * 通过打包参数实体进行加密
 *
 * @param: payload: 打包参数
 * @param pn: packet number
 * @param plain_text: 明文
 * @param addata: AEAD addata
 * 
 * @return tag: tag
 * @return cipher_text: 密文
 * @return: exception
 */
#define GQUIC_PACKED_PACKET_PAYLOAD_SEAL(tag, cipher_text, payload, pn, plain_text, addata) \
    ((payload)->sealer.cb((tag), (cipher_text), (payload)->sealer.self, (pn), (plain_text), (addata)))

/**
 * 打包模块
 */
typedef struct gquic_packet_packer_s gquic_packet_packer_t;
struct gquic_packet_packer_s {

    // 源connection id
    gquic_str_t conn_id;

    // 获取目标connection id的回调函数
    struct {
        void *self;
        gquic_exception_t (*cb) (gquic_str_t *const, void *const);
    } get_conn_id;

    // 是否为客户端
    bool is_client;

    // 获取加密密钥/头部保护模块
    gquic_handshake_establish_t *est;

    // 是否已丢弃initial阶段密钥
    bool droped_initial;
    // 是否已丢弃handshake阶段密钥
    bool droped_handshake;

    // initial阶段的CRYPTO stream
    gquic_crypto_stream_t *initial_stream;
    // handshake阶段的CRYPTO stream
    gquic_crypto_stream_t *handshake_stream;

    // token
    gquic_str_t token;

    // packet number生成模块
    gquic_packet_sent_packet_handler_t *pn_gen;

    // frame提取模块
    gquic_framer_t *framer;

    // 获取ACK frame
    gquic_packet_received_packet_handlers_t *acks;

    // 超时重发队列
    gquic_retransmission_queue_t *retransmission_queue;

    // 数据包最大长度
    u_int64_t max_packet_size;

    // 未发送过ACK frame的数据包个数 （用于判断是否应向对端发送ping包）
    int non_ack_eliciting_acks_count;
};

/**
 * 初始化数据包打包模块
 *
 * @param: packer: 打包模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_init(gquic_packet_packer_t *const packer);

/**
 * 构造数据包打包模块
 *
 * @param packer: 打包模块
 * @param src_id: 源connection id
 * @param get_conn_id_self: 获取目的connection id回调函数的self参数
 * @param get_conn_id_cb: 获取目的connection id的回调函数
 * @param initial_stream: initial stream
 * @param handshake_stream: handshake stream
 * @param pn_gen: packet number生成模块
 * @param retransmission_queue: 超时重发队列
 * @param max_packet_size: 数据包最大长度
 * @param est: 加密密钥/头部保护模块获取模块
 * @param framer: frame获取模块(控制frame/stream frame)
 * @param acks: ACK frame获取模块
 * @param is_client: 是否为客户端的标记
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_ctor(gquic_packet_packer_t *const packer,
                                           const gquic_str_t *const src_id,
                                           void *const get_conn_id_self, int (*get_conn_id_cb) (gquic_str_t *const, void *const),
                                           gquic_crypto_stream_t *const initial_stream,
                                           gquic_crypto_stream_t *const handshake_stream,
                                           gquic_packet_sent_packet_handler_t *const pn_gen,
                                           gquic_retransmission_queue_t *const retransmission_queue,
                                           const u_int64_t max_packet_size,
                                           gquic_handshake_establish_t *const est,
                                           gquic_framer_t *const framer,
                                           gquic_packet_received_packet_handlers_t *acks,
                                           const bool is_client);

/**
 * 析构数据包打包模块
 *
 * @param packer: 打包模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_dtor(gquic_packet_packer_t *const packer);

/**
 * 打包一个connection close的数据包
 *
 * @param packer: 打包模块
 * @param conn_close: CONNECTION_CLOSE frame
 * 
 * @return packed_packet: 打包过的数据包
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_pack_conn_close(gquic_packed_packet_t *const packed_packet,
                                                      gquic_packet_packer_t *const packer,
                                                      const gquic_frame_connection_close_t *const conn_close);

/**
 * 尝试打包一个ACK的数据包
 *
 * @param packer: 打包模块
 *
 * @return packed_packet: 打包过的数据包
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_try_pack_ack_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);

/**
 * 针对特定加密级别进行打包
 *
 * @param packer: 打包模块
 * @param enc_lv: 加密级别
 *
 * @return packed_packet: 打过包的数据包
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_try_pack_probe_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer,
                                                            const u_int8_t enc_lv);

/**
 * 数据打包
 *
 * @param packer: 打包模块
 *
 * @return packed_packet: 打过包的数据包
 * @return: exception
 */
gquic_exception_t gquic_packet_packer_pack_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);


/**
 * 判断是否已经握手完毕
 *
 * @param packer: 打包模块
 *
 * @return: 是否已经握手完毕
 */
inline static bool gquic_packet_packer_handshake_confirmed(gquic_packet_packer_t *const packer) {
    if (packer == NULL) {
        return false;
    }
    return packer->droped_initial && packer->droped_handshake;
}

/**
 * 获取目标connection id
 * 
 * @param packer: 打包模块
 *
 * @return conn_id: 目标connection id
 * @return: exception
 */
#define GQUIC_PACKET_PACKER_GET_CONN_ID(conn_id, packer) ((packer)->get_conn_id.cb((conn_id), (packer)->get_conn_id.self))

#endif
