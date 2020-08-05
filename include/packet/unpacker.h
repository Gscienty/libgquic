/* include/packet/unpacker.h 解析数据包模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_UNPACKER_H
#define _LIBGQUIC_PACKET_UNPACKER_H

#include "handshake/establish.h"
#include "packet/header.h"
#include <sys/types.h>
#include <stdbool.h>

/**
 * 解析数据包参数封装模块
 */
typedef struct gquic_unpacked_packet_payload_s gquic_unpacked_packet_payload_t;
struct gquic_unpacked_packet_payload_s {

    // 解密回调函数封装
    struct {
        bool is_1rtt;
        void *self;
        union {
            // initial和handshake加密级别的解密回调函数
            gquic_exception_t (*cb) (gquic_str_t *const,
                                     void *const, const u_int64_t,
                                     const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
            // 1rtt加密级别的解密回调函数, 接收时间以及key phase用于更新加/解密密钥
            gquic_exception_t (*one_rtt_cb) (gquic_str_t *const,
                                             void *const, const u_int64_t, const u_int64_t, const int,
                                             const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
        } cb;
    } opener;

    // 未解析的数据包数据
    const gquic_str_t *data;

    // 头部保护模块
    gquic_header_protector_t *header_opener;

    // 数据包接收时间
    u_int64_t recv_time;
};

/**
 * 解析数据包
 *
 * @param payload: 解析数据包封装参数
 * @param recv_time: 接收数据包时间
 * @param pn: packet number
 * @param kp: key phase
 * @param tag: tag
 * @param cipher_text: 密文
 * @param addata: addata
 *
 * @return plain_text: 明文
 * @return: exception
 */
#define GQUIC_UNPACKED_PACKET_PAYLOAD_OPEN(plain_text, payload, recv_time, pn, kp, tag, cipher_text, addata) \
    ((payload)->opener.is_1rtt \
     ? ((payload)->opener.cb.one_rtt_cb((plain_text), (payload)->opener.self, (recv_time), (pn), (kp), (tag), (cipher_text), (addata)))\
     : ((payload)->opener.cb.cb((plain_text), (payload)->opener.self, (pn), (tag), (cipher_text), (addata))))

/**
 * 初始化解析数据包参数封装模块
 *
 * @param payload: 参数封装模块
 *
 * @return: exception
 */
gquic_exception_t gquic_unpacked_packet_payload_init(gquic_unpacked_packet_payload_t *const payload);

/**
 * 解析出的数据包封装实体
 */
typedef struct gquic_unpacked_packet_s gquic_unpacked_packet_t;
struct gquic_unpacked_packet_s {

    // 是否为合法的数据包
    bool valid;

    // packet number
    u_int64_t pn;

    // 数据包首部
    gquic_packet_header_t hdr;

    // 加密级别
    u_int8_t enc_lv;

    // 数据包载荷数据
    gquic_str_t data;
};

/**
 * 初始化解析后数据包封装实体
 *
 * @param unpacked_packet: 数据包封装实体
 *
 * @return: exception
 */
gquic_exception_t gquic_unpacked_packet_init(gquic_unpacked_packet_t *const unpacked_packet);

/**
 * 析构解析后的数据包封装实体
 *
 * @param unpacked_packet: 数据包封装实体
 *
 * @return: exception
 */
gquic_exception_t gquic_unpacked_packet_dtor(gquic_unpacked_packet_t *const unpacked_packet);

/**
 * 数据包解析模块
 */
typedef struct gquic_packet_unpacker_s gquic_packet_unpacker_t;
struct gquic_packet_unpacker_s {

    // 用于获取解密模块及头部保护模块
    gquic_handshake_establish_t *est;

    // 记录最大接收的packet number
    u_int64_t largest_recv_pn;
};

/**
 * 初始化数据包解析模块
 *
 * @param unpacker: 数据包解析模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_unpacker_init(gquic_packet_unpacker_t *const unpacker);

/**
 * 构造数据包解析模块
 *
 * @param unpacker: 数据包解析模块
 * @param ext: 获取解密模块及头部保护模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_unpacker_ctor(gquic_packet_unpacker_t *const unpacker, gquic_handshake_establish_t *const est);

/**
 * 数据包解析过程
 *
 * @param unpacked_packet: 用于承载解析后的数据包的实体
 * @param unpacker: 解析模块
 * @param data: 未解析成数据包的原始数据流
 * @param recv_time: 接收时间
 * @param dst_conn_id_len: 目标connection id的长度（用于解析短首部的connection id）
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_unpacker_unpack(gquic_unpacked_packet_t *const unpacked_packet,
                                               gquic_packet_unpacker_t *const unpacker,
                                               const gquic_str_t *const data, const u_int64_t recv_time, const u_int64_t dst_conn_id_len);

#endif
