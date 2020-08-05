/* src/packet/unpacker.c 解析数据包模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/unpacker.h"
#include "packet/packet_number.h"
#include "util/malloc.h"
#include "exception.h"
#include <string.h>

/**
 * 长首部数据包解析过程，针对initial和handshake阶段的数据包
 */
static gquic_exception_t gquic_common_long_header_opener_open_wrapper(gquic_str_t *const,
                                                                      void *const, const u_int64_t,
                                                                      const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);

/**
 * 短首部数据包解析过程，针对1rtt阶段的数据包
 */
static gquic_exception_t gquic_1rtt_opener_open_wrapper(gquic_str_t *const,
                                                        void *const, const u_int64_t, const u_int64_t, const int,
                                                        const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);

/**
 * 对发来的数据包进行解析
 *
 * @param unpacked_packet: 存储解析后的数据包
 * @param unpacker: 解析数据包
 * @param payload: 解析数据包参数
 * @param dst_conn_id_len: 针对短首部的connection id长度
 *
 * @return: exception
 */
static gquic_exception_t gquic_packet_unpacker_unpack_packet(gquic_unpacked_packet_t *const unpacked_packet,
                                                             gquic_packet_unpacker_t *const unpacker,
                                                             gquic_unpacked_packet_payload_t *const payload, const u_int64_t dst_conn_id_len);

/**
 * 解析数据包首部
 *
 * @param unpacked_packet: 存储解析后的数据包
 * @param unpacker: 解析数据包
 * @param payload: 解析数据包参数
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_packet_unpacker_unpack_header(gquic_unpacked_packet_t *const unpacked_packet,
                                                             gquic_packet_unpacker_t *const unpacker,
                                                             gquic_unpacked_packet_payload_t *const payload, gquic_reader_str_t *const reader);

gquic_exception_t gquic_unpacked_packet_payload_init(gquic_unpacked_packet_payload_t *const payload) {
    if (payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    payload->data = NULL;
    payload->opener.is_1rtt = false;
    payload->opener.cb.cb = NULL;
    payload->opener.cb.one_rtt_cb = NULL;
    payload->opener.self = NULL;
    payload->header_opener = NULL;
    payload->recv_time = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_unpacked_packet_init(gquic_unpacked_packet_t *const unpacked_packet) {
    if (unpacked_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unpacked_packet->valid = false;
    unpacked_packet->pn = 0;
    gquic_packet_header_init(&unpacked_packet->hdr);
    unpacked_packet->enc_lv = 0;
    gquic_str_init(&unpacked_packet->data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_unpacked_packet_dtor(gquic_unpacked_packet_t *const unpacked_packet) {
    if (unpacked_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_header_dtor(&unpacked_packet->hdr);
    gquic_str_reset(&unpacked_packet->data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_unpacker_init(gquic_packet_unpacker_t *const unpacker) {
    if (unpacker == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unpacker->est = NULL;
    unpacker->largest_recv_pn = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_unpacker_ctor(gquic_packet_unpacker_t *const unpacker, gquic_handshake_establish_t *const est) {
    if (unpacker == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unpacker->est = est;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_unpacker_unpack(gquic_unpacked_packet_t *const unpacked_packet,
                                               gquic_packet_unpacker_t *const unpacker,
                                               const gquic_str_t *const data, const u_int64_t recv_time, const u_int64_t dst_conn_id_len) {
    gquic_unpacked_packet_payload_t payload;
    if (unpacked_packet == NULL || unpacker == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_unpacked_packet_payload_init(&payload);
    payload.data = data;
    payload.recv_time = recv_time;

    if ((GQUIC_STR_FIRST_BYTE(data) & 0xc0) == 0xc0) {
        switch ((GQUIC_STR_FIRST_BYTE(data) & 0x30) >> 4) {
        case 0x00:
            unpacked_packet->enc_lv = GQUIC_ENC_LV_INITIAL;
            payload.opener.is_1rtt = false;
            payload.opener.cb.cb = gquic_common_long_header_opener_open_wrapper;
            GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_initial_opener(&payload.header_opener,
                                                                                  (gquic_common_long_header_opener_t **) &payload.opener.self,
                                                                                  unpacker->est));
            break;
        case 0x02:
            unpacked_packet->enc_lv = GQUIC_ENC_LV_HANDSHAKE;
            payload.opener.is_1rtt = false;
            payload.opener.cb.cb = gquic_common_long_header_opener_open_wrapper;
            GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_handshake_opener(&payload.header_opener,
                                                                                    (gquic_common_long_header_opener_t **) &payload.opener.self,
                                                                                    unpacker->est));
            break;
        default:
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
        }
        unpacked_packet->hdr.is_long = true;
    }
    else if ((GQUIC_STR_FIRST_BYTE(data) & 0xc0) == 0x40) {
        unpacked_packet->enc_lv = GQUIC_ENC_LV_1RTT;
        payload.opener.is_1rtt = true;
        payload.opener.cb.one_rtt_cb = gquic_1rtt_opener_open_wrapper;
        payload.header_opener = &unpacker->est->aead.header_dec;
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_1rtt_opener(&payload.header_opener,
                                                                           (gquic_auto_update_aead_t **) &payload.opener.self,
                                                                           unpacker->est));
        unpacked_packet->hdr.is_long = false;
    }
    else {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_packet_unpacker_unpack_packet(unpacked_packet, unpacker, &payload, dst_conn_id_len));

    u_int64_t tmp_pn = gquic_packet_header_get_pn(&unpacked_packet->hdr);
    if (unpacker->largest_recv_pn < tmp_pn) {
        unpacker->largest_recv_pn = tmp_pn;
    }
    unpacked_packet->valid = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_common_long_header_opener_open_wrapper(gquic_str_t *const plain_text,
                                                                      void *const self, const u_int64_t pn,
                                                                      const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    return gquic_common_long_header_opener_open(plain_text, self, pn, tag, cipher_text, addata);
}

static gquic_exception_t gquic_1rtt_opener_open_wrapper(gquic_str_t *const plain_text,
                                                        void *const self, const u_int64_t recv_time, const u_int64_t pn, const gquic_exception_t kp,
                                                        const gquic_str_t *const tag, const gquic_str_t *const cipher_text, const gquic_str_t *const addata) {
    return gquic_auto_update_aead_open(plain_text, self, recv_time, pn, kp, tag, cipher_text, addata);
}

static gquic_exception_t gquic_packet_unpacker_unpack_packet(gquic_unpacked_packet_t *const unpacked_packet,
                                                             gquic_packet_unpacker_t *const unpacker,
                                                             gquic_unpacked_packet_payload_t *const payload, const u_int64_t dst_conn_id_len) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_reader_str_t reader = { 0, NULL };
    if (unpacked_packet == NULL || unpacker == NULL || payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    reader = *payload->data;

    // 解析首部未加密部分
    if (unpacked_packet->hdr.is_long) {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_long_header_alloc(&unpacked_packet->hdr.hdr.l_hdr));
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_long_header_deserialize_unseal_part(gquic_packet_header_long(&unpacked_packet->hdr), &reader));
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_short_header_alloc(&unpacked_packet->hdr.hdr.s_hdr));
        gquic_packet_header_short(&unpacked_packet->hdr)->dcid_len = dst_conn_id_len;
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_short_header_deserialize_unseal_part(gquic_packet_header_short(&unpacked_packet->hdr), &reader));
    }

    // 解析首部
    GQUIC_EXCEPTION_ASSIGN(exception, gquic_packet_unpacker_unpack_header(unpacked_packet, unpacker, payload, &reader));
    if (exception != GQUIC_SUCCESS && exception != GQUIC_EXCEPTION_INVALID_RESERVED_BITS) {
        GQUIC_PROCESS_DONE(exception);
    }

    u_int64_t header_len = GQUIC_STR_VAL(&reader) - GQUIC_STR_VAL(payload->data);
    gquic_str_t tag = { 16, GQUIC_STR_VAL(payload->data) + header_len };
    gquic_str_t cipher_text = { GQUIC_STR_SIZE(payload->data) - header_len - 16, GQUIC_STR_VAL(payload->data) + header_len + 16 };
    gquic_str_t addata = { header_len, GQUIC_STR_VAL(payload->data) };

    // 解析数据包载荷部分
    GQUIC_ASSERT_FAST_RETURN(GQUIC_UNPACKED_PACKET_PAYLOAD_OPEN(&unpacked_packet->data,
                                                                payload, payload->recv_time, gquic_packet_header_get_pn(&unpacked_packet->hdr),
                                                                (!unpacked_packet->hdr.is_long
                                                                 && (gquic_packet_header_short(&unpacked_packet->hdr)->flag & 0x04) != 0),
                                                                &tag, &cipher_text, &addata));
    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_packet_unpacker_unpack_header(gquic_unpacked_packet_t *const unpacked_packet,
                                                             gquic_packet_unpacker_t *const unpacker,
                                                             gquic_unpacked_packet_payload_t *const payload, gquic_reader_str_t *const reader) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    u_int64_t deserialized_hdr_size = 0;
    u_int8_t origin_pn[4] = { 0 };
    int pn_len = 0;
    if (unpacked_packet == NULL || unpacker == NULL || payload == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    deserialized_hdr_size = GQUIC_STR_VAL(reader) - GQUIC_STR_VAL(payload->data);
    if (GQUIC_STR_SIZE(payload->data) < deserialized_hdr_size + 4 + 16) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    memcpy(origin_pn, GQUIC_STR_VAL(payload->data) + deserialized_hdr_size, 4);
    gquic_str_t header = { 4, GQUIC_STR_VAL(payload->data) + deserialized_hdr_size };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(payload->data) + deserialized_hdr_size + 4 };

    // 设定首部保护模块的加密密钥
    GQUIC_HEADER_PROTECTOR_SET_KEY(payload->header_opener, &sample);

    if (unpacked_packet->hdr.is_long) {
        // 长首部解析加密部分
        GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &gquic_packet_header_long(&unpacked_packet->hdr)->flag, payload->header_opener);
        pn_len = gquic_packet_number_flag_to_size(gquic_packet_header_long(&unpacked_packet->hdr)->flag);
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_long_header_deserialize_seal_part(gquic_packet_header_long(&unpacked_packet->hdr), reader));
        *(u_int8_t *) GQUIC_STR_VAL(payload->data) = gquic_packet_header_long(&unpacked_packet->hdr)->flag;
    }
    else {
        // 短首部解析加密部分
        GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &gquic_packet_header_short(&unpacked_packet->hdr)->flag, payload->header_opener);
        pn_len = gquic_packet_number_flag_to_size(gquic_packet_header_short(&unpacked_packet->hdr)->flag);
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_short_header_deserialize_seal_part(gquic_packet_header_short(&unpacked_packet->hdr), reader));
        *(u_int8_t *) GQUIC_STR_VAL(payload->data) = gquic_packet_header_short(&unpacked_packet->hdr)->flag;
    }
    if (pn_len != 4) {
        memcpy(GQUIC_STR_VAL(payload->data) + deserialized_hdr_size + pn_len, origin_pn + pn_len, 4 - pn_len);
    }
    gquic_packet_header_set_pn(&unpacked_packet->hdr,
                               gquic_packet_number_decode(pn_len, unpacker->largest_recv_pn, gquic_packet_header_get_pn(&unpacked_packet->hdr)));

    GQUIC_PROCESS_DONE(exception);
}

