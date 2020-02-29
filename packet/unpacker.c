#include "packet/unpacker.h"
#include "util/pn.h"

static int gquic_common_long_header_opener_open_wrapper(gquic_str_t *const,
                                                        void *const,
                                                        const u_int64_t,
                                                        const gquic_str_t *const,
                                                        const gquic_str_t *const,
                                                        const gquic_str_t *const);
static int gquic_1rtt_opener_open_wrapper(gquic_str_t *const,
                                          void *const,
                                          const u_int64_t,
                                          const u_int64_t,
                                          const int,
                                          const gquic_str_t *const,
                                          const gquic_str_t *const,
                                          const gquic_str_t *const);
static int gquic_packet_unpacker_unpack_header_packet(gquic_unpacked_packet_t *const,
                                                      gquic_packet_unpacker_t *const,
                                                      gquic_unpacked_packet_payload_t *const);
static int gquic_packet_unpacker_unpack_header(gquic_unpacked_packet_t *const,
                                               gquic_packet_unpacker_t *const,
                                               gquic_unpacked_packet_payload_t *const,
                                               gquic_reader_str_t *const);

int gquic_unpacked_packet_payload_init(gquic_unpacked_packet_payload_t *const payload) {
    if (payload == NULL) {
        return -1;
    }
    payload->data = NULL;
    payload->opener.is_1rtt = 0;
    payload->opener.cb.cb = NULL;
    payload->opener.cb.one_rtt_cb = NULL;
    payload->opener.self = NULL;
    payload->header_opener = NULL;
    payload->recv_time = 0;

    return 0;
}

int gquic_unpacked_packet_init(gquic_unpacked_packet_t *const unpacked_packet) {
    if (unpacked_packet == NULL) {
        return -1;
    }
    unpacked_packet->valid = 0;
    unpacked_packet->pn = 0;
    gquic_packet_header_init(&unpacked_packet->hdr);
    unpacked_packet->enc_lv = 0;
    gquic_str_init(&unpacked_packet->data);

    return 0;
}

int gquic_unpacked_packet_dtor(gquic_unpacked_packet_t *const unpacked_packet) {
    if (unpacked_packet == NULL) {
        return -1;
    }
    gquic_packet_header_dtor(&unpacked_packet->hdr);
    gquic_str_reset(&unpacked_packet->data);

    return 0;
}

int gquic_packet_unpacker_init(gquic_packet_unpacker_t *const unpacker) {
    if (unpacker == NULL) {
        return -1;
    }
    unpacker->est = 0;
    unpacker->largest_recv_pn = 0;

    return 0;
}

int gquic_packet_unpacker_ctor(gquic_packet_unpacker_t *const unpacker, gquic_handshake_establish_t *const est) {
    if (unpacker == NULL || est == NULL) {
        return -1;
    }
    unpacker->est = est;

    return 0;
}

int gquic_packet_unpacker_unpack(gquic_unpacked_packet_t *const unpacked_packet,
                                 gquic_packet_unpacker_t *const unpacker,
                                 const gquic_str_t *const data,
                                 const u_int64_t recv_time) {
    int ret = 0;
    gquic_unpacked_packet_payload_t payload;
    if (unpacked_packet == NULL || unpacker == NULL || data == NULL) {
        return -1;
    }
    gquic_unpacked_packet_payload_init(&payload);
    payload.data = data;
    payload.recv_time = recv_time;

    if ((GQUIC_STR_FIRST_BYTE(data) & 0xc0) == 0xc0) {
        switch ((GQUIC_STR_FIRST_BYTE(data) & 0x30) >> 4) {
        case 0x00:
            unpacked_packet->enc_lv = GQUIC_ENC_LV_INITIAL;
            payload.opener.is_1rtt = 0;
            payload.opener.cb.cb = gquic_common_long_header_opener_open_wrapper;
            if ((ret = gquic_handshake_establish_get_initial_opener(&payload.header_opener,
                                                                    (gquic_common_long_header_opener_t **) &payload.opener.self,
                                                                    unpacker->est)) != 0) {
                if (ret == -2) {
                    return -2; // key dropped
                }
                return -3;
            }
            break;
        case 0x02:
            unpacked_packet->enc_lv = GQUIC_ENC_LV_HANDSHAKE;
            payload.opener.is_1rtt = 0;
            payload.opener.cb.cb = gquic_common_long_header_opener_open_wrapper;
            if ((ret = gquic_handshake_establish_get_handshake_opener(&payload.header_opener,
                                                                    (gquic_common_long_header_opener_t **) &payload.opener.self,
                                                                      unpacker->est)) != 0) {
                if (ret == -2) {
                    return -4; // key dropped
                }
                return -5;
            }
            break;
        default:
            return -6;
        }
        unpacked_packet->hdr.is_long = 1;
    }
    else if ((GQUIC_STR_FIRST_BYTE(data) & 0xc0) == 0x40) {
        unpacked_packet->enc_lv = GQUIC_ENC_LV_1RTT;
        payload.opener.is_1rtt = 1;
        payload.opener.cb.one_rtt_cb = gquic_1rtt_opener_open_wrapper;
        payload.header_opener = &unpacker->est->aead.header_dec;
        if ((ret = gquic_handshake_establish_get_1rtt_opener(&payload.header_opener,
                                                             (gquic_auto_update_aead_t **) &payload.opener.self,
                                                             unpacker->est)) != 0) {
            if (ret == -2) {
                return -7; // key not available
            }
            return -8;
        }
        unpacked_packet->hdr.is_long = 0;
    }
    else {
        return -9;
    }

    if ((ret = gquic_packet_unpacker_unpack_header_packet(unpacked_packet, unpacker, &payload)) != 0) {
        if (ret == -6) {
            return -10; // unpack header error
        }
        return -11;
    }

    u_int64_t tmp_pn = gquic_packet_header_get_pn(&unpacked_packet->hdr);
    if (unpacker->largest_recv_pn < tmp_pn) {
        unpacker->largest_recv_pn = tmp_pn;
    }
    return 0;
}

static int gquic_common_long_header_opener_open_wrapper(gquic_str_t *const plain_text,
                                                        void *const self,
                                                        const u_int64_t pn,
                                                        const gquic_str_t *const tag,
                                                        const gquic_str_t *const cipher_text,
                                                        const gquic_str_t *const addata) {
    return gquic_common_long_header_opener_open(plain_text, self, pn, tag, cipher_text, addata);
}

static int gquic_1rtt_opener_open_wrapper(gquic_str_t *const plain_text,
                                          void *const self,
                                          const u_int64_t recv_time,
                                          const u_int64_t pn,
                                          const int kp,
                                          const gquic_str_t *const tag,
                                          const gquic_str_t *const cipher_text,
                                          const gquic_str_t *const addata) {
    return gquic_auto_update_aead_open(plain_text, self, recv_time, pn, kp, tag, cipher_text, addata);
}

static int gquic_packet_unpacker_unpack_header_packet(gquic_unpacked_packet_t *const unpacked_packet,
                                                      gquic_packet_unpacker_t *const unpacker,
                                                      gquic_unpacked_packet_payload_t *const payload) {
    gquic_reader_str_t reader = { 0, NULL };
    if (unpacked_packet == NULL || unpacker == NULL || payload == NULL) {
        return -1;
    }
    reader = *payload->data;
    if (unpacked_packet->hdr.is_long) {
        if ((unpacked_packet->hdr.hdr.l_hdr = gquic_packet_long_header_alloc()) == NULL) {
            return -2;
        }
        if (gquic_packet_long_header_deserialize_unseal_part(unpacked_packet->hdr.hdr.l_hdr, &reader) != 0) {
            return -3;
        }
    }
    else {
        if ((unpacked_packet->hdr.hdr.s_hdr = malloc(sizeof(gquic_packet_short_header_t))) == NULL) {
            return -4;
        }
        if (gquic_packet_short_header_deserialize_unseal_part(unpacked_packet->hdr.hdr.s_hdr, &reader) != 0) {
            return -5;
        }
    }
    if (gquic_packet_unpacker_unpack_header(unpacked_packet, unpacker, payload, &reader) != 0) {
        return -6;
    }

    u_int64_t header_len = GQUIC_STR_VAL(&reader) - GQUIC_STR_VAL(payload->data);
    gquic_str_t tag = { 16, GQUIC_STR_VAL(payload->data) + header_len };
    gquic_str_t cipher_text = { GQUIC_STR_SIZE(payload->data) - header_len - 16, GQUIC_STR_VAL(payload->data) + header_len + 16 };
    gquic_str_t addata = { header_len, GQUIC_STR_VAL(payload->data) };
    if (GQUIC_UNPACKED_PACKET_PAYLOAD_OPEN(&unpacked_packet->data,
                                       payload,
                                       payload->recv_time,
                                       gquic_packet_header_get_pn(&unpacked_packet->hdr),
                                       unpacked_packet->hdr.is_long == 0 && ((GQUIC_STR_FIRST_BYTE(payload->data) & 0x04) != 0),
                                       &tag,
                                       &cipher_text,
                                       &addata) != 0) {
        return -7;
    }

    return 0;
}

static int gquic_packet_unpacker_unpack_header(gquic_unpacked_packet_t *const unpacked_packet,
                                               gquic_packet_unpacker_t *const unpacker,
                                               gquic_unpacked_packet_payload_t *const payload,
                                               gquic_reader_str_t *const reader) {
    u_int64_t deserialized_hdr_size = 0;
    u_int8_t origin_pn[4] = { 0 };
    int pn_len = 0;
    if (unpacked_packet == NULL || unpacker == NULL || payload == NULL || reader == NULL) {
        return -1;
    }
    deserialized_hdr_size = GQUIC_STR_VAL(reader) - GQUIC_STR_VAL(payload->data);
    if (GQUIC_STR_SIZE(payload->data) < deserialized_hdr_size + 4 + 16) {
        return -2;
    }
    memcpy(origin_pn, GQUIC_STR_VAL(payload->data) + deserialized_hdr_size, 4);
    gquic_str_t header = { 4, GQUIC_STR_VAL(payload->data) + deserialized_hdr_size };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(payload->data) + deserialized_hdr_size + 4 };
    if (unpacked_packet->hdr.is_long) {
        GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &unpacked_packet->hdr.hdr.l_hdr->flag, payload->header_opener, &sample);
        pn_len = (0x03 & unpacked_packet->hdr.hdr.l_hdr->flag) + 1;
        if (pn_len != 4) {
            memcpy(GQUIC_STR_VAL(payload->data) + deserialized_hdr_size, origin_pn, 4);
        }
        if (gquic_packet_long_header_deserialize_seal_part(unpacked_packet->hdr.hdr.l_hdr, reader) != 0) {
            return -3;
        }
    }
    else {
        GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &unpacked_packet->hdr.hdr.s_hdr->flag, payload->header_opener, &sample);
        pn_len = (0x03 & unpacked_packet->hdr.hdr.l_hdr->flag) + 1;
        if (pn_len != 4) {
            memcpy(GQUIC_STR_VAL(payload->data) + deserialized_hdr_size, origin_pn, 4);
        }
        if (gquic_packet_short_header_deserialize_seal_part(unpacked_packet->hdr.hdr.s_hdr, reader) != 0) {
            return -4;
        }
    }

    gquic_packet_header_set_pn(&unpacked_packet->hdr,
                               gquic_pn_decode(pn_len, unpacker->largest_recv_pn, gquic_packet_header_get_pn(&unpacked_packet->hdr)));
    return 0;
}
