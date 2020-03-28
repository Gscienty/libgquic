#include "packet/unpacker.h"
#include "packet/packet_number.h"
#include "exception.h"

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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    payload->data = NULL;
    payload->opener.is_1rtt = 0;
    payload->opener.cb.cb = NULL;
    payload->opener.cb.one_rtt_cb = NULL;
    payload->opener.self = NULL;
    payload->header_opener = NULL;
    payload->recv_time = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_unpacked_packet_init(gquic_unpacked_packet_t *const unpacked_packet) {
    if (unpacked_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unpacked_packet->valid = 0;
    unpacked_packet->pn = 0;
    gquic_packet_header_init(&unpacked_packet->hdr);
    unpacked_packet->enc_lv = 0;
    gquic_str_init(&unpacked_packet->data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_unpacked_packet_dtor(gquic_unpacked_packet_t *const unpacked_packet) {
    if (unpacked_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_header_dtor(&unpacked_packet->hdr);
    gquic_str_reset(&unpacked_packet->data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_unpacker_init(gquic_packet_unpacker_t *const unpacker) {
    if (unpacker == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unpacker->est = 0;
    unpacker->largest_recv_pn = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_unpacker_ctor(gquic_packet_unpacker_t *const unpacker, gquic_handshake_establish_t *const est) {
    if (unpacker == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unpacker->est = est;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_unpacker_unpack(gquic_unpacked_packet_t *const unpacked_packet,
                                 gquic_packet_unpacker_t *const unpacker,
                                 const gquic_str_t *const data,
                                 const u_int64_t recv_time) {
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
            payload.opener.is_1rtt = 0;
            payload.opener.cb.cb = gquic_common_long_header_opener_open_wrapper;
            GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_initial_opener(&payload.header_opener,
                                                                                  (gquic_common_long_header_opener_t **) &payload.opener.self,
                                                                                  unpacker->est));
            break;
        case 0x02:
            unpacked_packet->enc_lv = GQUIC_ENC_LV_HANDSHAKE;
            payload.opener.is_1rtt = 0;
            payload.opener.cb.cb = gquic_common_long_header_opener_open_wrapper;
            GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_handshake_opener(&payload.header_opener,
                                                                      (gquic_common_long_header_opener_t **) &payload.opener.self,
                                                                      unpacker->est));
            break;
        default:
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
        }
        unpacked_packet->hdr.is_long = 1;
    }
    else if ((GQUIC_STR_FIRST_BYTE(data) & 0xc0) == 0x40) {
        unpacked_packet->enc_lv = GQUIC_ENC_LV_1RTT;
        payload.opener.is_1rtt = 1;
        payload.opener.cb.one_rtt_cb = gquic_1rtt_opener_open_wrapper;
        payload.header_opener = &unpacker->est->aead.header_dec;
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_1rtt_opener(&payload.header_opener,
                                                             (gquic_auto_update_aead_t **) &payload.opener.self,
                                                             unpacker->est));
        unpacked_packet->hdr.is_long = 0;
    }
    else {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_packet_unpacker_unpack_header_packet(unpacked_packet, unpacker, &payload));

    u_int64_t tmp_pn = gquic_packet_header_get_pn(&unpacked_packet->hdr);
    if (unpacker->largest_recv_pn < tmp_pn) {
        unpacker->largest_recv_pn = tmp_pn;
    }
    unpacked_packet->valid = 1;
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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
    int exception = GQUIC_SUCCESS;
    gquic_reader_str_t reader = { 0, NULL };
    if (unpacked_packet == NULL || unpacker == NULL || payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    reader = *payload->data;
    if (unpacked_packet->hdr.is_long) {
        if ((unpacked_packet->hdr.hdr.l_hdr = gquic_packet_long_header_alloc()) == NULL) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_long_header_deserialize_unseal_part(unpacked_packet->hdr.hdr.l_hdr, &reader));
        
    }
    else {
        if ((unpacked_packet->hdr.hdr.s_hdr = malloc(sizeof(gquic_packet_short_header_t))) == NULL) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_short_header_deserialize_unseal_part(unpacked_packet->hdr.hdr.s_hdr, &reader));
    }
    GQUIC_ASSERT_CAUSE(exception, gquic_packet_unpacker_unpack_header(unpacked_packet, unpacker, payload, &reader));
    if (exception != GQUIC_SUCCESS && exception != GQUIC_EXCEPTION_INVALID_RESERVED_BITS) {
        GQUIC_PROCESS_DONE(exception);
    }

    u_int64_t header_len = GQUIC_STR_VAL(&reader) - GQUIC_STR_VAL(payload->data);
    gquic_str_t tag = { 16, GQUIC_STR_VAL(payload->data) + header_len };
    gquic_str_t cipher_text = { GQUIC_STR_SIZE(payload->data) - header_len - 16, GQUIC_STR_VAL(payload->data) + header_len + 16 };
    gquic_str_t addata = { header_len, GQUIC_STR_VAL(payload->data) };
    GQUIC_ASSERT_FAST_RETURN(GQUIC_UNPACKED_PACKET_PAYLOAD_OPEN(&unpacked_packet->data,
                                                                payload,
                                                                payload->recv_time,
                                                                gquic_packet_header_get_pn(&unpacked_packet->hdr),
                                                                unpacked_packet->hdr.is_long == 0 && ((GQUIC_STR_FIRST_BYTE(payload->data) & 0x04) != 0),
                                                                &tag, &cipher_text, &addata));
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_packet_unpacker_unpack_header(gquic_unpacked_packet_t *const unpacked_packet,
                                               gquic_packet_unpacker_t *const unpacker,
                                               gquic_unpacked_packet_payload_t *const payload,
                                               gquic_reader_str_t *const reader) {
    int exception = GQUIC_SUCCESS;
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
    GQUIC_HEADER_PROTECTOR_SET_KEY(payload->header_opener, &sample);
    if (unpacked_packet->hdr.is_long) {
        GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &unpacked_packet->hdr.hdr.l_hdr->flag, payload->header_opener);
        pn_len = gquic_packet_number_flag_to_size(unpacked_packet->hdr.hdr.l_hdr->flag);
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_long_header_deserialize_seal_part(unpacked_packet->hdr.hdr.l_hdr, reader));
        if ((unpacked_packet->hdr.hdr.l_hdr->flag & 0x0c) != 0) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INVALID_RESERVED_BITS);
        }
        *(u_int8_t *) GQUIC_STR_VAL(payload->data) = unpacked_packet->hdr.hdr.l_hdr->flag;
    }
    else {
        GQUIC_HEADER_PROTECTOR_DECRYPT(&header, &unpacked_packet->hdr.hdr.s_hdr->flag, payload->header_opener);
        pn_len = gquic_packet_number_flag_to_size(unpacked_packet->hdr.hdr.s_hdr->flag);
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_short_header_deserialize_seal_part(unpacked_packet->hdr.hdr.s_hdr, reader));
        if ((unpacked_packet->hdr.hdr.s_hdr->flag & 0x18) != 0) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INVALID_RESERVED_BITS);
        }
        *(u_int8_t *) GQUIC_STR_VAL(payload->data) = unpacked_packet->hdr.hdr.s_hdr->flag;
    }
    if (pn_len != 4) {
        memcpy(GQUIC_STR_VAL(payload->data) + deserialized_hdr_size + pn_len, origin_pn + pn_len, 4 - pn_len);
    }
    gquic_packet_header_set_pn(&unpacked_packet->hdr,
                               gquic_packet_number_decode(pn_len, unpacker->largest_recv_pn, gquic_packet_header_get_pn(&unpacked_packet->hdr)));

    GQUIC_PROCESS_DONE(exception);
}
