#include "packet/packer.h"
#include "tls/common.h"
#include "frame/meta.h"
#include "frame/ping.h"
#include "util/time.h"
#include "util/malloc.h"
#include "exception.h"

static int gquic_retransmission_queue_add_initial_wrapper(void *const, void *const);
static int gquic_retransmission_queue_add_handshake_wrapper(void *const, void *const);
static int gquic_retransmission_queue_add_app_wrapper(void *const, void *const);

static int gquic_common_long_header_sealer_seal_wrapper(gquic_str_t *const,
                                               gquic_str_t *const,
                                               void *const,
                                               const u_int64_t,
                                               const gquic_str_t *const,
                                               const gquic_str_t *const);
static int gquic_1rtt_sealer_seal_wrapper(gquic_str_t *const,
                                          gquic_str_t *const,
                                          void *const,
                                          const u_int64_t,
                                          const gquic_str_t *const,
                                          const gquic_str_t *const);

static int gquic_packet_packer_get_sealer_and_header(gquic_packed_packet_payload_t *const, gquic_packet_packer_t *const);

int gquic_packed_packet_init(gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    packed_packet->valid = 0;
    gquic_packet_header_init(&packed_packet->hdr);
    gquic_str_init(&packed_packet->raw);
    packed_packet->ack = NULL;
    packed_packet->frames = NULL;
    packed_packet->buffer = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packed_packet_dtor(gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (packed_packet->hdr.is_long) {
        if (packed_packet->hdr.hdr.l_hdr != NULL) {
            gquic_packet_long_header_release(packed_packet->hdr.hdr.l_hdr);
        }
    }
    else {
        if (packed_packet->hdr.hdr.s_hdr != NULL) {
            free(packed_packet->hdr.hdr.s_hdr);
        }
    }
    if (packed_packet->ack != NULL) {
        gquic_frame_release(packed_packet->ack);
    }
    if (packed_packet->frames != NULL) {
        while (!gquic_list_head_empty(packed_packet->frames)) {
            gquic_frame_release(*(void **) GQUIC_LIST_FIRST(packed_packet->frames));
            gquic_list_release(GQUIC_LIST_FIRST(packed_packet->frames));
        }
        free(packed_packet->frames);
    }
    gquic_packet_buffer_put(packed_packet->buffer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packed_packet_dtor_without_frames(gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (packed_packet->hdr.is_long) {
        if (packed_packet->hdr.hdr.l_hdr != NULL) {
            gquic_packet_long_header_release(packed_packet->hdr.hdr.l_hdr);
        }
    }
    else {
        if (packed_packet->hdr.hdr.s_hdr != NULL) {
            free(packed_packet->hdr.hdr.s_hdr);
        }
    }
    gquic_packet_buffer_put(packed_packet->buffer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int8_t gquic_packed_packet_enc_lv(const gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        return 0;
    }
    if (!packed_packet->hdr.is_long) {
        return GQUIC_ENC_LV_1RTT;
    }
    switch (gquic_packet_long_header_type(packed_packet->hdr.hdr.l_hdr)) {
    case GQUIC_LONG_HEADER_INITIAL:
        return GQUIC_ENC_LV_INITIAL;
    case GQUIC_LONG_HEADER_HANDSHAKE:
        return GQUIC_ENC_LV_HANDSHAKE;
    }

    return 0;
}

int gquic_packed_packet_is_ack_eliciting(gquic_packed_packet_t *const packed_packet) {
    if (packed_packet == NULL) {
        return 0;
    }

    return gquic_frames_has_frame_ack(packed_packet->frames);
}

int gquic_packed_packet_get_ack_packet(gquic_packet_t *const packet,
                                       gquic_packed_packet_t *const packed_packet,
                                       gquic_retransmission_queue_t *const queue) {
    u_int64_t largest_ack = (u_int64_t) -1;
    u_int8_t enc_lv = 0;
    void *frame_storage = NULL;
    if (packet == NULL || packed_packet == NULL || queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_init(packet);
    if (packed_packet->ack != NULL) {
        largest_ack = packed_packet->ack->largest_ack;
    }
    enc_lv = gquic_packed_packet_enc_lv(packed_packet);
    GQUIC_LIST_FOREACH(frame_storage, packed_packet->frames) {
        if (GQUIC_FRAME_META(*(void **) frame_storage).on_lost.self != NULL) {
            continue;
        }
        switch (enc_lv) {
        case GQUIC_ENC_LV_INITIAL:
            GQUIC_FRAME_META(*(void **) frame_storage).on_lost.self = queue;
            GQUIC_FRAME_META(*(void **) frame_storage).on_lost.cb = gquic_retransmission_queue_add_initial_wrapper;
            break;
        case GQUIC_ENC_LV_HANDSHAKE:
            GQUIC_FRAME_META(*(void **) frame_storage).on_lost.self = queue;
            GQUIC_FRAME_META(*(void **) frame_storage).on_lost.cb = gquic_retransmission_queue_add_handshake_wrapper;
            break;
        case GQUIC_ENC_LV_1RTT:
            GQUIC_FRAME_META(*(void **) frame_storage).on_lost.self = queue;
            GQUIC_FRAME_META(*(void **) frame_storage).on_lost.cb = gquic_retransmission_queue_add_app_wrapper;
            break;
        }
    }
    packet->pn = gquic_packet_header_get_pn(&packed_packet->hdr);
    packet->largest_ack = largest_ack;
    packet->frames = packed_packet->frames;
    packet->len = GQUIC_STR_SIZE(&packed_packet->raw);
    packet->enc_lv = enc_lv;
    packet->send_time = gquic_time_now();

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_retransmission_queue_add_initial_wrapper(void *const self, void *const frame) {
    return gquic_retransmission_queue_add_initial(self, frame);
}

static int gquic_retransmission_queue_add_handshake_wrapper(void *const self, void *const frame) {
    return gquic_retransmission_queue_add_handshake(self, frame);
}

static int gquic_retransmission_queue_add_app_wrapper(void *const self, void *const frame) {
    return gquic_retransmission_queue_add_app(self, frame);
}

int gquic_packed_packet_payload_init(gquic_packed_packet_payload_t *const payload) {
    if (payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    payload->frames = NULL;
    payload->ack = NULL;
    payload->len = 0;
    payload->sealer.cb = NULL;
    payload->sealer.self = NULL;
    payload->header_sealer = NULL;
    gquic_packet_header_init(&payload->hdr);
    payload->enc_lv = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packed_packet_payload_dtor(gquic_packed_packet_payload_t *const payload) {
    if (payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (payload->frames != NULL) {
        while (!gquic_list_head_empty(payload->frames)) {
            gquic_frame_release(*(void **) GQUIC_LIST_FIRST(payload->frames));
            gquic_list_release(GQUIC_LIST_FIRST(payload->frames));
        }
        free(payload->frames);
    }
    if (payload->ack != NULL) {
        gquic_frame_release(payload->ack);
    }
    if (payload->hdr.is_long && payload->hdr.hdr.l_hdr != NULL) {
        gquic_packet_long_header_release(payload->hdr.hdr.l_hdr);
    }
    if (!payload->hdr.is_long && payload->hdr.hdr.s_hdr != NULL) {
        free(payload->hdr.hdr.s_hdr);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_init(gquic_packet_packer_t *const packer) {
    if (packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&packer->conn_id);
    packer->get_conn_id.cb = NULL;
    packer->get_conn_id.self = NULL;
    packer->is_client = 0;
    packer->est = NULL;
    packer->droped_initial = 0;
    packer->droped_handshake = 0;
    packer->initial_stream = NULL;
    packer->handshake_stream = NULL;
    gquic_str_init(&packer->token);
    packer->pn_gen = NULL;
    packer->framer = NULL;
    packer->acks = NULL;
    packer->retransmission_queue = NULL;
    packer->max_packet_size = 0;
    packer->non_ack_eliciting_acks_count = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_ctor(gquic_packet_packer_t *const packer,
                             const gquic_str_t *const src_id,
                             void *const get_conn_id_self,
                             int (*get_conn_id_cb) (gquic_str_t *const, void *const),
                             gquic_crypto_stream_t *const initial_stream,
                             gquic_crypto_stream_t *const handshake_stream,
                             gquic_packet_sent_packet_handler_t *const pn_gen,
                             gquic_retransmission_queue_t *const retransmission_queue,
                             const u_int64_t max_packet_size,
                             gquic_handshake_establish_t *const est,
                             gquic_framer_t *const framer,
                             gquic_packet_received_packet_handlers_t *acks,
                             const int is_client) {
    if (packer == NULL
        || src_id == NULL
        || get_conn_id_self == NULL
        || get_conn_id_cb == NULL
        || initial_stream == NULL
        || handshake_stream == NULL
        || pn_gen == NULL
        || retransmission_queue == NULL
        || est == NULL
        || framer == NULL
        || acks == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_copy(&packer->conn_id, src_id);
    packer->get_conn_id.self = get_conn_id_self;
    packer->get_conn_id.cb = get_conn_id_cb;
    packer->is_client = is_client;
    packer->est = est;
    packer->initial_stream = initial_stream;
    packer->handshake_stream = handshake_stream;
    packer->pn_gen = pn_gen;
    packer->framer = framer;
    packer->acks = acks;
    packer->retransmission_queue = retransmission_queue;
    packer->max_packet_size = max_packet_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_dtor(gquic_packet_packer_t *const packer) {
    if (packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&packer->conn_id);
    gquic_str_reset(&packer->token);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_pack_conn_close(gquic_packed_packet_t *const packed_packet,
                                        gquic_packet_packer_t *const packer,
                                        const gquic_frame_connection_close_t *const conn_close) {
    int exception = GQUIC_SUCCESS;
    gquic_packed_packet_payload_t payload;
    const void **frame_storage = NULL;
    if (packed_packet == NULL || packer == NULL || conn_close == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packed_packet_payload_init(&payload);
    if ((payload.frames = malloc(sizeof(gquic_list_t))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_list_head_init(payload.frames);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &frame_storage, sizeof(void *)))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }
    *frame_storage = conn_close;
    gquic_list_insert_before(payload.frames, frame_storage);
    payload.len = GQUIC_FRAME_SIZE(conn_close);

    if (!GQUIC_ASSERT_CAUSE(exception,
                            gquic_handshake_establish_get_1rtt_sealer(&payload.header_sealer,
                                                                      (gquic_auto_update_aead_t **) &payload.sealer.self,
                                                                      packer->est))) {
        payload.sealer.cb = gquic_1rtt_sealer_seal_wrapper;
        gquic_packet_packer_get_short_header(&payload.hdr, packer, packer->est->aead.times);
        payload.enc_lv = GQUIC_ENC_LV_1RTT;
    }
    else if (!GQUIC_ASSERT_CAUSE(exception,
                                 gquic_handshake_establish_get_handshake_sealer(&payload.header_sealer,
                                                                                (gquic_common_long_header_sealer_t **) &payload.sealer.self,
                                                                                packer->est))) {
        payload.sealer.cb = gquic_common_long_header_sealer_seal_wrapper;
        gquic_packet_packer_get_long_header(&payload.hdr, packer, GQUIC_ENC_LV_HANDSHAKE);
        payload.enc_lv = GQUIC_ENC_LV_HANDSHAKE;
    }
    else if (!GQUIC_ASSERT_CAUSE(exception, gquic_handshake_establish_get_initial_sealer(&payload.header_sealer,
                                                                 (gquic_common_long_header_sealer_t **) &payload.sealer.self,
                                                                 packer->est))) {
        payload.sealer.cb = gquic_common_long_header_sealer_seal_wrapper;
        gquic_common_long_header_sealer_get_header_sealer(&payload.header_sealer, &packer->est->initial_sealer);
        gquic_packet_packer_get_long_header(&payload.hdr, packer, GQUIC_ENC_LV_INITIAL);
        payload.enc_lv = GQUIC_ENC_LV_INITIAL;
    }
    else {
        GQUIC_PROCESS_DONE(exception);
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_pack(packed_packet, packer, &payload))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_common_long_header_sealer_seal_wrapper(gquic_str_t *const tag,
                                                        gquic_str_t *const cipher_text,
                                                        void *const self,
                                                        const u_int64_t pn,
                                                        const gquic_str_t *const plain_text,
                                                        const gquic_str_t *const addata) {
    return gquic_common_long_header_sealer_seal(tag, cipher_text, self, pn, plain_text, addata);
}

static int gquic_1rtt_sealer_seal_wrapper(gquic_str_t *const tag,
                                          gquic_str_t *const cipher_text,
                                          void *const self,
                                          const u_int64_t pn,
                                          const gquic_str_t *const plain_text,
                                          const gquic_str_t *const addata) {
    return gquic_auto_update_aead_seal(tag, cipher_text, self, pn, plain_text, addata);
}

int gquic_packet_packer_get_short_header(gquic_packet_header_t *const hdr, gquic_packet_packer_t *const packer, const int times) {
    int pn_len = 0;
    gquic_str_t dcid = { 0, NULL };
    if (hdr == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    hdr->is_long = 0;
    if ((hdr->hdr.s_hdr = gquic_packet_short_header_alloc()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_packet_handler_peek_pn(&hdr->hdr.s_hdr->pn, &pn_len, packer->pn_gen, GQUIC_ENC_LV_1RTT));
    hdr->hdr.s_hdr->flag = 0x40 | (0x03 & (pn_len - 1)) | (((times % 2) == 1) ? 0x04 : 0);
    GQUIC_ASSERT_FAST_RETURN(GQUIC_PACKET_PACKER_GET_CONN_ID(&dcid, packer));
    hdr->hdr.s_hdr->dcid_len = GQUIC_STR_SIZE(&dcid);
    memcpy(hdr->hdr.s_hdr->dcid, GQUIC_STR_VAL(&dcid), GQUIC_STR_SIZE(&dcid));

    gquic_str_reset(&dcid);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_get_long_header(gquic_packet_header_t *const hdr, gquic_packet_packer_t *const packer, const u_int8_t enc_lv) {
    u_int64_t pn = 0;
    int pn_len = 0;
    gquic_str_t dcid = { 0, NULL };
    if (hdr == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    hdr->is_long = 1;
    if ((hdr->hdr.l_hdr = gquic_packet_long_header_alloc()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_packet_handler_peek_pn(&pn, &pn_len, packer->pn_gen, enc_lv));
    GQUIC_ASSERT_FAST_RETURN(GQUIC_PACKET_PACKER_GET_CONN_ID(&dcid, packer));
    memcpy(hdr->hdr.l_hdr->dcid, GQUIC_STR_VAL(&dcid), GQUIC_STR_SIZE(&dcid));
    hdr->hdr.l_hdr->dcid_len = GQUIC_STR_SIZE(&dcid);
    memcpy(hdr->hdr.l_hdr->scid, GQUIC_STR_VAL(&packer->conn_id), GQUIC_STR_SIZE(&packer->conn_id));
    hdr->hdr.l_hdr->scid_len = GQUIC_STR_SIZE(&packer->conn_id);

    if (enc_lv == GQUIC_ENC_LV_INITIAL) {
        hdr->hdr.l_hdr->flag = 0xc0 | (0x03 & (pn_len - 1));
        ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->pn = pn;
        ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->len = packer->max_packet_size;
        ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->token_len = GQUIC_STR_SIZE(&packer->token);
        if ((((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->token = malloc(GQUIC_STR_SIZE(&packer->token))) == NULL) {
            gquic_str_reset(&dcid);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
        }
        memcpy(((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->token,
               GQUIC_STR_VAL(&packer->token),
               GQUIC_STR_SIZE(&packer->token));
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    else if (enc_lv == GQUIC_ENC_LV_HANDSHAKE) {
        hdr->hdr.l_hdr->flag = 0xc0 | 0x20 | (0x03 & (pn_len - 1));
        ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->pn = pn;
        ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(hdr->hdr.l_hdr))->len = packer->max_packet_size;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
}

int gquic_packet_packer_pack(gquic_packed_packet_t *const packed_packet,
                             gquic_packet_packer_t *const packer,
                             gquic_packed_packet_payload_t *const payload) {
    int pn_len = 0;
    u_int64_t padding_len = 0;
    u_int8_t header_type = 4; 
    if (packed_packet == NULL || packer == NULL || payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (payload->hdr.is_long) {
        if (payload->hdr.hdr.l_hdr == NULL) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_NOT_EXIST);
        }
        pn_len = (0x03 & payload->hdr.hdr.l_hdr->flag) + 1;
        header_type = (payload->hdr.hdr.l_hdr->flag & 0x30) >> 4;
    }
    else {
        if (payload->hdr.hdr.s_hdr == NULL) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_NOT_EXIST);
        }
        pn_len = (0x03 & payload->hdr.hdr.s_hdr->flag) + 1;
    }

    if (payload->enc_lv != GQUIC_ENC_LV_1RTT) {
        if (packer->is_client && header_type == 0x00) {
            size_t header_len = gquic_packet_header_size(&payload->hdr);
            padding_len = 1200 - 16 - header_len - payload->len;
            gquic_packet_header_set_len(&payload->hdr, pn_len + 1200 - header_len);
        }
        else {
            gquic_packet_header_set_len(&payload->hdr, pn_len + 16 + payload->len);
        }
    }
    else if ((int) payload->len < 4 - pn_len) {
        padding_len = 4 - pn_len - payload->len;
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_pack_with_padding(packed_packet, packer, payload, padding_len));
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_pack_with_padding(gquic_packed_packet_t *const packed_packet,
                                          gquic_packet_packer_t *const packer,
                                          gquic_packed_packet_payload_t *const payload,
                                          const u_int64_t padding_len) {
    int exception = GQUIC_SUCCESS;
    int pn_len = 0;
    u_int64_t hdr_pn = 0;
    void **frame_storage = NULL;
    gquic_packet_buffer_t *buffer = NULL;
    u_int64_t header_size = 0;
    gquic_str_t tag = { 0, NULL };
    gquic_str_t cipher_text = { 0, NULL };
    gquic_str_t seal_header = { 0, NULL };
    if (packed_packet == NULL || packer == NULL || payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_buffer_get(&buffer));
    gquic_writer_str_t writer = buffer->slice;
    if (payload->hdr.is_long) {
        pn_len = gquic_packet_number_flag_to_size(payload->hdr.hdr.l_hdr->flag);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_long_header_serialize(payload->hdr.hdr.l_hdr, &writer))) {
            goto failure;
        }
    }
    else {
        pn_len = gquic_packet_number_flag_to_size(payload->hdr.hdr.s_hdr->flag);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_short_header_serialize(payload->hdr.hdr.s_hdr, &writer))) {
            goto failure;
        }
    }
    hdr_pn = gquic_packet_header_get_pn(&payload->hdr);
    header_size = GQUIC_STR_VAL(&writer) - GQUIC_STR_VAL(&buffer->slice);
    if (payload->ack != NULL) {
        if (GQUIC_ASSERT_CAUSE(exception, GQUIC_FRAME_SERIALIZE(payload->ack, &writer))) {
            goto failure;
        }
    }
    if (padding_len > 0) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_writer_str_write_padding(&writer, 0, padding_len))) {
            goto failure;
        }
    }
    if (payload->frames != NULL) {
        GQUIC_LIST_FOREACH(frame_storage, payload->frames) {
            if (GQUIC_ASSERT_CAUSE(exception, GQUIC_FRAME_SERIALIZE(*frame_storage, &writer))) {
                goto failure;
            }
        }
    }
    if (GQUIC_STR_VAL(&writer) - GQUIC_STR_VAL(&buffer->slice) - header_size - padding_len != payload->len) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
        goto failure;
    }
    if ((u_int64_t) (GQUIC_STR_VAL(&writer) - GQUIC_STR_VAL(&buffer->slice) + 16) > packer->max_packet_size) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
        goto failure;
    }

    const gquic_str_t plain_text = {
        GQUIC_STR_VAL(&writer) - GQUIC_STR_VAL(&buffer->slice) - header_size,
        GQUIC_STR_VAL(&buffer->slice) + header_size
    };
    const gquic_str_t addata = { header_size, GQUIC_STR_VAL(&buffer->slice) };

    if (GQUIC_ASSERT_CAUSE(exception,
                           GQUIC_PACKED_PACKET_PAYLOAD_SEAL(&tag, &cipher_text,
                                                            payload,
                                                            gquic_packet_header_get_pn(&payload->hdr), &plain_text, &addata))) {
        goto failure;
    }

    if (header_size + GQUIC_STR_SIZE(&tag) + GQUIC_STR_SIZE(&cipher_text) > GQUIC_STR_SIZE(&buffer->slice)) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
        goto failure;
    }

    // set payload
    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size, GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));
    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&tag), GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text));

    // seal header
    gquic_str_t header = { pn_len, GQUIC_STR_VAL(&buffer->slice) + header_size - pn_len };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(&buffer->slice) + header_size - pn_len + 4 };
    u_int8_t first = GQUIC_STR_FIRST_BYTE(&buffer->slice);
    GQUIC_HEADER_PROTECTOR_SET_KEY(payload->header_sealer, &sample);
    GQUIC_HEADER_PROTECTOR_ENCRYPT(&header, &first, payload->header_sealer);
    *(u_int8_t *) GQUIC_STR_VAL(&buffer->slice) = first;

    u_int64_t pn;
    if (GQUIC_ASSERT(gquic_packet_sent_packet_handler_pop_pn(&pn, packer->pn_gen, payload->enc_lv)) || hdr_pn != pn) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
        goto failure;
    }
    
    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    packed_packet->valid = 1;
    packed_packet->ack = payload->ack;
    packed_packet->buffer = buffer;
    packed_packet->hdr = payload->hdr;
    packed_packet->frames = payload->frames;
    gquic_str_t cnt = { GQUIC_STR_VAL(&buffer->writer) - GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_VAL(&buffer->slice) };
    packed_packet->raw = cnt;

    gquic_str_reset(&tag);
    gquic_str_reset(&cipher_text);
    gquic_str_reset(&seal_header);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&tag);
    gquic_str_reset(&cipher_text);
    gquic_str_reset(&seal_header);
    gquic_packet_buffer_put(buffer);
    GQUIC_PROCESS_DONE(exception);
}

int gquic_packet_packer_try_pack_ack_packet(gquic_packed_packet_t *const packed_packet,
                                            gquic_packet_packer_t *const packer) {
    int exception = GQUIC_SUCCESS;
    gquic_packed_packet_payload_t payload;
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packed_packet_payload_init(&payload);
    if (!gquic_packet_packer_handshake_confirmed(packer)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handlers_get_ack_frame(&payload.ack, packer->acks, GQUIC_ENC_LV_INITIAL));
        if (payload.ack != NULL) {
            payload.enc_lv = GQUIC_ENC_LV_INITIAL;
        }
        else {
            if (GQUIC_ASSERT_CAUSE(exception,
                                   gquic_packet_received_packet_handlers_get_ack_frame(&payload.ack, packer->acks, GQUIC_ENC_LV_HANDSHAKE))) {
                gquic_packed_packet_payload_dtor(&payload);
                GQUIC_PROCESS_DONE(exception);
            }
            if (payload.ack != NULL) {
                payload.enc_lv = GQUIC_ENC_LV_HANDSHAKE;
            }
        }
    }
    if (payload.ack == NULL) {
        if (GQUIC_ASSERT_CAUSE(exception,
                               gquic_packet_received_packet_handlers_get_ack_frame(&payload.ack, packer->acks, GQUIC_ENC_LV_1RTT))) {
            gquic_packed_packet_payload_dtor(&payload);
            GQUIC_PROCESS_DONE(exception);
        }
        if (payload.ack != NULL) {
            payload.enc_lv = GQUIC_ENC_LV_HANDSHAKE;
        }
        else {
            gquic_packed_packet_payload_dtor(&payload);
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }
    payload.len = GQUIC_FRAME_SIZE(payload.ack);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_get_sealer_and_header(&payload, packer))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_pack(packed_packet, packer, &payload))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_packer_get_sealer_and_header(gquic_packed_packet_payload_t *const payload,
                                                     gquic_packet_packer_t *const packer) {
    if (payload == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (payload->enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_initial_sealer(&payload->header_sealer,
                                                                (gquic_common_long_header_sealer_t **) &payload->sealer.self, packer->est))
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_get_long_header(&payload->hdr, packer, GQUIC_ENC_LV_INITIAL));
        payload->sealer.cb = gquic_common_long_header_sealer_seal_wrapper;
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_handshake_sealer(&payload->header_sealer,
                                                       (gquic_common_long_header_sealer_t **) &payload->sealer.self, packer->est));
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_get_long_header(&payload->hdr, packer, GQUIC_ENC_LV_HANDSHAKE));
        payload->sealer.cb = gquic_common_long_header_sealer_seal_wrapper;
        break;
    case GQUIC_ENC_LV_1RTT:
        GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_1rtt_sealer(&payload->header_sealer,
                                                  (gquic_auto_update_aead_t **) &payload->sealer.self, packer->est));
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_get_short_header(&payload->hdr, packer, packer->est->aead.times));
        payload->sealer.cb = gquic_1rtt_sealer_seal_wrapper;
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_try_pack_initial_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer) {
    int exception = GQUIC_SUCCESS;
    gquic_packed_packet_payload_t payload;
    int has_retransmission = 0;
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packed_packet_payload_init(&payload);

    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_initial_sealer(&payload.header_sealer,
                                                                          (gquic_common_long_header_sealer_t **) &payload.sealer.self, packer->est));
    payload.sealer.cb = gquic_common_long_header_sealer_seal_wrapper;
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handlers_get_ack_frame(&payload.ack, packer->acks, GQUIC_ENC_LV_INITIAL));
    if (payload.ack != NULL) {
        payload.len = GQUIC_FRAME_SIZE(payload.ack);
    }
    has_retransmission = gquic_retransmission_queue_has_initial(packer->retransmission_queue);
    if (!gquic_crypto_stream_has_data(packer->initial_stream) && !has_retransmission && payload.ack == NULL) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&payload.frames, gquic_list_t))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }
    gquic_list_head_init(payload.frames);
    payload.enc_lv = GQUIC_ENC_LV_INITIAL;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_pack_crypto_packet(packed_packet, packer, &payload, has_retransmission))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_try_pack_handshake_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer) {
    int exception = GQUIC_SUCCESS;
    gquic_packed_packet_payload_t payload;
    int has_retransmission = 0;
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packed_packet_payload_init(&payload);

    payload.sealer.cb = gquic_common_long_header_sealer_seal_wrapper;
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_get_handshake_sealer(&payload.header_sealer,
                                                                            (gquic_common_long_header_sealer_t **) &payload.sealer.self,
                                                                            packer->est));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handlers_get_ack_frame(&payload.ack, packer->acks, GQUIC_ENC_LV_INITIAL));
    if (payload.ack != NULL) {
        payload.len = GQUIC_FRAME_SIZE(payload.ack);
    }
    has_retransmission = gquic_retransmission_queue_has_initial(packer->retransmission_queue);
    if (!gquic_crypto_stream_has_data(packer->handshake_stream) && !has_retransmission && payload.ack == NULL) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&payload.frames, gquic_list_t))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }
    gquic_list_head_init(payload.frames);
    payload.enc_lv = GQUIC_ENC_LV_HANDSHAKE;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_pack_crypto_packet(packed_packet, packer, &payload, has_retransmission))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_try_pack_app_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer) {
    int exception = GQUIC_SUCCESS;
    u_int64_t header_len = 0;
    u_int64_t max_size = 0;
    u_int64_t remain = 0;
    u_int64_t added_size = 0;
    gquic_packed_packet_payload_t payload;
    void *frame = NULL;
    void **frame_storage = NULL;
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packed_packet_payload_init(&payload);
    if (GQUIC_ASSERT(gquic_handshake_establish_get_1rtt_sealer(&payload.header_sealer,
                                                               (gquic_auto_update_aead_t **) &payload.sealer.self, packer->est))) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    payload.sealer.cb = gquic_1rtt_sealer_seal_wrapper;

    payload.enc_lv = GQUIC_ENC_LV_1RTT;
    if ((payload.frames = malloc(sizeof(gquic_list_t))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_list_head_init(payload.frames);
    if (gquic_packet_packer_get_short_header(&payload.hdr, packer, packer->est->aead.times) != 0) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    header_len = gquic_packet_short_header_size(payload.hdr.hdr.s_hdr);
    max_size = packer->max_packet_size - 16 - header_len;

    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_packet_received_packet_handlers_get_ack_frame(&payload.ack, packer->acks, GQUIC_ENC_LV_1RTT))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }
    if (payload.ack != NULL) {
        payload.len += GQUIC_FRAME_SIZE(payload.ack);
    }

    for ( ;; ) {
        remain = max_size - payload.len;
        if (remain < 128) {
            break;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_retransmission_queue_get_app(&frame, packer->retransmission_queue, remain))) {
            gquic_packed_packet_payload_dtor(&payload);
            GQUIC_PROCESS_DONE(exception);
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &frame_storage, sizeof(void *)))) {
            gquic_packed_packet_payload_dtor(&payload);
            GQUIC_PROCESS_DONE(exception);
        }
        *frame_storage = frame;
        gquic_list_insert_before(payload.frames, frame_storage);
        payload.len += GQUIC_FRAME_SIZE(frame);
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_framer_append_ctrl_frame(payload.frames, &added_size, packer->framer, max_size - payload.len))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }
    payload.len += added_size;
    added_size = 0;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_framer_append_stream_frames(payload.frames, &added_size, packer->framer, max_size - payload.len))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }
    payload.len += added_size;

    if (gquic_list_head_empty(payload.frames) && payload.ack == NULL) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    
    if (gquic_list_head_empty(payload.frames)) {
        if (packer->non_ack_eliciting_acks_count >= 19) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_frame_ping_alloc((gquic_frame_ping_t **) &frame))) {
                gquic_packed_packet_payload_dtor(&payload);
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
            }
            GQUIC_FRAME_INIT(frame);
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &frame_storage, sizeof(void *)))) {
                gquic_packed_packet_payload_dtor(&payload);
                GQUIC_PROCESS_DONE(exception);
            }
            *frame_storage = frame;
            gquic_list_insert_before(payload.frames, frame_storage);
            payload.len += GQUIC_FRAME_SIZE(frame);
            packer->non_ack_eliciting_acks_count = 0;
        }
        else {
            packer->non_ack_eliciting_acks_count++;
        }
        
    }
    else {
        packer->non_ack_eliciting_acks_count = 0;
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_pack(packed_packet, packer, &payload))) {
        gquic_packed_packet_payload_dtor(&payload);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_try_pack_crypto_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer) {
    int exception = GQUIC_SUCCESS;
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_try_pack_initial_packet(packed_packet, packer));
    if (exception == GQUIC_EXCEPTION_KEY_DROPPED) {
        packer->droped_initial = 1;
    }
    else if (exception != GQUIC_SUCCESS || packed_packet->valid == 1) {
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_try_pack_handshake_packet(packed_packet, packer));
    if (exception == GQUIC_EXCEPTION_KEY_DROPPED) {
        packer->droped_handshake = 1;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (exception == GQUIC_EXCEPTION_KEY_UNAVAILABLE) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_PROCESS_DONE(exception);
}

int gquic_packet_packer_pack_crypto_packet(gquic_packed_packet_t *const packed_packet,
                                           gquic_packet_packer_t *const packer,
                                           gquic_packed_packet_payload_t *const payload,
                                           const int has_retransmission) {
    gquic_crypto_stream_t *str = NULL;
    u_int64_t header_len = 0;
    u_int64_t remain = 0;
    void *frame = NULL;
    void **frame_storage = NULL;
    if (packed_packet == NULL || packer == NULL || payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (payload->enc_lv == GQUIC_ENC_LV_HANDSHAKE) {
        str = packer->handshake_stream;
    }
    else {
        str = packer->initial_stream;
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_get_long_header(&payload->hdr, packer, payload->enc_lv));
    header_len = gquic_packet_long_header_size(payload->hdr.hdr.l_hdr);
    
    if (has_retransmission) {
        for ( ;; ) {
            frame = NULL;
            switch (payload->enc_lv) {
            case GQUIC_ENC_LV_INITIAL:
                remain = 16 * (1 << 10) - header_len - 16 - payload->len;
                gquic_retransmission_queue_get_initial(&frame, packer->retransmission_queue, remain);
                break;
            case GQUIC_ENC_LV_HANDSHAKE:
                remain = packer->max_packet_size - header_len - 16 - payload->len;
                gquic_retransmission_queue_get_handshake(&frame, packer->retransmission_queue, remain);
                break;
            }
            if (frame == NULL) {
                break;
            }
            GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &frame_storage, sizeof(void *)));
            *frame_storage = frame;
            gquic_list_insert_before(payload->frames, frame_storage);
            payload->len += GQUIC_FRAME_SIZE(frame);
        }
    }
    else if (gquic_crypto_stream_has_data(str)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_pop_crypto_frame((gquic_frame_crypto_t **) &frame,
                                                                      str, packer->max_packet_size - header_len - 16 - payload->len));
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &frame_storage, sizeof(void *)));
        *frame_storage = frame;
        gquic_list_insert_before(payload->frames, frame_storage);
        payload->len += GQUIC_FRAME_SIZE(frame);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_pack(packed_packet, packer, payload));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_pack_packet(gquic_packed_packet_t *const packed_packet,
                                    gquic_packet_packer_t *const packer) {
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!gquic_packet_packer_handshake_confirmed(packer)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_try_pack_crypto_packet(packed_packet, packer));
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_try_pack_app_packet(packed_packet, packer));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_packer_try_pack_probe_packet(gquic_packed_packet_t *const packed_packet,
                                              gquic_packet_packer_t *const packer,
                                              const u_int8_t enc_lv) {
    if (packed_packet == NULL || packer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_try_pack_initial_packet(packed_packet, packer));
        break;

    case GQUIC_ENC_LV_HANDSHAKE:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_try_pack_handshake_packet(packed_packet, packer));
        break;

    case GQUIC_ENC_LV_1RTT:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_try_pack_app_packet(packed_packet, packer));
        break;

    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
