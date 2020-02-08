#include "packet/packer.h"
#include "tls/common.h"

int gquic_packed_packet_init(gquic_packed_packet_t *packed_packet) {
    if (packed_packet == NULL) {
        return -1;
    }
    gquic_packet_header_init(&packed_packet->hdr);
    gquic_str_init(&packed_packet->raw);
    packed_packet->ack = NULL;
    gquic_list_head_init(&packed_packet->frames);
    packed_packet->buffer = NULL;

    return 0;
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
    return gquic_frames_has_frame_ack(&packed_packet->frames);
}
