#ifndef _LIBGQUIC_PACKET_PACKER_H
#define _LIBGQUIC_PACKET_PACKER_H

#include "packet/header.h"
#include "packet/packet_pool.h"
#include "frame/ack.h"
#include "util/list.h"

typedef struct gquic_packed_packet_s gquic_packed_packet_t;
struct gquic_packed_packet_s {
    gquic_packet_header_t hdr;
    gquic_str_t raw;
    gquic_frame_ack_t *ack;
    gquic_list_t frames;
    gquic_packet_buffer_t *buffer;
};

int gquic_packed_packet_init(gquic_packed_packet_t *packed_packet);
u_int8_t gquic_packed_packet_enc_lv(const gquic_packed_packet_t *const packed_packet);
int gquic_packed_packet_is_ack_eliciting(gquic_packed_packet_t *const packed_packet);

#endif
