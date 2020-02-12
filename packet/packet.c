#include "packet/packet.h"
#include "frame/meta.h"

int gquic_packet_init(gquic_packet_t *const packet) {
    if (packet == NULL) {
        return -1;
    }
    packet->pn = 0;
    packet->largest_ack = 0;
    packet->len = 0;
    packet->enc_lv = 0;
    packet->send_time = 0;
    packet->included_infly = 0;
    packet->frames = NULL;

    return 0;
}

int gquic_packet_dtor(gquic_packet_t *const packet) {
    if (packet == NULL) {
        return -1;
    }

    return 0;
}
