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
    gquic_list_head_init(&packet->frames);

    return 0;
}

int gquic_packet_release(gquic_packet_t *const packet) {
    if (packet == NULL) {
        return -1;
    }
    while (!gquic_list_head_empty(&packet->frames)) {
        GQUIC_FRAME_RELEASE(GQUIC_LIST_FIRST(&packet->frames));
        gquic_list_release(GQUIC_LIST_FIRST(&packet->frames));
    }

    return 0;
}
