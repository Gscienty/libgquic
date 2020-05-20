#include "packet/packet.h"
#include "frame/meta.h"
#include "exception.h"
#include "util/count_pointer.h"

int gquic_packet_init(gquic_packet_t *const packet) {
    if (packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    packet->pn = 0;
    packet->largest_ack = 0;
    packet->len = 0;
    packet->enc_lv = 0;
    packet->send_time = 0;
    packet->included_infly = 0;
    packet->frames_cptr = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_dtor(gquic_packet_t *const packet) {
    if (packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (packet->frames_cptr != NULL) {
        gquic_count_pointer_try_release(packet->frames_cptr);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
