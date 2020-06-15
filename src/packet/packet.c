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
    packet->frames = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_dtor(gquic_packet_t *const packet) {
    int exception = GQUIC_SUCCESS;
    if (packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (packet->frames != NULL) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet->frames, gquic_cptr_frames_t, frames, cptr);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_cptr_frames_dtor(void *const frames_) {
    gquic_list_t *frames = frames_;
    if (frames == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (!gquic_list_head_empty(frames)) {
        gquic_frame_release(*(void **) GQUIC_LIST_FIRST(frames));
        gquic_list_release(GQUIC_LIST_FIRST(frames));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
