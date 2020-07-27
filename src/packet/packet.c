/* src/packet/packet.c 存储发送的数据包实体
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/packet.h"
#include "packet/packet_number.h"
#include "frame/meta.h"
#include "exception.h"
#include "util/count_pointer.h"

gquic_exception_t gquic_packet_init(gquic_packet_t *const packet) {
    if (packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    packet->pn = GQUIC_INVALID_PACKET_NUMBER;
    packet->largest_ack = GQUIC_INVALID_PACKET_NUMBER;
    packet->len = 0;
    packet->enc_lv = 0;
    packet->send_time = 0;
    packet->included_infly = false;
    packet->frames = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_dtor(gquic_packet_t *const packet) {
    gquic_exception_t exception = GQUIC_SUCCESS;
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

gquic_exception_t gquic_cptr_packet_dtor(void *const packet) {
    GQUIC_PROCESS_DONE(gquic_packet_dtor(packet));
}
