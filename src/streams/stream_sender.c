/* src/stream/stream_sender.c 数据流处理接口
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "streams/stream_sender.h"
#include "exception.h"
#include <stddef.h>

static gquic_exception_t uni_stream_sender_on_stream_completed(void *const, const u_int64_t);

gquic_exception_t gquic_stream_sender_init(gquic_stream_sender_t *const sender) {
    if (sender == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sender->queue_ctrl_frame.cb = NULL;
    sender->queue_ctrl_frame.self = NULL;
    sender->on_has_stream_data.cb = NULL;
    sender->on_has_stream_data.self = NULL;
    sender->on_stream_completed.cb = NULL;
    sender->on_stream_completed.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_uni_stream_sender_init(gquic_uni_stream_sender_t *const sender) {
    if (sender == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_stream_sender_init(&sender->base);
    sender->on_stream_completed_cb.cb = NULL;
    sender->on_stream_completed_cb.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_uni_stream_sender_prototype(gquic_stream_sender_t *const prototype, gquic_uni_stream_sender_t *const sender) {
    if (prototype == NULL || sender == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    prototype->on_has_stream_data = sender->base.on_has_stream_data;
    prototype->queue_ctrl_frame = sender->base.queue_ctrl_frame;
    prototype->on_stream_completed.cb = uni_stream_sender_on_stream_completed;
    prototype->on_stream_completed.self = sender;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t uni_stream_sender_on_stream_completed(void *const sender, const u_int64_t _) {
    (void) _;
    gquic_uni_stream_sender_t *uni_sender = sender;
    if (sender == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (uni_sender->on_stream_completed_cb.self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    return uni_sender->on_stream_completed_cb.cb(uni_sender->on_stream_completed_cb.self);
}
