#include "unit_test.h"
#include "streams/send_stream.h"
#include "frame/stream_pool.h"
#include "util/time.h"
#include "util/timeout.h"

GQUIC_UNIT_TEST(send_streams_deadline) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_send_stream_t str;
    gquic_send_stream_init(&str);
    gquic_send_stream_ctor(&str, 1334, &sender, &stream_flow_ctrl);

    gquic_send_stream_set_write_deadline(&str, gquic_time_now() - 1000);

    gquic_str_t data = { 0, NULL };
    gquic_str_set(&data, "ab");
    gquic_writer_str_t writer = data;

    GQUIC_UNIT_TEST_EXPECT(gquic_send_stream_write(&str, &writer) == GQUIC_EXCEPTION_DEADLINE);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

struct __writing_once_s {
    gquic_send_stream_t *str;
    sem_t notify;
};

int __writing_once(void *const param_) {
    struct __writing_once_s *const param = param_;

    gquic_str_t data = { 0, NULL };
    gquic_str_set(&data, "test");
    gquic_reader_str_t reader = data;

    gquic_send_stream_write(param->str, &reader);
    sem_post(&param->notify);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writing_once) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_conn_flow_ctrl_t conn_flow_ctrl;
    gquic_flowcontrol_conn_flow_ctrl_init(&conn_flow_ctrl);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    stream_flow_ctrl.conn_flow_ctrl = &conn_flow_ctrl;
    gquic_send_stream_t str;
    gquic_send_stream_init(&str);
    gquic_send_stream_ctor(&str, 1334, &sender, &stream_flow_ctrl);

    conn_flow_ctrl.base.swnd = 9999;
    conn_flow_ctrl.base.sent_bytes = 0;
    stream_flow_ctrl.base.swnd = 9999;
    stream_flow_ctrl.base.sent_bytes = 0;

    struct __writing_once_s param;
    param.str = &str;
    sem_init(&param.notify, 0, 0);
    gquic_timeout_start(0, __writing_once, &param);
    while (str.send_reader == NULL) { };

    gquic_frame_stream_t *frame = NULL;
    gquic_send_stream_pop_stream_frame(&frame, &str, 1000);
    gquic_str_t data = { 0, NULL };
    gquic_str_set(&data, "test");
    GQUIC_UNIT_TEST_EXPECT(gquic_str_cmp(&data, &frame->data) == 0);
    GQUIC_UNIT_TEST_EXPECT(!gquic_frame_stream_get_fin(frame));
    GQUIC_UNIT_TEST_EXPECT(frame->off == 0);
    GQUIC_UNIT_TEST_EXPECT(str.write_off == 4);
    sem_wait(&param.notify);
    GQUIC_UNIT_TEST_EXPECT(str.send_reader == NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
