#include "unit_test.h"
#include "streams/send_stream.h"
#include "frame/stream_pool.h"
#include "frame/stream_data_blocked.h"
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

struct __writing_s {
    gquic_send_stream_t *str;
    sem_t notify;
};

int __writing_once(void *const param_) {
    struct __writing_s *const param = param_;

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

    struct __writing_s param;
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

GQUIC_UNIT_TEST(write_get_data_two) {
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

    struct __writing_s param;
    param.str = &str;
    sem_init(&param.notify, 0, 0);
    gquic_timeout_start(0, __writing_once, &param);
    while (str.send_reader == NULL) { };

    gquic_frame_stream_t *frame = NULL;
    gquic_send_stream_pop_stream_frame(&frame, &str, 4 + 2);
    gquic_str_t data = { 0, NULL };
    gquic_str_set(&data, "te");
    GQUIC_UNIT_TEST_EXPECT(gquic_str_cmp(&data, &frame->data) == 0);
    GQUIC_UNIT_TEST_EXPECT(!gquic_frame_stream_get_fin(frame));
    GQUIC_UNIT_TEST_EXPECT(frame->off == 0);
    GQUIC_UNIT_TEST_EXPECT(str.write_off == 2);

    gquic_frame_stream_t *frame2 = NULL;
    gquic_send_stream_pop_stream_frame(&frame2, &str, 4 + 3);
    gquic_str_t data2 = { 0, NULL };
    gquic_str_set(&data2, "st");
    GQUIC_UNIT_TEST_EXPECT(gquic_str_cmp(&data2, &frame2->data) == 0);
    GQUIC_UNIT_TEST_EXPECT(!gquic_frame_stream_get_fin(frame2));
    GQUIC_UNIT_TEST_EXPECT(frame2->off == 2);
    GQUIC_UNIT_TEST_EXPECT(str.write_off == 4);
    
    gquic_frame_stream_t *frame3 = NULL;
    gquic_send_stream_pop_stream_frame(&frame3, &str, 1000);
    GQUIC_UNIT_TEST_EXPECT(frame3 == NULL);

    sem_wait(&param.notify);
    GQUIC_UNIT_TEST_EXPECT(str.send_reader == NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(no_data) {
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

    gquic_frame_stream_t *frame = NULL;
    GQUIC_UNIT_TEST_EXPECT(!gquic_send_stream_pop_stream_frame(&frame, &str, 999));
    GQUIC_UNIT_TEST_EXPECT(frame == NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int __flow_ctrl_block_queue_ctrl_frame(void *const _, void *const frame) {
    (void) _;

    GQUIC_UNIT_TEST_EXPECT(GQUIC_FRAME_META(frame).type == 0x15);
    GQUIC_UNIT_TEST_EXPECT(((gquic_frame_stream_data_blocked_t *) frame)->id == 1334);
    GQUIC_UNIT_TEST_EXPECT(((gquic_frame_stream_data_blocked_t *) frame)->limit == 12);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(flow_ctrl_block) {
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

    sender.queue_ctrl_frame.cb = __flow_ctrl_block_queue_ctrl_frame;
    sender.queue_ctrl_frame.self = __flow_ctrl_block_queue_ctrl_frame;

    stream_flow_ctrl.base.swnd = 12;
    stream_flow_ctrl.base.last_blocked_at = 0;
    stream_flow_ctrl.base.sent_bytes = 12;
    conn_flow_ctrl.base.swnd = 12;
    conn_flow_ctrl.base.last_blocked_at = 0;
    conn_flow_ctrl.base.sent_bytes = 12;

    struct __writing_s param;
    param.str = &str;
    sem_init(&param.notify, 0, 0);
    gquic_timeout_start(0, __writing_once, &param);
    while (str.send_reader == NULL) { };

    gquic_frame_stream_t *frame = NULL;
    GQUIC_UNIT_TEST_EXPECT(!gquic_send_stream_pop_stream_frame(&frame, &str, 1000));
    GQUIC_UNIT_TEST_EXPECT(frame == NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int __flow_ctrl_block_queue_ctrl_frame_2(void *const _, void *const frame) {
    (void) _;

    GQUIC_UNIT_TEST_EXPECT(GQUIC_FRAME_META(frame).type == 0x15);
    GQUIC_UNIT_TEST_EXPECT(((gquic_frame_stream_data_blocked_t *) frame)->id == 1334);
    GQUIC_UNIT_TEST_EXPECT(((gquic_frame_stream_data_blocked_t *) frame)->limit == 2);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(flow_ctrl_block_2) {
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

    sender.queue_ctrl_frame.cb = __flow_ctrl_block_queue_ctrl_frame_2;
    sender.queue_ctrl_frame.self = __flow_ctrl_block_queue_ctrl_frame_2;

    stream_flow_ctrl.base.swnd = 2;
    stream_flow_ctrl.base.last_blocked_at = 0;
    stream_flow_ctrl.base.sent_bytes = 0;
    conn_flow_ctrl.base.swnd = 2;
    conn_flow_ctrl.base.last_blocked_at = 0;
    conn_flow_ctrl.base.sent_bytes = 0;

    struct __writing_s param;
    param.str = &str;
    sem_init(&param.notify, 0, 0);
    gquic_timeout_start(0, __writing_once, &param);
    while (str.send_reader == NULL) { };

    gquic_frame_stream_t *frame = NULL;
    GQUIC_UNIT_TEST_EXPECT(gquic_send_stream_pop_stream_frame(&frame, &str, 4 + 2));
    GQUIC_UNIT_TEST_EXPECT(frame != NULL);

    frame = NULL;
    GQUIC_UNIT_TEST_EXPECT(!gquic_send_stream_pop_stream_frame(&frame, &str, 1000));
    GQUIC_UNIT_TEST_EXPECT(frame == NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
