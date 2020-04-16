#include "unit_test.h"
#include "streams/recv_stream.h"
#include "frame/stream.h"
#include "frame/stop_sending.h"
#include "util/timeout.h"
#include <string.h>

GQUIC_UNIT_TEST(recv_streams_reading) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 4);
    
    gquic_frame_stream_t *frame = gquic_frame_stream_alloc();
    frame->off = 0;
    gquic_str_set(&frame->data, "abcd");

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame) == GQUIC_SUCCESS);
    
    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("abcd", buf, 4) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);

}

GQUIC_UNIT_TEST(recv_stream_read_multi_times) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);

    gquic_frame_stream_t *frame = gquic_frame_stream_alloc();
    frame->off = 0;
    gquic_str_set(&frame->data, "abcd");

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame) == GQUIC_SUCCESS);

    u_int8_t buf1[2] = { 0 };
    gquic_writer_str_t writer1 = { 2, buf1 };
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer1) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("ab", buf1, 2) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer1) - (void *) buf1 == 2);


    u_int8_t buf2[2] = { 0 };
    gquic_writer_str_t writer2 = { 2, buf2 };
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer2) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("cd", buf2, 2) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer2) - (void *) buf2 == 2);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reads_all_data_available) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 2, 0);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 0;
    gquic_str_set(&frame1->data, "ab");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame1) == GQUIC_SUCCESS);
    gquic_frame_stream_t *frame2 = gquic_frame_stream_alloc();
    frame2->off = 2;
    gquic_str_set(&frame2->data, "cd");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame2) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("abcd", buf, 4) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int __waiting_data_thread(void *const str_) {
    gquic_recv_stream_t *recv_str = str_;

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 0;
    gquic_str_set(&frame1->data, "ab");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(recv_str, frame1) == GQUIC_SUCCESS);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(waiting_data) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 2, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    gquic_timeout_start(1000 * 1000, __waiting_data_thread, &recv_str);

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("ab", buf, 2) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 2);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(wrong_data) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 2, 0);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 2;
    gquic_str_set(&frame1->data, "ab");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame1) == GQUIC_SUCCESS);
    gquic_frame_stream_t *frame2 = gquic_frame_stream_alloc();
    frame2->off = 0;
    gquic_str_set(&frame2->data, "cd");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame2) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("cdab", buf, 4) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(ignore_duplicate) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 2, 0);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 0;
    gquic_str_set(&frame1->data, "ab");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame1) == GQUIC_SUCCESS);

    gquic_frame_stream_t *frame_dup = gquic_frame_stream_alloc();
    frame_dup->off = 0;
    gquic_str_set(&frame_dup->data, "er");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame_dup) == GQUIC_SUCCESS);

    gquic_frame_stream_t *frame2 = gquic_frame_stream_alloc();
    frame2->off = 2;
    gquic_str_set(&frame2->data, "cd");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame2) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("abcd", buf, 4) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(rejects_overlapping_data_range) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 6, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 4);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 0;
    gquic_str_set(&frame1->data, "abcd");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame1) == GQUIC_SUCCESS);

    gquic_frame_stream_t *frame2 = gquic_frame_stream_alloc();
    frame2->off = 2;
    gquic_str_set(&frame2->data, "cdef");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame2) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(memcmp("abcdef", buf, 6) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 6);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(deadline) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 4);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 0;
    gquic_str_set(&frame1->data, "abcd");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame1) == GQUIC_SUCCESS);

    gquic_recv_stream_set_read_deadline(&recv_str, gquic_time_now() - 1000 * 1000);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_DEADLINE);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

struct __deadline_changed_s {
    gquic_recv_stream_t *recv_str;
    sem_t done;
};

static int __deadline_changed(void *const param_) {
    struct __deadline_changed_s *const param = param_;

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(param->recv_str, &writer) == GQUIC_EXCEPTION_DEADLINE);

    sem_post(&param->done);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(deadline_changed) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 4);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    gquic_recv_stream_set_read_deadline(&recv_str, gquic_time_now() + 1000 * 1000 * 1000);

    struct __deadline_changed_s param;
    sem_init(&param.done, 0, 0);
    param.recv_str = &recv_str;

    gquic_timeout_start(0, __deadline_changed, &param);

    gquic_recv_stream_set_read_deadline(&recv_str, gquic_time_now() - 1);

    sem_wait(&param.done);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(deadline_after) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 0);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 4);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    gquic_recv_stream_set_read_deadline(&recv_str, gquic_time_now() + 1000 * 1000);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_DEADLINE);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(close_with_fin) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);

    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 1);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 4);
    
    gquic_frame_stream_t *frame = gquic_frame_stream_alloc();
    frame->off = 0;
    gquic_frame_stream_set_fin(frame);
    gquic_str_set(&frame->data, "abcd");

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame) == GQUIC_SUCCESS);
    
    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);
    GQUIC_UNIT_TEST_EXPECT(memcmp("abcd", buf, 4) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(fin_bit_gquic_handle_out_of_order) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 2, 0);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 4, 1);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    gquic_frame_stream_t *frame1 = gquic_frame_stream_alloc();
    frame1->off = 2;
    gquic_str_set(&frame1->data, "ab");
    gquic_frame_stream_set_fin(frame1);
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame1) == GQUIC_SUCCESS);

    gquic_frame_stream_t *frame2 = gquic_frame_stream_alloc();
    frame2->off = 0;
    gquic_str_set(&frame2->data, "cd");
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame2) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);
    GQUIC_UNIT_TEST_EXPECT(memcmp("cdab", buf, 4) == 0);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(handle_immediate_fin) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 0, 1);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 0);

    gquic_frame_stream_t *frame = gquic_frame_stream_alloc();
    frame->off = 0;
    gquic_frame_stream_set_fin(frame);
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 0);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(remote_close) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 0, 1);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 0);

    gquic_recv_stream_close_remote(&recv_str, 0);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };

    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 0);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(close_shutdown_immediately) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    const int GQUIC_EXCEPTION_TEST = -2000000;
    gquic_recv_stream_close_for_shutdown(&recv_str, GQUIC_EXCEPTION_TEST);
    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_TEST);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(cancel_read) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    const int GQUIC_EXCEPTION_TEST = -2000000;
    gquic_recv_stream_read_cancel(&recv_str, GQUIC_EXCEPTION_TEST);
    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_TEST);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(cancel_read_2) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    const int GQUIC_EXCEPTION_TEST = -2000000;
    gquic_recv_stream_read_cancel(&recv_str, GQUIC_EXCEPTION_TEST);
    gquic_recv_stream_read_cancel(&recv_str, GQUIC_EXCEPTION_TEST);
    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_TEST);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int queue_stop_sending_queue_ctrl_frame_cb(void *const self, void *const frame) {
    (void) self;

    GQUIC_UNIT_TEST_EXPECT(GQUIC_FRAME_META(frame).type == 0x05);
    GQUIC_UNIT_TEST_EXPECT(((gquic_frame_stop_sending_t *) frame)->id == 1337);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(cancel_queue_stop_sending) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    sender.queue_ctrl_frame.cb = queue_stop_sending_queue_ctrl_frame_cb;
    sender.queue_ctrl_frame.self = queue_stop_sending_queue_ctrl_frame_cb;

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    const int GQUIC_EXCEPTION_TEST = -2000000;
    gquic_recv_stream_read_cancel(&recv_str, GQUIC_EXCEPTION_TEST);
    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_TEST);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int queue_on_stream_completed_cb(void *const self, const u_int64_t sid) {
    (void) self;
    GQUIC_UNIT_TEST_EXPECT(sid == 1337);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(cancel_fin) {
    gquic_stream_sender_t sender;
    gquic_stream_sender_init(&sender);
    gquic_flowcontrol_stream_flow_ctrl_t stream_flow_ctrl;
    gquic_flowcontrol_stream_flow_ctrl_init(&stream_flow_ctrl);
    gquic_recv_stream_t recv_str;
    gquic_recv_stream_init(&recv_str);

    sender.on_stream_completed.cb = queue_on_stream_completed_cb;
    sender.on_stream_completed.self = queue_on_stream_completed_cb;

    gquic_recv_stream_ctor(&recv_str, 1337, &sender, &stream_flow_ctrl);
    const int GQUIC_EXCEPTION_TEST = -2000000;
    gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(&stream_flow_ctrl, 2, 1);
    gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(&stream_flow_ctrl, 2);

    gquic_frame_stream_t *frame = gquic_frame_stream_alloc();
    frame->off = 0;
    gquic_str_set(&frame->data, "ab");
    gquic_frame_stream_set_fin(frame);
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_handle_stream_frame(&recv_str, frame) == GQUIC_SUCCESS);

    u_int8_t buf[10] = { 0 };
    gquic_str_t writer = { 10, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_recv_stream_read(&recv_str, &writer) == GQUIC_EXCEPTION_EOF);
    gquic_recv_stream_read_cancel(&recv_str, GQUIC_EXCEPTION_TEST);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
