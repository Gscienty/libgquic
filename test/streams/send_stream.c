#include "unit_test.h"
#include "streams/send_stream.h"
#include "util/time.h"

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
