#include "unit_test.h"
#include "util/prr.h"

GQUIC_UNIT_TEST(prr_sender_1) {
    gquic_prr_t prr;
    gquic_prr_init(&prr);

    u_int64_t packet_in_flight = 50;
    u_int64_t byte_in_flight = 50 * 1460;
    u_int64_t sshthresh = packet_in_flight / 2;
    u_int64_t cwnd = sshthresh * 1460;

    gquic_prr_packet_lost(&prr, byte_in_flight);
    gquic_prr_packet_acked(&prr, 1460);
    byte_in_flight -= 1460;
    GQUIC_UNIT_TEST_EXPECT(gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
    gquic_prr_packet_sent(&prr, 1460);
    GQUIC_UNIT_TEST_EXPECT(!gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));

    u_int64_t i;
    for (i = 0; i < sshthresh - 1; i++) {
        gquic_prr_packet_acked(&prr, 1460);
        byte_in_flight -= 1460;
        GQUIC_UNIT_TEST_EXPECT(!gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
        gquic_prr_packet_acked(&prr, 1460);
        byte_in_flight -= 1460;
        GQUIC_UNIT_TEST_EXPECT(gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
        gquic_prr_packet_sent(&prr, 1460);
        byte_in_flight += 1460;
    }

    GQUIC_UNIT_TEST_EXPECT(byte_in_flight == cwnd);
    for (i = 0; i < 10; i++) {
        gquic_prr_packet_acked(&prr, 1460);
        byte_in_flight -= 1460;
        GQUIC_UNIT_TEST_EXPECT(gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
        gquic_prr_packet_sent(&prr, 1460);
        byte_in_flight += 1460;

        GQUIC_UNIT_TEST_EXPECT(byte_in_flight == cwnd);
        GQUIC_UNIT_TEST_EXPECT(!gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
    }

    return 0;
}

GQUIC_UNIT_TEST(prr_sender_2) {
    gquic_prr_t prr;
    gquic_prr_init(&prr);

    u_int64_t byte_in_flight = 20 * 1460;
    int lost_packets = 13;
    int sshthresh = 10;
    u_int64_t cwnd = sshthresh * 1460;

    byte_in_flight -= lost_packets * 1460;
    gquic_prr_packet_lost(&prr, byte_in_flight);

    int i = 0;
    for (i = 0; i < 3; i++) {
        gquic_prr_packet_acked(&prr, 1460);
        byte_in_flight -= 1460;
        int j = 0;
        for (j = 0; j < 2; j++) {
            GQUIC_UNIT_TEST_EXPECT(gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
            gquic_prr_packet_sent(&prr, 1460);
            byte_in_flight += 1460;
        }
        GQUIC_UNIT_TEST_EXPECT(!gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
    }

    for (i = 0; i < 10; i++) {
        gquic_prr_packet_acked(&prr, 1460);
        byte_in_flight -= 1460;
        GQUIC_UNIT_TEST_EXPECT(gquic_prr_allowable_send(&prr, cwnd, byte_in_flight, sshthresh * 1460));
        gquic_prr_packet_sent(&prr, 1460);
        byte_in_flight += 1460;
    }

    return 0;
}
