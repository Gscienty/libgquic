#include "packet/send_queue.h"
#include "util/malloc.h"
#include "exception.h"
#include "coglobal.h"

int gquic_packet_send_queue_init(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    queue->conn = NULL;
    liteco_channel_init(&queue->queue_chain);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_ctor(gquic_packet_send_queue_t *const queue, gquic_net_conn_t *const conn) {
    if (queue == NULL || conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    queue->conn = conn;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_dtor(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_send(gquic_packet_send_queue_t *const queue, gquic_packed_packet_t *const packed_packet) {
    if (queue == NULL || packed_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    liteco_channel_send(&queue->queue_chain, packed_packet);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_close(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_close(&queue->queue_chain);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_run(gquic_packet_send_queue_t *const queue) {
    int exception = GQUIC_SUCCESS;
    gquic_packed_packet_t *packed_packet = NULL;
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    for ( ;; ) {
        packed_packet = NULL;
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, (const void **) &packed_packet, NULL, 0, &queue->queue_chain);
        if (exception == GQUIC_EXCEPTION_CLOSED) {
            break;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_net_conn_write(queue->conn, &packed_packet->raw));
        gquic_packed_packet_dtor_without_frames(packed_packet);
        gquic_free(packed_packet);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
