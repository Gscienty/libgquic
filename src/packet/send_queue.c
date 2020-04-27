#include "packet/send_queue.h"
#include "exception.h"
#include "global_schedule.h"

int gquic_packet_send_queue_init(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    queue->conn = NULL;
    gquic_coroutine_chain_init(&queue->queue_chain);

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

    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_send(&queue->queue_chain, gquic_get_global_schedule(), packed_packet));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_close(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_boradcast_close(&queue->queue_chain, gquic_get_global_schedule()));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_send_queue_run(gquic_coroutine_t *const co, gquic_packet_send_queue_t *const queue) {
    gquic_packed_packet_t *packed_packet = NULL;
    if (co == NULL || queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    for ( ;; ) {
        GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_recv((void **) &packed_packet, NULL, co, 1, &queue->queue_chain, NULL));
        GQUIC_ASSERT_FAST_RETURN(gquic_net_conn_write(queue->conn, &packed_packet->raw));
        gquic_packed_packet_dtor_without_frames(packed_packet);
        free(packed_packet);
    }
}
