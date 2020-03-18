#include "packet/send_queue.h"
#include "exception.h"

int gquic_packet_send_queue_init(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    queue->conn = NULL;
    gquic_sem_list_init(&queue->queue);

    return GQUIC_SUCCESS;
}

int gquic_packet_send_queue_ctor(gquic_packet_send_queue_t *const queue, gquic_net_conn_t *const conn) {
    if (queue == NULL || conn == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    queue->conn = conn;

    return GQUIC_SUCCESS;
}

int gquic_packet_send_queue_dtor(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_sem_list_sem_dtor(&queue->queue);

    return GQUIC_SUCCESS;
}

int gquic_packet_send_queue_send(gquic_packet_send_queue_t *const queue, gquic_packed_packet_t *const packed_packet) {
    gquic_packet_send_queue_event_t *event = NULL;
    if (queue == NULL || packed_packet == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((event = gquic_list_alloc(sizeof(gquic_packet_send_queue_event_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    event->event = GQUIC_PACKET_SEND_QUEUE_EVENT_PACKET;
    event->packed_packet = packed_packet;
    gquic_sem_list_push(&queue->queue, event);

    return GQUIC_SUCCESS;
}

int gquic_packet_send_queue_close(gquic_packet_send_queue_t *const queue) {
    gquic_packet_send_queue_event_t *event = NULL;
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((event = gquic_list_alloc(sizeof(gquic_packet_send_queue_event_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    event->event = GQUIC_PACKET_SEND_QUEUE_EVENT_CLOSE;
    event->packed_packet = NULL;
    gquic_sem_list_push(&queue->queue, event);

    return GQUIC_SUCCESS;
}

int gquic_packet_send_queue_run(gquic_packet_send_queue_t *const queue) {
    gquic_packet_send_queue_event_t *event = NULL;
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    for ( ;; ) {
        GQUIC_ASSERT_FAST_RETURN(gquic_sem_list_pop((void **) &event, &queue->queue));

        switch (event->event) {
        case GQUIC_PACKET_SEND_QUEUE_EVENT_CLOSE:
            gquic_list_release(event);
            return GQUIC_SUCCESS;
        case GQUIC_PACKET_SEND_QUEUE_EVENT_PACKET:
            GQUIC_ASSERT_FAST_RETURN(gquic_net_conn_write(queue->conn, &event->packed_packet->raw));
            gquic_packed_packet_dtor_without_frames(event->packed_packet);
            free(event->packed_packet);
            gquic_list_release(event);
            break;
        default:
            return GQUIC_EXCEPTION_SEND_QUEUE_INVALID_EVENT;
        }
    }
}
