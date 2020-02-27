#include "packet/send_queue.h"

int gquic_packet_send_queue_init(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        return -1;
    }
    queue->conn = NULL;
    gquic_sem_list_init(&queue->queue);

    return 0;
}

int gquic_packet_send_queue_ctor(gquic_packet_send_queue_t *const queue, gquic_net_conn_t *const conn) {
    if (queue == NULL || conn == NULL) {
        return -1;
    }
    queue->conn = conn;

    return 0;
}

int gquic_packet_send_queue_dtor(gquic_packet_send_queue_t *const queue) {
    if (queue == NULL) {
        return -1;
    }
    gquic_sem_list_sem_dtor(&queue->queue);
    return 0;
}

int gquic_packet_send_queue_send(gquic_packet_send_queue_t *const queue, gquic_packed_packet_t *const packed_packet) {
    gquic_packet_send_queue_event_t *event = NULL;
    if (queue == NULL || packed_packet == NULL) {
        return -1;
    }
    if ((event = gquic_list_alloc(sizeof(gquic_packet_send_queue_event_t))) == NULL) {
        return -2;
    }
    event->event = GQUIC_PACKET_SEND_QUEUE_EVENT_PACKET;
    event->packed_packet = packed_packet;
    gquic_sem_list_push(&queue->queue, event);
    return 0;
}

int gquic_packet_send_queue_close(gquic_packet_send_queue_t *const queue) {
    gquic_packet_send_queue_event_t *event = NULL;
    if (queue == NULL) {
        return -1;
    }
    if ((event = gquic_list_alloc(sizeof(gquic_packet_send_queue_event_t))) == NULL) {
        return -2;
    }
    event->event = GQUIC_PACKET_SEND_QUEUE_EVENT_CLOSE;
    event->packed_packet = NULL;
    gquic_sem_list_push(&queue->queue, event);
    return 0;
}

int gquic_packet_send_queue_run(gquic_packet_send_queue_t *const queue) {
    gquic_packet_send_queue_event_t *event = NULL;
    if (queue == NULL) {
        return -1;
    }
    for ( ;; ) {
        if (gquic_sem_list_pop((void **) &event, &queue->queue) != 0) {
            return -2;
        }
        switch (event->event) {
        case GQUIC_PACKET_SEND_QUEUE_EVENT_CLOSE:
            gquic_list_release(event);
            return 0;
        case GQUIC_PACKET_SEND_QUEUE_EVENT_PACKET:
            if (gquic_net_conn_write(queue->conn, &event->packed_packet->raw) != 0) {
                return -3;
            }
            gquic_packed_packet_dtor_without_frames(event->packed_packet);
            free(event->packed_packet);
            gquic_list_release(event);
            break;
        default:
            return -4;
        }
    }
}
