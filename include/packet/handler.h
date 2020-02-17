#ifndef _LIBGQUIC_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_HANDLER_H

#include "packet/packet.h"
#include "packet/received_packet.h"
#include "util/io.h"

typedef struct gquic_packet_handler_s gquic_packet_handler_t;
struct gquic_packet_handler_s {
    struct {
        void *self;
        int (*cb) (void *const, gquic_received_packet_t *const);
    } handle_packet;
    gquic_io_t closer;
    struct {
        void *self;
        int (*cb) (void *const, const int);
    } destory;
    struct {
        void *self;
        int (*cb) (void *const);
    } is_client;
};
int gquic_packet_handler_init(gquic_packet_handler_t *const handler);

#endif
