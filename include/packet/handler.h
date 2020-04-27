#ifndef _LIBGQUIC_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_HANDLER_H

#include "packet/packet.h"
#include "packet/received_packet.h"
#include "util/io.h"
#include "coroutine/coroutine.h"

typedef struct gquic_packet_handler_s gquic_packet_handler_t;
struct gquic_packet_handler_s {
    struct {
        void *self;
        int (*cb) (void *const, gquic_received_packet_t *const);
    } handle_packet;
    gquic_io_t closer;
    struct {
        void *self;
        int (*cb) (gquic_coroutine_t *const, void *const, const int);
    } destroy;
    struct {
        void *self;
        int (*cb) (void *const);
    } is_client;
};

#define GQUIC_PACKET_HANDLER_HANDLE_PACKET(handler, packet) \
    (((gquic_packet_handler_t *) (handler))->handle_packet.cb(((gquic_packet_handler_t *) (handler))->handle_packet.self, (packet)))
#define GQUIC_PACKET_HANDLER_DESTROY(co, handler, err) \
    (((gquic_packet_handler_t *) (handler))->destroy.cb((co), ((gquic_packet_handler_t *) (handler))->destroy.self, err))
#define GQUIC_PACKET_HANDLER_IS_CLIENT(handler) \
    (((gquic_packet_handler_t *) (handler))->is_client.cb(((gquic_packet_handler_t *) (handler))->is_client.self))

int gquic_packet_handler_init(gquic_packet_handler_t *const handler);

#endif
