#include "packet/handler.h"

int gquic_packet_handler_init(gquic_packet_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    handler->handle_packet.cb = NULL;
    handler->handle_packet.self = NULL;
    handler->is_client.cb = NULL;
    handler->is_client.self = NULL;
    handler->destory.cb = NULL;
    handler->destory.self = NULL;
    gquic_io_init(&handler->closer);

    return 0;
}
