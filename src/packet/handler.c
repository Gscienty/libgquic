#include "packet/handler.h"
#include "exception.h"

int gquic_packet_handler_init(gquic_packet_handler_t *const handler) {
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    handler->handle_packet.cb = NULL;
    handler->handle_packet.self = NULL;
    handler->is_client.cb = NULL;
    handler->is_client.self = NULL;
    handler->destroy.cb = NULL;
    handler->destroy.self = NULL;
    gquic_io_init(&handler->closer);

    return GQUIC_SUCCESS;
}
