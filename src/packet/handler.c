#include "packet/handler.h"
#include "exception.h"

gquic_exception_t gquic_packet_handler_init(gquic_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->handle_packet.cb = NULL;
    handler->handle_packet.self = NULL;
    handler->is_client = false;
    handler->destroy.cb = NULL;
    handler->destroy.self = NULL;
    gquic_io_init(&handler->closer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
