#include "handshake/extension_handler.h"
#include "handshake/establish.h"
#include "tls/common.h"

static int get_extensions_wrap(gquic_list_t *const, void *const, const u_int8_t);
static int received_extensions_wrap(void *const, const u_int8_t, gquic_list_t *const);

int gquic_handshake_extension_handler_init(gquic_handshake_extension_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    handler->is_client = 0;
    gquic_str_init(&handler->params);
    handler->process_event_sem = NULL;
    return 0;
}

int gquic_handshake_extension_handler_release(gquic_handshake_extension_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    gquic_str_reset(&handler->params);

    return 0;
}

int gquic_handshake_extension_handler_assign(gquic_handshake_extension_handler_t *const handler,
                                             gquic_sem_list_t *const process_event_sem,
                                             const gquic_transport_parameters_t *const params,
                                             const int is_client) {
    if (handler == NULL || process_event_sem == NULL || params == NULL) {
        return -1;
    }
    handler->is_client = is_client;
    handler->process_event_sem = process_event_sem;
    if (gquic_str_alloc(&handler->params, gquic_transport_parameters_size(params)) != 0) {
        return -2;
    }
    if (gquic_transport_parameters_serialize(params, GQUIC_STR_VAL(&handler->params), GQUIC_STR_SIZE(&handler->params)) < 0) {
        return -3;
    }
    return 0;
}

int gquic_handshake_extension_handler_get_extensions(gquic_list_t *const extensions,
                                                     gquic_handshake_extension_handler_t *const handler,
                                                     const u_int8_t msg_type) {
    gquic_tls_extension_t *ext = NULL;
    if (extensions == NULL || handler == NULL) {
        return -1;
    }
    if ((handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO)
        || (!handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS)) {
        return 0;
    }
    if ((ext = gquic_list_alloc(sizeof(gquic_tls_extension_t))) == NULL) {
        return -2;
    }
    ext->type = GQUIC_TLS_EXTENSION_QUIC;
    gquic_str_init(&ext->data);
    if (gquic_str_copy(&ext->data, &handler->params) != 0) {
        return -3;
    }
    if (gquic_list_insert_before(extensions, ext) != 0) {
        return -4;
    }
    return 0;
}

int gquic_handshake_extension_handler_recv_extensions(gquic_handshake_extension_handler_t *const handler,
                                                      const u_int8_t msg_type,
                                                      const gquic_list_t *const extensions) {
    gquic_establish_process_event_t *process_event = NULL;
    gquic_tls_extension_t *ext = NULL;
    if (handler == NULL || extensions == NULL) {
        return -1;
    }
    if ((handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS)
        || (!handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO)) {
        return 0;
    }
    
    GQUIC_LIST_FOREACH(ext, extensions) {
        if (ext->type == GQUIC_TLS_EXTENSION_QUIC) {
            if ((process_event = gquic_list_alloc(sizeof(gquic_establish_process_event_t))) == NULL) {
                return -2;
            }
            process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_PARAM;
            gquic_str_init(&process_event->param);
            if (gquic_str_copy(&process_event->param, &ext->data) != 0) {
                return -3;
            }
            break;
        }
    }
    if (process_event == NULL) {
        if ((process_event = gquic_list_alloc(sizeof(gquic_establish_process_event_t))) == NULL) {
            return -4;
        }
        process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_PARAM;
        gquic_str_init(&process_event->param);
    }
    gquic_sem_list_push(handler->process_event_sem, process_event);
    return 0;
}

int gquic_handshake_extension_handler_set_config_extension(gquic_tls_config_t *const cfg,
                                                           gquic_handshake_extension_handler_t *const handler) {
    if (cfg == NULL || handler == NULL) {
        return -1;
    }
    cfg->ext_self = handler;
    cfg->extensions = get_extensions_wrap;
    cfg->received_extensions = received_extensions_wrap;

    return 0;
}

static int get_extensions_wrap(gquic_list_t *const extensions, void *const handler, const u_int8_t msg_type) {
    return gquic_handshake_extension_handler_get_extensions(extensions, handler, msg_type);
}

static int received_extensions_wrap(void *const handler, const u_int8_t msg_type, gquic_list_t *const extensions) {
    return gquic_handshake_extension_handler_recv_extensions(handler, msg_type, extensions);
}
