/* src/handshake/extension_handler.c TLS附加部分处理模块实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "handshake/extension_handler.h"
#include "handshake/establish.h"
#include "tls/common.h"
#include "util/malloc.h"
#include "exception.h"

static gquic_exception_t get_extensions_wrap(gquic_list_t *const, void *const, const u_int8_t);
static gquic_exception_t received_extensions_wrap(void *const, const u_int8_t, gquic_list_t *const);

gquic_exception_t gquic_handshake_extension_handler_init(gquic_handshake_extension_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->is_client = false;
    gquic_str_init(&handler->params);
    handler->param_chain = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_extension_handler_dtor(gquic_handshake_extension_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&handler->params);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_extension_handler_ctor(gquic_handshake_extension_handler_t *const handler,
                                                         liteco_channel_t *const param_chain,
                                                         const gquic_transport_parameters_t *const params,
                                                         const bool is_client) {
    if (handler == NULL || param_chain == NULL || params == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->is_client = is_client;
    handler->param_chain = param_chain;
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&handler->params, gquic_transport_parameters_size(params)));
    gquic_writer_str_t writer = handler->params;
    GQUIC_ASSERT_FAST_RETURN(gquic_transport_parameters_serialize(params, &writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_extension_handler_get_extensions(gquic_list_t *const extensions,
                                                                   gquic_handshake_extension_handler_t *const handler,
                                                                   const u_int8_t msg_type) {
    gquic_tls_extension_t *ext = NULL;
    if (extensions == NULL || handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO)
        || (!handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS)) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &ext, sizeof(gquic_tls_extension_t)));
    ext->type = GQUIC_TLS_EXTENSION_QUIC;
    gquic_str_init(&ext->data);
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&ext->data, &handler->params));
    GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(extensions, ext));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_extension_handler_recv_extensions(gquic_handshake_extension_handler_t *const handler,
                                                                    const u_int8_t msg_type,
                                                                    const gquic_list_t *const extensions) {
    gquic_establish_process_event_t *process_event = NULL;
    gquic_tls_extension_t *ext = NULL;
    if (handler == NULL || extensions == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS)
        || (!handler->is_client && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO)) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&process_event, gquic_establish_process_event_t));
    process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_PARAM;
    gquic_str_init(&process_event->param);

    GQUIC_LIST_FOREACH(ext, extensions) {
        if (ext->type == GQUIC_TLS_EXTENSION_QUIC) {
            GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&process_event->param, &ext->data));
            break;
        }
    }
    liteco_channel_send(handler->param_chain, process_event);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_handshake_extension_handler_set_config_extension(gquic_tls_config_t *const cfg,
                                                                         gquic_handshake_extension_handler_t *const handler) {
    if (cfg == NULL || handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cfg->ext_self = handler;
    cfg->extensions = get_extensions_wrap;
    cfg->received_extensions = received_extensions_wrap;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t get_extensions_wrap(gquic_list_t *const extensions, void *const handler, const u_int8_t msg_type) {
    return gquic_handshake_extension_handler_get_extensions(extensions, handler, msg_type);
}

static gquic_exception_t received_extensions_wrap(void *const handler, const u_int8_t msg_type, gquic_list_t *const extensions) {
    return gquic_handshake_extension_handler_recv_extensions(handler, msg_type, extensions);
}
