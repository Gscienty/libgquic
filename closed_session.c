#include "closed_session.h"
#include <malloc.h>

static int gquic_closed_remote_session_handle_packet(void *const, gquic_received_packet_t *const);
static int gquic_closed_remote_session_close(void *const);
static int gquic_closed_remote_session_destory(void *const, const int);
static int gquic_closed_remote_session_client_is_client(void *const);
static int gquic_closed_remote_session_server_is_client(void *const);

gquic_packet_handler_t *gquic_closed_remote_session_client_alloc() {
    gquic_packet_handler_t *ret = malloc(sizeof(gquic_packet_handler_t));
    if (ret == NULL) {
        return NULL;
    }
    ret->closer.closer.cb = gquic_closed_remote_session_close;
    ret->closer.closer.self = ret;
    ret->destroy.cb = gquic_closed_remote_session_destory;
    ret->destroy.self = ret;
    ret->handle_packet.cb = gquic_closed_remote_session_handle_packet;
    ret->handle_packet.self = ret;
    ret->is_client.cb = gquic_closed_remote_session_client_is_client;
    ret->is_client.self = ret;
    
    return ret;
}

gquic_packet_handler_t *gquic_closed_remote_session_server_alloc() {
    gquic_packet_handler_t *ret = malloc(sizeof(gquic_packet_handler_t));
    if (ret == NULL) {
        return NULL;
    }
    ret->closer.closer.cb = gquic_closed_remote_session_close;
    ret->closer.closer.self = ret;
    ret->destroy.cb = gquic_closed_remote_session_destory;
    ret->destroy.self = ret;
    ret->handle_packet.cb = gquic_closed_remote_session_handle_packet;
    ret->handle_packet.self = ret;
    ret->is_client.cb = gquic_closed_remote_session_server_is_client;
    ret->is_client.self = ret;

    return ret;
}

static int gquic_closed_remote_session_handle_packet(void *const _, gquic_received_packet_t *const rp) {
    (void) _;
    if (rp == NULL) {
        return -1;
    }
    gquic_packet_buffer_put(rp->buffer);
    free(rp);
    return 0;
}

static int gquic_closed_remote_session_close(void *const _) {
    (void) _;
    return 0;
}

static int gquic_closed_remote_session_destory(void *const _, const int __) {
    (void) _;
    (void) __;
    return 0;
}

static int gquic_closed_remote_session_client_is_client(void *const _) {
    (void) _;
    return 1;
}
static int gquic_closed_remote_session_server_is_client(void *const _) {
    (void) _;
    return 0;
}
