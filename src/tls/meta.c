#include "tls/meta.h"
#include "exception.h"
#include <malloc.h>

void *gquic_tls_msg_alloc(const size_t size) {
    gquic_tls_msg_meta_t *meta = malloc(sizeof(gquic_tls_msg_meta_t) + size);
    if (meta == NULL) {
        return NULL;
    }
    meta->init_func = NULL;
    meta->deserialize_func = NULL;
    meta->dtor_func = NULL;
    meta->serialize_func = NULL;
    meta->size_func = NULL;
    meta->type = 0x00;
    meta->payload_size = size;
    return ((void *) meta) + sizeof(gquic_tls_msg_meta_t);
}

int gquic_tls_msg_release(void *const msg) {
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_TLS_MSG_DTOR(msg);
    free(&GQUIC_TLS_MSG_META(msg));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
