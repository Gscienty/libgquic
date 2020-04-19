#include "tls/meta.h"
#include "exception.h"
#include <malloc.h>

int gquic_tls_msg_alloc(void **const result, const size_t size) {
    if (result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_msg_meta_t *meta = malloc(sizeof(gquic_tls_msg_meta_t) + size);
    if (meta == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    meta->init_func = NULL;
    meta->deserialize_func = NULL;
    meta->dtor_func = NULL;
    meta->serialize_func = NULL;
    meta->size_func = NULL;
    meta->type = 0x00;
    meta->payload_size = size;
    *result = ((void *) meta) + sizeof(gquic_tls_msg_meta_t);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_msg_release(void *const msg) {
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_TLS_MSG_DTOR(msg);
    free(&GQUIC_TLS_MSG_META(msg));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
