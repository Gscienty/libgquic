#ifndef _LIBGQUIC_TLS_MSG_META_H
#define _LIBGQUIC_TLS_MSG_META_H

#include <sys/types.h>
#include <stddef.h>
#include "exception.h"
#include "util/str.h"

typedef struct gquic_tls_msg_meta_s gquic_tls_msg_meta_t;
struct gquic_tls_msg_meta_s {
    int (*init_func) (void *const);
    int (*dtor_func) (void *const);
    ssize_t (*size_func) (const void *const);
    int (*serialize_func) (const void *const, gquic_writer_str_t *const);
    int (*deserialize_func) (void *const, gquic_reader_str_t *const);
    u_int8_t type;

    size_t payload_size;
};

#define GQUIC_TLS_MSG_META(ptr) (*((gquic_tls_msg_meta_t *) (((void *) ptr) - sizeof(gquic_tls_msg_meta_t))))
#define GQUIC_TLS_MSG_SPEC(msg_type_t, ptr) (*((msg_type_t *) (((void *) ptr) + sizeof(gquic_tls_msg_meta_t))))

#define GQUIC_TLS_MSG_INIT(ptr) (GQUIC_TLS_MSG_META((ptr)).init_func((ptr)))
#define GQUIC_TLS_MSG_DTOR(ptr) (GQUIC_TLS_MSG_META((ptr)).dtor_func((ptr)))
#define GQUIC_TLS_MSG_SIZE(ptr) (GQUIC_TLS_MSG_META((ptr)).size_func((ptr)))
#define GQUIC_TLS_MSG_SERIALIZE(ptr, writer) (GQUIC_TLS_MSG_META((ptr)).serialize_func((ptr), (writer)))
#define GQUIC_TLS_MSG_DESERIALIZE(ptr, reader) (GQUIC_TLS_MSG_META((ptr)).deserialize_func((ptr), (reader)))

int gquic_tls_msg_alloc(void **const result, const size_t size);
int gquic_tls_msg_release(void *const msg);
static inline int gquic_tls_msg_combine_serialize(gquic_str_t *const buf, const void *const msg) {
    if (buf == NULL || msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(buf, GQUIC_TLS_MSG_SIZE(msg)));
    gquic_writer_str_t writer = *buf;
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_MSG_SERIALIZE(msg, &writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
