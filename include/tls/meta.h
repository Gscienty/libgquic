#ifndef _LIBGQUIC_TLS_MSG_META_H
#define _LIBGQUIC_TLS_MSG_META_H

#include <sys/types.h>
#include <stddef.h>
#include "util/str.h"

typedef struct gquic_tls_msg_meta_s gquic_tls_msg_meta_t;
struct gquic_tls_msg_meta_s {
    int (*init_func) (void *const);
    int (*dtor_func) (void *const);
    ssize_t (*size_func) (const void *const);
    ssize_t (*serialize_func) (const void *const, void *const, const size_t);
    ssize_t (*deserialize_func) (void *const, const void *const, const size_t);
    u_int8_t type;

    size_t payload_size;
};

#define GQUIC_TLS_MSG_META(ptr) (*((gquic_tls_msg_meta_t *) (((void *) ptr) - sizeof(gquic_tls_msg_meta_t))))
#define GQUIC_TLS_MSG_SPEC(msg_type_t, ptr) (*((msg_type_t *) (((void *) ptr) + sizeof(gquic_tls_msg_meta_t))))

#define GQUIC_TLS_MSG_INIT(ptr) (GQUIC_TLS_MSG_META((ptr)).init_func((ptr)))
#define GQUIC_TLS_MSG_DTOR(ptr) (GQUIC_TLS_MSG_META((ptr)).dtor_func((ptr)))
#define GQUIC_TLS_MSG_SIZE(ptr) (GQUIC_TLS_MSG_META((ptr)).size_func((ptr)))
#define GQUIC_TLS_MSG_SERIALIZE(ptr, buf, size) (GQUIC_TLS_MSG_META((ptr)).serialize_func((ptr), (buf), (size)))
#define GQUIC_TLS_MSG_DESERIALIZE(ptr, buf, size) (GQUIC_TLS_MSG_META((ptr)).deserialize_func((ptr), (buf), (size)))

void *gquic_tls_msg_alloc(const size_t size);
int gquic_tls_msg_release(void *const msg);
static inline int gquic_tls_msg_combine_serialize(gquic_str_t *const buf, const void *const msg) {
    if (buf == NULL || msg == NULL) {
        return -1;
    }
    if (gquic_str_alloc(buf, GQUIC_TLS_MSG_SIZE(msg)) != 0) {
        return -2;
    }
    if (GQUIC_TLS_MSG_SERIALIZE(msg, GQUIC_STR_VAL(buf), GQUIC_STR_SIZE(buf)) < 0) {
        return -3;
    }
    return 0;
}

#endif
