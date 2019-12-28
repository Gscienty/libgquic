#ifndef _LIBGQUIC_FRAME_META_H
#define _LIBGQUIC_FRAME_META_H

#include <sys/types.h>

typedef struct gquic_frame_meta_s gquic_frame_meta_t;
struct gquic_frame_meta_s {
    int (*init_func) (void *const);
    size_t (*size_func) (const void *const);
    ssize_t (*serialize_func) (const void *const, void *const, const size_t);
    ssize_t (*deserialize_func) (void *const, const void *const, const size_t);
    int (*dtor_func) (void *const);
    u_int8_t type;

    size_t payload_size;
};

#define GQUIC_FRAME_META(ptr) (*((gquic_frame_meta_t *) (((void *) ptr) - sizeof(gquic_frame_meta_t))))
#define GQUIC_FRAME_SPEC(frame_type_t, ptr) (*((frame_type_t *) (((void *) ptr) + sizeof(gquic_frame_meta_t))))

#define GQUIC_FRAME_INIT(ptr) (GQUIC_FRAME_META((ptr)).init_func((ptr)))
#define GQUIC_FRAME_SIZE(ptr) (GQUIC_FRAME_META((ptr)).size_func((ptr)))
#define GQUIC_FRAME_SERIALIZE(ptr, buf, size) (GQUIC_FRAME_META((ptr)).serialize_func((ptr), (buf), (size)))
#define GQUIC_FRAME_DESRIALIZE(ptr, buf, size) (GQUIC_FRAME_META((ptr)).deserialize_func((ptr), (buf), (size)))
#define GQUIC_FRAME_DTOR(ptr) (GQUIC_FRAME_META((ptr)).dtor_func((ptr)))

void *gquic_frame_alloc(size_t size);
int gquic_frame_release(void *const frame);

#endif

