#ifndef _LIBGQUIC_FRAME_META_H
#define _LIBGQUIC_FRAME_META_H

#include <unistd.h>

typedef void *gquic_abstract_frame_ptr_t;
typedef unsigned char gquic_frame_type_t;

typedef size_t (*gquic_frame_size_fptr_t) (gquic_abstract_frame_ptr_t);
typedef ssize_t (*gquic_frame_serialize_fptr_t) (const gquic_abstract_frame_ptr_t, void *, const size_t);
typedef ssize_t (*gquic_frame_deserialize_fptr_t) (gquic_abstract_frame_ptr_t, const void *, const size_t);
typedef int (*gquic_frame_init_fptr_t) (gquic_abstract_frame_ptr_t);
typedef int (*gquic_frame_release_fptr_t) (gquic_abstract_frame_ptr_t);

typedef struct gquic_frame_meta_s gquic_frame_meta_t;
struct gquic_frame_meta_s {
    gquic_frame_init_fptr_t init_func;
    gquic_frame_size_fptr_t size_func;
    gquic_frame_serialize_fptr_t serialize_func;
    gquic_frame_deserialize_fptr_t deserialize_func;
    gquic_frame_release_fptr_t release_func;
    gquic_frame_type_t type;

    size_t payload_size;
};

#define GQUIC_FRAME_META(ptr) (*((gquic_frame_meta_t *) (((void *) ptr) - sizeof(gquic_frame_meta_t))))
#define GQUIC_FRAME_SPEC(frame_type_t, ptr) (*((frame_type_t *) (((void *) ptr) + sizeof(gquic_frame_meta_t))))

gquic_abstract_frame_ptr_t gquic_frame_alloc(size_t size);
int gquic_frame_release(gquic_abstract_frame_ptr_t frame);

#endif

