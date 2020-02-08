#ifndef _LIBGQUIC_FRAME_META_H
#define _LIBGQUIC_FRAME_META_H

#include "util/str.h"
#include <sys/types.h>

typedef struct gquic_frame_meta_s gquic_frame_meta_t;
struct gquic_frame_meta_s {
    int (*init_func) (void *const);
    size_t (*size_func) (const void *const);
    int (*serialize_func) (const void *const, gquic_writer_str_t *const);
    int (*deserialize_func) (void *const, gquic_reader_str_t *const);
    int (*dtor_func) (void *const);
    u_int8_t type;

    struct {
        void *self;
        int (*on_acked) (void *const, void *const);
        int (*on_lost) (void *const, void *const);
    } event;

    size_t payload_size;
};

#define GQUIC_FRAME_META(ptr) (*((gquic_frame_meta_t *) (((void *) ptr) - sizeof(gquic_frame_meta_t))))
#define GQUIC_FRAME_SPEC(frame_type_t, ptr) (*((frame_type_t *) (((void *) ptr) + sizeof(gquic_frame_meta_t))))

#define GQUIC_FRAME_INIT(ptr) (GQUIC_FRAME_META((ptr)).init_func((ptr)))
#define GQUIC_FRAME_SIZE(ptr) (GQUIC_FRAME_META((ptr)).size_func((ptr)))
#define GQUIC_FRAME_SERIALIZE(ptr, writer) (GQUIC_FRAME_META((ptr)).serialize_func((ptr), (writer)))
#define GQUIC_FRAME_DESRIALIZE(ptr, reader) (GQUIC_FRAME_META((ptr)).deserialize_func((ptr), (reader)))
#define GQUIC_FRAME_DTOR(ptr) (GQUIC_FRAME_META((ptr)).dtor_func((ptr)))
#define GQUIC_FRAME_ON_ACKED(ptr) (GQUIC_FRAME_META((ptr)).event.on_acked((GQUIC_FRAME_META((ptr)).event.self), (ptr)))
#define GQUIC_FRAME_ON_LOST(ptr) (GQUIC_FRAME_META((ptr)).event.on_lost((GQUIC_FRAME_META((ptr)).event.self), (ptr)))

void *gquic_frame_alloc(size_t size);
int gquic_frame_release(void *const frame);

#endif

