#include "frame/stream_pool.h"
#include "frame/meta.h"
#include <stddef.h>

static struct gquic_stream_frame_pool_s {

} pool;

int gquic_stream_frame_pool_init() {
    return 0;
}

int gquic_stream_frame_pool_get(gquic_frame_stream_t **const stream) {
    if ((*stream = gquic_frame_stream_alloc()) == NULL) {
        return -1;
    }
    GQUIC_FRAME_INIT(*stream);
    return 0;
}

int gquic_stream_frame_pool_put(gquic_frame_stream_t *const stream) {
    if (stream == NULL) {
        return -1;
    }
    gquic_frame_release(stream);
    return 0;
}
