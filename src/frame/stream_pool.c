#include "frame/stream_pool.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static struct gquic_stream_frame_pool_s {

} pool;

int gquic_stream_frame_pool_init() {
    return GQUIC_SUCCESS;
}

int gquic_stream_frame_pool_get(gquic_frame_stream_t **const stream) {
    if ((*stream = gquic_frame_stream_alloc()) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    GQUIC_FRAME_INIT(*stream);
    return GQUIC_SUCCESS;
}

int gquic_stream_frame_pool_put(gquic_frame_stream_t *const stream) {
    if (stream == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_frame_release(stream);
    return GQUIC_SUCCESS;
}
