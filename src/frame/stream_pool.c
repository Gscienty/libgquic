#include "frame/stream_pool.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static struct gquic_stream_frame_pool_s {

} pool;

int gquic_stream_frame_pool_init() {
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_stream_frame_pool_get(gquic_frame_stream_t **const stream) {
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_stream_alloc(stream));
    GQUIC_FRAME_INIT(*stream);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_stream_frame_pool_put(gquic_frame_stream_t *const stream) {
    if (stream == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_frame_release(stream);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
