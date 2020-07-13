/* src/frame/stream_pool.c STREAM frame 池实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/stream_pool.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static struct gquic_stream_frame_pool_s {

} pool;

gquic_exception_t gquic_stream_frame_pool_init() {
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_frame_pool_get(gquic_frame_stream_t **const stream) {
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_stream_alloc(stream));
    GQUIC_FRAME_INIT(*stream);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_frame_pool_put(gquic_frame_stream_t *const stream) {
    if (stream == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_frame_release(stream);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
