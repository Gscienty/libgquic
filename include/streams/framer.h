#ifndef _LIBGQUIC_STREAMS_FRAMER_H
#define _LIBGQUIC_STREAMS_FRAMER_H

#include "streams/stream_map.h"
#include "util/list.h"
#include "util/rbtree.h"
#include <semaphore.h>

typedef struct gquic_framer_s gquic_framer_t;
struct gquic_framer_s {
    sem_t mtx;
    sem_t ctrl_frame_mtx;
    gquic_stream_map_t *stream_getter;
    gquic_rbtree_t *active_streams_root; /* u_int64_t: u_int8_t */
    gquic_list_t stream_queue; /* u_int64_t */
    gquic_list_t ctrl_frames; /* void * */

    int stream_queue_count;
};

int gquic_framer_init(gquic_framer_t *const framer);
int gquic_framer_ctor(gquic_framer_t *const framer,
                      gquic_stream_map_t *const stream_getter);
int gquic_framer_queue_ctrl_frame(gquic_framer_t *const framer,
                                  void *const frame);
int gquic_framer_append_ctrl_frame(gquic_list_t *const frames,
                                   u_int64_t *const length,
                                   gquic_framer_t *const framer,
                                   const u_int64_t max_len);
int gquic_framer_add_active_stream(gquic_framer_t *const framer,
                                   const u_int64_t id);
int gquic_framer_append_stream_frames(gquic_list_t *const frames,
                                      u_int64_t *const length,
                                      gquic_framer_t *const framer,
                                      const u_int64_t max_len);

#endif
