#ifndef _LIBGQUIC_STREAMS_INBIDI_STREAM_MAP_H
#define _LIBGQUIC_STREAMS_INBIDI_STREAM_MAP_H

#include "streams/stream.h"
#include "util/rbtree.h"
#include "coglobal.h"
#include <pthread.h>

typedef struct gquic_inbidi_stream_map_s gquic_inbidi_stream_map_t;
struct gquic_inbidi_stream_map_s {
    pthread_mutex_t mtx;
    liteco_channel_t new_stream_chan;

    gquic_rbtree_t *streams; /* u_int64_t: gquic_stream_t * */
    u_int64_t streams_count;
    gquic_rbtree_t *del_streams; /* u_int64_t; u_int8_t */
    
    u_int64_t next_stream_accept;
    u_int64_t next_stream_open;
    u_int64_t max_stream;
    u_int64_t max_stream_count;

    struct {
        void *self;
        int (*cb) (gquic_stream_t *const, void *const, const u_int64_t);
    } stream_ctor;
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_max_stream_id;

    int closed;
    int closed_reason;
};

#define GQUIC_INBIDI_STREAM_MAP_CTOR_STREAM(stream, map, n) ((map)->stream_ctor.cb(stream, (map)->stream_ctor.self, n))
#define GQUIC_INBIDI_STREAM_MAP_QUEUE_MAX_STREAM_ID(map, stream) ((map)->queue_max_stream_id.cb((map)->queue_max_stream_id.self, stream))

int gquic_inbidi_stream_map_init(gquic_inbidi_stream_map_t *const str_map);
int gquic_inbidi_stream_map_ctor(gquic_inbidi_stream_map_t *const str_map,
                                 void *const new_stream_self,
                                 int (*new_stream_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                 u_int64_t max_stream_count,
                                 void *const queue_max_stream_id_self,
                                 int (*queue_max_stream_id_cb) (void *const, void *const));
int gquic_inbidi_stream_map_accept_stream(gquic_stream_t **const str, gquic_inbidi_stream_map_t *const str_map, liteco_channel_t *const done_chan);
int gquic_inbidi_stream_map_get_or_open_stream(gquic_stream_t **const str, gquic_inbidi_stream_map_t *const str_map, const u_int64_t num);
int gquic_inbidi_stream_map_release_stream(gquic_inbidi_stream_map_t *const str_map, const u_int64_t num);
int gquic_inbidi_stream_map_close(gquic_inbidi_stream_map_t *const str_map, const int reason);

#endif
