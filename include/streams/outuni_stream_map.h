#ifndef _LIBGQUIC_STREAMS_OUTUNI_STREAM_MAP_H
#define _LIBGQUIC_STREAMS_OUTUNI_STREAM_MAP_H

#include "streams/stream.h"
#include "util/rbtree.h"
#include <semaphore.h>

typedef struct gquic_outuni_stream_map_s gquic_outuni_stream_map_t;
struct gquic_outuni_stream_map_s {
    sem_t mtx;
    gquic_rbtree_t *streams_root; /* u_int64_t: gquic_stream_t */
    gquic_rbtree_t *open_queue; /* u_int64_t: sem_t * */

    u_int64_t lowest_in_queue;
    u_int64_t highest_in_queue;
    u_int64_t max_stream;
    u_int64_t next_stream;
    int block_sent;

    struct {
        void *self;
        int (*cb) (gquic_stream_t *const, void *const, const u_int64_t);
    } stream_ctor;
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_stream_id_blocked;

    int closed;
    int closed_reason;
};

#define GQUIC_OUTUNI_STREAM_MAP_STREAM_CTOR(stream, map, n) ((map)->stream_ctor.cb((stream), (map)->stream_ctor.self, n))
#define GQUIC_OUTUNI_STREAM_MAP_QUEUE_STREAM_ID_BLOCKED(frame, map) ((map)->queue_stream_id_blocked.cb((frame), (map)->queue_stream_id_blocked.self))

int gquic_outuni_stream_map_init(gquic_outuni_stream_map_t *const str_map);
int gquic_outuni_stream_map_ctor(gquic_outuni_stream_map_t *const str_map,
                                 void *const stream_ctor_self,
                                 int (*stream_ctor_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                 void *const queue_stream_id_blocked_self,
                                 int (*queue_stream_id_blocked_cb) (void *const, void *const));
int gquic_outuni_stream_map_open_stream(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map);
int gquic_outuni_stream_map_open_stream_sync(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map);
int gquic_outuni_stream_map_get_stream(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map, const u_int64_t num);
int gquic_outuni_stream_map_release_stream(gquic_outuni_stream_map_t *const str_map, const u_int64_t num);
int gquic_outuni_stream_map_set_max_stream(gquic_outuni_stream_map_t *const str_map, const u_int64_t num);
int gquic_outuni_stream_map_close(gquic_outuni_stream_map_t *const str_map, const int err);

#endif
