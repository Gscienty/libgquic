#ifndef _LIBGQUIC_STREAMS_STREAM_MAP_H
#define _LIBGQUIC_STREAMS_STREAM_MAP_H

#include "streams/stream_sender.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "streams/inuni_stream_map.h"
#include "streams/inbidi_stream_map.h"
#include "streams/outuni_stream_map.h"
#include "streams/outbidi_stream_map.h"
#include "frame/max_streams.h"
#include "handshake/transport_parameters.h"

typedef struct gquic_stream_map_s gquic_stream_map_t;
struct gquic_stream_map_s {
    int is_client;
    gquic_stream_sender_t *sender;
    struct {
        void *self;
        int (*cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t);
    } flow_ctrl_ctor;

    gquic_inuni_stream_map_t inuni;
    gquic_inbidi_stream_map_t inbidi;
    gquic_outuni_stream_map_t outuni;
    gquic_outbidi_stream_map_t outbidi;
};

#define GQUIC_STREAM_MAP_FLOW_CTRL_CTOR(ctrl, map, n) ((map)->flow_ctrl_ctor.cb(ctrl, (map)->flow_ctrl_ctor.self, n))

int gquic_stream_map_init(gquic_stream_map_t *const str_map);
int gquic_stream_map_ctor(gquic_stream_map_t *const str_map,
                          gquic_stream_sender_t *const sender,
                          void *const flow_ctrl_ctor_self,
                          int (*flow_ctrl_ctor_cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t),
                          const u_int64_t max_inbidi_stream_count,
                          const u_int64_t max_inuni_stream_count,
                          const int is_client);
int gquic_stream_map_open_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
int gquic_stream_map_open_stream_sync(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
int gquic_stream_map_open_uni_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
int gquic_stream_map_open_uni_stream_sync(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
int gquic_stream_map_accept_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
int gquic_stream_map_accept_uni_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map);
int gquic_stream_map_release_stream(gquic_stream_map_t *const str_map, const u_int64_t id);
int gquic_stream_map_get_or_open_recv_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, const u_int64_t id);
int gquic_stream_map_get_or_open_send_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, const u_int64_t id);
int gquic_stream_map_handle_max_streams_frame(gquic_stream_map_t *const str_map, gquic_frame_max_streams_t *const frame);
int gquic_stream_map_handle_update_limits(gquic_stream_map_t *const str_map, gquic_transport_parameters_t *const params);
int gquic_stream_map_close(gquic_stream_map_t *const str_map, int err);

#endif
