#include "streams/stream_map.h"
#include "util/stream_id.h"
#include "frame/meta.h"

static int gquic_stream_map_outbidi_stream_ctor(gquic_stream_t *const, void *const, const u_int64_t);
static int gquic_stream_map_inbidi_stream_ctor(gquic_stream_t *const, void *const, const u_int64_t);
static int gquic_stream_map_outuni_stream_ctor(gquic_stream_t *const, void *const, const u_int64_t);
static int gquic_stream_map_inuni_stream_ctor(gquic_stream_t *const, void *const, const u_int64_t);

int gquic_stream_map_init(gquic_stream_map_t *const str_map) {
    if (str_map == NULL) {
        return -1;
    }

    str_map->is_client = 0;
    str_map->sender = NULL;
    str_map->flow_ctrl_ctor.cb = NULL;
    str_map->flow_ctrl_ctor.self = NULL;
    gquic_inuni_stream_map_init(&str_map->inuni);
    gquic_inbidi_stream_map_init(&str_map->inbidi);
    gquic_outuni_stream_map_init(&str_map->outuni);
    gquic_outbidi_stream_map_init(&str_map->outbidi);

    return 0;
}

int gquic_stream_map_ctor(gquic_stream_map_t *const str_map,
                          gquic_stream_sender_t *const sender,
                          void *const flow_ctrl_ctor_self,
                          int (*flow_ctrl_ctor_cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t),
                          const u_int64_t max_inbidi_stream_count,
                          const u_int64_t max_inuni_stream_count,
                          const int is_client) {
    if (str_map == NULL || sender == NULL || flow_ctrl_ctor_self == NULL || flow_ctrl_ctor_cb == NULL) {
        return -1;
    }

    str_map->is_client = is_client;
    str_map->flow_ctrl_ctor.cb = flow_ctrl_ctor_cb;
    str_map->flow_ctrl_ctor.self = flow_ctrl_ctor_self;
    str_map->sender = sender;

    gquic_outbidi_stream_map_ctor(&str_map->outbidi,
                                  str_map, gquic_stream_map_outbidi_stream_ctor,
                                  sender->queue_ctrl_frame.self, sender->queue_ctrl_frame.cb);

    gquic_inbidi_stream_map_ctor(&str_map->inbidi,
                                 str_map, gquic_stream_map_inbidi_stream_ctor,
                                 max_inbidi_stream_count,
                                 sender->queue_ctrl_frame.self, sender->queue_ctrl_frame.cb);

    gquic_outuni_stream_map_ctor(&str_map->outuni,
                                 str_map, gquic_stream_map_outuni_stream_ctor,
                                 sender->queue_ctrl_frame.self, sender->queue_ctrl_frame.cb);

    gquic_inuni_stream_map_ctor(&str_map->inuni,
                                str_map, gquic_stream_map_inuni_stream_ctor,
                                max_inuni_stream_count,
                                sender->queue_ctrl_frame.self, sender->queue_ctrl_frame.cb);

    return 0;
}

static int gquic_stream_map_outbidi_stream_ctor(gquic_stream_t *const str, void *const str_map_, const u_int64_t num) {
    u_int64_t id = 0;
    gquic_stream_map_t *str_map = str_map_;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    id = gquic_stream_num_to_stream_id(1, str_map->is_client, num);
    gquic_stream_ctor(str, id, str_map->sender, str_map->flow_ctrl_ctor.self, str_map->flow_ctrl_ctor.cb);
    return 0;
}

static int gquic_stream_map_inbidi_stream_ctor(gquic_stream_t *const str, void *const str_map_, const u_int64_t num) {
    u_int64_t id = 0;
    gquic_stream_map_t *str_map = str_map_;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    id = gquic_stream_num_to_stream_id(1, !str_map->is_client, num);
    gquic_stream_ctor(str, id, str_map->sender, str_map->flow_ctrl_ctor.self, str_map->flow_ctrl_ctor.cb);
    return 0;
}

static int gquic_stream_map_outuni_stream_ctor(gquic_stream_t *const str, void *const str_map_, const u_int64_t num) {
    u_int64_t id = 0;
    gquic_stream_map_t *str_map = str_map_;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    id = gquic_stream_num_to_stream_id(0, str_map->is_client, num);
    gquic_stream_ctor(str, id, str_map->sender, str_map->flow_ctrl_ctor.self, str_map->flow_ctrl_ctor.cb);
    return 0;
}

static int gquic_stream_map_inuni_stream_ctor(gquic_stream_t *const str, void *const str_map_, const u_int64_t num) {
    u_int64_t id = 0;
    gquic_stream_map_t *str_map = str_map_;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    id = gquic_stream_num_to_stream_id(0, !str_map->is_client, num);
    gquic_stream_ctor(str, id, str_map->sender, str_map->flow_ctrl_ctor.self, str_map->flow_ctrl_ctor.cb);
    return 0;
}

int gquic_stream_map_open_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map) {
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    return gquic_outbidi_stream_map_open_stream(str, &str_map->outbidi);
}

int gquic_stream_map_open_stream_sync(gquic_stream_t **const str, gquic_stream_map_t *const str_map) {
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    return gquic_outbidi_stream_map_open_stream_sync(str, &str_map->outbidi);
}

int gquic_stream_map_open_uni_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map) {
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    return gquic_outuni_stream_map_open_stream(str, &str_map->outuni);
}

int gquic_stream_map_open_uni_stream_sync(gquic_stream_t **const str, gquic_stream_map_t *const str_map) {
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    return gquic_outuni_stream_map_open_stream_sync(str, &str_map->outuni);
}

int gquic_stream_map_accept_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map) {
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    return gquic_inbidi_stream_map_accept_stream(str, &str_map->inbidi);
}

int gquic_stream_map_accept_uni_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map) {
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    return gquic_inuni_stream_map_accept_stream(str, &str_map->inuni);
}

int gquic_stream_map_release_stream(gquic_stream_map_t *const str_map, const u_int64_t id) {
    u_int64_t num = 0;
    if (str_map == NULL) {
        return -1;
    }
    num = gquic_stream_id_to_stream_num(id);

    if (gquic_stream_id_is_bidi(id)) {
        if (gquic_stream_id_is_client(id) == str_map->is_client) {
            return gquic_outbidi_stream_map_release_stream(&str_map->outbidi, num);
        }
        else {
            return gquic_inbidi_stream_map_release_stream(&str_map->inbidi, num);
        }
    }
    else {
        if (gquic_stream_id_is_client(id) == str_map->is_client) {
            return gquic_outuni_stream_map_release_stream(&str_map->outuni, num);
        }
        else {
            return gquic_inuni_stream_map_release_stream(&str_map->inuni, num);
        }
    }
    return -2;
}

int gquic_stream_map_get_or_open_recv_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, const u_int64_t id) {
    u_int64_t num = 0;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    num = gquic_stream_id_to_stream_num(id);
    if (gquic_stream_id_is_bidi(id)) {
        if (gquic_stream_id_is_client(id) == str_map->is_client) {
            return gquic_outbidi_stream_map_get_stream(str, &str_map->outbidi, num);
        }
        else {
            return gquic_inbidi_stream_map_get_or_open_stream(str, &str_map->inbidi, num);
        }
    }
    else {
        if (gquic_stream_id_is_client(id) == str_map->is_client) {
            return -2;
        }
        return gquic_inuni_stream_map_get_or_open_stream(str, &str_map->inuni, num);
    }

    return -3;
}

int gquic_stream_map_get_or_open_send_stream(gquic_stream_t **const str, gquic_stream_map_t *const str_map, const u_int64_t id) {
    u_int64_t num = 0;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    num = gquic_stream_id_to_stream_num(id);
    if (gquic_stream_id_is_bidi(id)) {
        if (gquic_stream_id_is_client(id) == str_map->is_client) {
            return gquic_outbidi_stream_map_get_stream(str, &str_map->outbidi, num);
        }
        else {
            return gquic_inbidi_stream_map_get_or_open_stream(str, &str_map->inbidi, num);
        }
    }
    else {
        if (gquic_stream_id_is_client(id) == str_map->is_client) {
            return gquic_outuni_stream_map_get_stream(str, &str_map->outuni, num);
        }
        return -2;
    }

    return -3;
}

int gquic_stream_map_handle_max_streams_frame(gquic_stream_map_t *const str_map, gquic_frame_max_streams_t *const frame) {
    if (str_map == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_META(frame).type == 0x12) {
        gquic_outbidi_stream_map_set_max_stream(&str_map->outbidi, frame->max);
    }
    else {
        gquic_outuni_stream_map_set_max_stream(&str_map->outuni, frame->max);
    }

    return 0;
}

int gquic_stream_map_handle_update_limits(gquic_stream_map_t *const str_map, gquic_transport_parameters_t *const params) {
    if (str_map == NULL || params == NULL) {
        return -1;
    }
    if (params->max_streams_bidi > (1UL << 60) || params->max_streams_uni > (1UL << 60)) {
        return -2;
    }
    gquic_outbidi_stream_map_set_max_stream(&str_map->outbidi, params->max_streams_bidi);
    gquic_outuni_stream_map_set_max_stream(&str_map->outuni, params->max_streams_uni);

    return 0;
}

int gquic_stream_map_close(gquic_stream_map_t *const str_map, int err) {
    if (str_map == NULL) {
        return -1;
    }
    gquic_outbidi_stream_map_close(&str_map->outbidi, err);
    gquic_outuni_stream_map_close(&str_map->outuni, err);
    gquic_inbidi_stream_map_close(&str_map->inbidi, err);
    gquic_inuni_stream_map_close(&str_map->inuni, err);

    return 0;
}
