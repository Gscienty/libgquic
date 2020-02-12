#ifndef _LIBGQUIC_PACKET_RECEIVED_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_RECEIVED_PACKET_HANDLER_H

#include <sys/types.h>
#include "util/list.h"
#include "util/rtt.h"
#include "frame/ack.h"

typedef struct gquic_packet_interval_s gquic_packet_interval_t;
struct gquic_packet_interval_s {
    u_int64_t start;
    u_int64_t end;
};

typedef struct gquic_packet_received_mem_s gquic_packet_received_mem_t;
struct gquic_packet_received_mem_s {
    int ranges_count;
    gquic_list_t ranges;
    u_int64_t deleted_below;
};

int gquic_packet_received_mem_init(gquic_packet_received_mem_t *const mem);
int gquic_packet_received_mem_dtor(gquic_packet_received_mem_t *const mem);
int gquic_packet_reveived_mem_received(gquic_packet_received_mem_t *const mem, const u_int64_t pn);
int gquic_packet_received_mem_delete_below(gquic_packet_received_mem_t *const mem, const u_int64_t pn);
int gquic_packet_received_mem_get_blocks(gquic_list_t *const blocks,
                                         const gquic_packet_received_mem_t *const mem);


typedef struct gquic_packet_received_packet_handler_s gquic_packet_received_packet_handler_t;
struct gquic_packet_received_packet_handler_s {
    u_int64_t largest_observed;
    u_int64_t ignore_below;
    u_int64_t largest_obeserved_time; /* microsecond */
    gquic_packet_received_mem_t mem;
    u_int64_t max_ack_delay;
    const gquic_rtt_t *rtt;
    struct {
        int packets_count;
        int ack_eliciting_count;
    } since_last_ack;
    int ack_queued;
    u_int64_t ack_alarm;
    gquic_frame_ack_t *last_ack;
};

int gquic_packet_received_packet_handler_init(gquic_packet_received_packet_handler_t *const handler);
int gquic_packet_received_packet_handler_ctor(gquic_packet_received_packet_handler_t *const handler,
                                              gquic_rtt_t *const rtt);
int gquic_packet_received_packet_handler_dtor(gquic_packet_received_packet_handler_t *const handler);
int gquic_packet_received_packet_handler_received_packet(gquic_packet_received_packet_handler_t *const handler,
                                                         const u_int64_t pn,
                                                         const u_int64_t recv_time,
                                                         const int should_inst_ack);
int gquic_packet_received_packet_handler_get_ack_frame(gquic_frame_ack_t **const ack,
                                                       gquic_packet_received_packet_handler_t *const handler);
int gquic_packet_received_packet_handler_ignore_below(gquic_packet_received_packet_handler_t *const handler,
                                                      const u_int64_t pn);

typedef struct gquic_packet_received_packet_handlers_s gquic_packet_received_packet_handlers_t;
struct gquic_packet_received_packet_handlers_s {
    gquic_packet_received_packet_handler_t initial;
    gquic_packet_received_packet_handler_t handshake;
    gquic_packet_received_packet_handler_t one_rtt;

    int initial_dropped;
    int handshake_dropped;
    int one_rtt_dropped;
};

int gquic_packet_received_packet_handlers_init(gquic_packet_received_packet_handlers_t *const handlers);
int gquic_packet_received_packet_handlers_ctor(gquic_packet_received_packet_handlers_t *const handlers,
                                               gquic_rtt_t *const rtt);
int gquic_packet_received_packet_handlers_dtor(gquic_packet_received_packet_handlers_t *const handlers);
int gquic_packet_received_packet_handlers_received_packet(gquic_packet_received_packet_handlers_t *const handler,
                                                          const u_int64_t pn,
                                                          const u_int64_t recv_time,
                                                          const int should_inst_ack,
                                                          const u_int8_t enc_lv);
int gquic_packet_received_packet_handlers_ignore_below(gquic_packet_received_packet_handlers_t *const handlers,
                                                       const u_int64_t pn);
int gquic_packet_received_packet_handlers_drop_packets(gquic_packet_received_packet_handlers_t *const handlers,
                                                       const u_int8_t enc_lv);
u_int64_t gquic_packet_received_packet_handlers_get_alarm_timeout(gquic_packet_received_packet_handlers_t *const handlers);
int gquic_packet_received_packet_handlers_get_ack_frame(gquic_frame_ack_t **const ack,
                                                        gquic_packet_received_packet_handlers_t *const handlers,
                                                        const u_int8_t enc_lv);

#endif
