#include "packet/sent_packet_handler.h"
#include "tls/common.h"
#include "packet/send_mode.h"
#include <malloc.h>

static inline gquic_packet_sent_pn_t *gquic_sent_packet_handler_get_sent_pn(gquic_packet_sent_packet_handler_t *const,
                                                                            const u_int8_t enc_lv);
static inline int gquic_sent_packet_handler_get_earliest_loss_time_space(u_int64_t *const,
                                                                         u_int8_t *const,
                                                                         gquic_packet_sent_packet_handler_t *const);
static inline int gquic_sent_packet_handler_get_earliest_sent_time_space(u_int64_t *const,
                                                                         u_int8_t *const,
                                                                         gquic_packet_sent_packet_handler_t *const);
static inline int gquic_sent_packet_handler_set_loss_detection_timer(gquic_packet_sent_packet_handler_t *const);
static inline int gquic_sent_packet_handler_has_outstanding_crypto_packets(const gquic_packet_sent_packet_handler_t *const);
static inline int gquic_sent_packet_handler_has_outstanding_packets(const gquic_packet_sent_packet_handler_t *const);
static inline int gquic_packet_sent_packet_sent_packet_inner(gquic_packet_sent_packet_handler_t *const, gquic_packet_t *const);


int gquic_packet_sent_mem_init(gquic_packet_sent_mem_t *const mem) {
    if (mem == NULL) {
        return -1;
    }
    mem->count = 0;
    gquic_list_head_init(&mem->list);
    gquic_rbtree_root_init(&mem->root);

    return 0;
}

int gquic_packet_sent_mem_dtor(gquic_packet_sent_mem_t *const mem) {
    gquic_rbtree_t *del = NULL;
    if (mem == NULL) {
        return -1;
    }

    while (!gquic_rbtree_is_nil(mem->root)) {
        del = mem->root;
        gquic_rbtree_remove(&mem->root, &del);
        gquic_rbtree_release(del, NULL);
    }
    while (!gquic_list_head_empty(&mem->list)) {
        gquic_packet_dtor(GQUIC_LIST_FIRST(&mem->list));
        gquic_list_release(GQUIC_LIST_FIRST(&mem->list));
    }
    return 0;
}

int gquic_packet_sent_mem_sent_packet(gquic_packet_sent_mem_t *const mem, const gquic_packet_t *const packet) {
    const gquic_packet_t **packet_storage = NULL;
    gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (mem == NULL || packet == NULL) {
        return -1;
    }
    if ((packet_storage = gquic_list_alloc(sizeof(gquic_packet_t *))) == NULL) {
        return -2;
    }
    if (gquic_rbtree_alloc(&packet_storage_rb_node, sizeof(u_int64_t), sizeof(gquic_packet_t ***)) != 0) {
        return -3;
    }
    *packet_storage = packet;
    *(const gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node) = packet_storage;
    *(u_int64_t *) GQUIC_RBTREE_KEY(packet_storage_rb_node) = packet->pn;

    gquic_list_insert_before(&mem->list, packet_storage);
    gquic_rbtree_insert(&mem->root, packet_storage_rb_node);
    mem->count++;

    return 0;
}

int gquic_packet_sent_mem_get_packet(const gquic_packet_t **const packet, gquic_packet_sent_mem_t *const mem, const u_int64_t pn) {
    const gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (packet == NULL || mem == NULL) {
        return -1;
    }
    *packet = NULL;
    if (gquic_rbtree_find(&packet_storage_rb_node, mem->root, &pn, sizeof(u_int64_t)) != 0) {
        return -2;
    }
    *packet = **(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node);
    return 0;
}

int gquic_packet_sent_mem_remove(gquic_packet_sent_mem_t *const mem, const u_int64_t pn, int (*release_packet_func) (gquic_packet_t *const)) {
    gquic_packet_t *packet = NULL;
    gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (mem == NULL) {
        return -1;
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &packet_storage_rb_node, mem->root, &pn, sizeof(u_int64_t)) != 0) {
        return -2;
    }
    packet = **(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node);

    gquic_rbtree_remove(&mem->root, &packet_storage_rb_node);
    gquic_list_release(*(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node));
    gquic_rbtree_release(packet_storage_rb_node, NULL);

    if (packet != NULL && release_packet_func != NULL) {
        if (release_packet_func(packet) != 0) {
            return -3;
        }
    }
    mem->count--;
    return 0;
}

int gquic_packet_sent_pn_init(gquic_packet_sent_pn_t *const sent_pn) {
    if (sent_pn == NULL) {
        return -1;
    }
    gquic_packet_sent_mem_init(&sent_pn->mem);
    gquic_packet_number_gen_init(&sent_pn->pn_gen);
    sent_pn->largest_ack = -1;
    sent_pn->largest_sent = -1;
    sent_pn->loss_time = 0;
    sent_pn->last_sent_ack_time = 0;

    return 0;
}

int gquic_packet_sent_pn_ctor(gquic_packet_sent_pn_t *const sent_pn, const u_int64_t init_pn) {
    if (sent_pn == NULL) {
        return -1;
    }
    gquic_packet_number_gen_ctor(&sent_pn->pn_gen, init_pn, 500);
    return 0;
}

int gquic_packet_sent_pn_dtor(gquic_packet_sent_pn_t *const sent_pn) {
    if (sent_pn == NULL) {
        return -1;
    }
    gquic_packet_sent_mem_dtor(&sent_pn->mem);
    gquic_packet_number_gen_dtor(&sent_pn->pn_gen);
    return 0;
}

int gquic_packet_sent_packet_handler_init(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    handler->next_send_time = 0;
    handler->initial_packets = NULL;
    handler->handshake_packets = NULL;
    handler->one_rtt_packets = NULL;
    handler->handshake_complete = 0;
    handler->lowest_not_confirm_acked = 0;
    handler->infly_bytes = 0;
    gquic_cong_cubic_init(&handler->cong);
    handler->rtt = NULL;
    handler->pto_count = 0;
    handler->pto_mode = 0;
    handler->num_probes_to_send = 0;
    handler->alarm = 0;
    handler->event_cb.self = NULL;
    handler->event_cb.cb = NULL;

    return 0;
}

int gquic_packet_sent_packet_handler_ctor(gquic_packet_sent_packet_handler_t *const handler,
                                          const u_int64_t initial_pn,
                                          const gquic_rtt_t *const rtt,
                                          void *const event_self,
                                          int (*event_cb)(void *const, gquic_event_t *const)) {
    if (handler == NULL) {
        return -1;
    }
    gquic_cong_cubic_ctor(&handler->cong, rtt, 32 * 1460, 1000 * 1460);
    if ((handler->initial_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        return -2;
    }
    if ((handler->handshake_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        return -3;
    }
    if ((handler->one_rtt_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        return -4;
    }
    gquic_packet_sent_pn_init(handler->initial_packets);
    gquic_packet_sent_pn_init(handler->handshake_packets);
    gquic_packet_sent_pn_init(handler->one_rtt_packets);
    gquic_packet_sent_pn_ctor(handler->initial_packets, initial_pn);
    gquic_packet_sent_pn_ctor(handler->handshake_packets, 0);
    gquic_packet_sent_pn_ctor(handler->one_rtt_packets, 0);
    handler->rtt = rtt;
    handler->event_cb.self = event_self;
    handler->event_cb.cb = event_cb;

    return 0;
}

int gquic_packet_sent_packet_handler_dtor(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    if (handler->initial_packets != NULL) {
        gquic_packet_sent_pn_dtor(handler->initial_packets);
        free(handler->initial_packets);
    }
    if (handler->handshake_packets != NULL) {
        gquic_packet_sent_pn_dtor(handler->handshake_packets);
        free(handler->handshake_packets);
    }
    if (handler->one_rtt_packets != NULL) {
        gquic_packet_sent_pn_dtor(handler->one_rtt_packets);
        free(handler->one_rtt_packets);
    }

    return 0;
}

int gquic_packet_sent_packet_handler_drop_packets(gquic_packet_sent_packet_handler_t *const handler,
                                                  const u_int8_t enc_lv) {
    gquic_packet_sent_pn_t *sent_pn = NULL;
    const gquic_packet_t **packet_storage = NULL;
    if (handler == NULL) {
        return -1;
    }
    sent_pn = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv);
    GQUIC_LIST_FOREACH(packet_storage, &sent_pn->mem.list) {
        if ((*packet_storage)->included_infly) {
            handler->infly_bytes -= (*packet_storage)->len;
        }
    }
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        if (handler->initial_packets != NULL) {
            gquic_packet_sent_pn_dtor(handler->initial_packets);
            free(handler->initial_packets);
            handler->initial_packets = NULL;
        }
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        if (handler->handshake_packets != NULL) {
            gquic_packet_sent_pn_dtor(handler->handshake_packets);
            free(handler->handshake_packets);
            handler->handshake_packets = NULL;
        }
        break;
    default:
        return -2;
    }
    gquic_sent_packet_handler_set_loss_detection_timer(handler);
    handler->pto_mode = GQUIC_SEND_MODE_NONE;
    return 0;
}

int gquic_packet_sent_packet_sent_packet(gquic_packet_sent_packet_handler_t *const handler,
                                         gquic_packet_t *const packet) {
    gquic_packet_sent_pn_t *sent_pn = NULL;
    if (handler == NULL || packet == NULL) {
        return -1;
    }
    if (gquic_packet_sent_packet_sent_packet_inner(handler, packet)) {
        if ((sent_pn = gquic_sent_packet_handler_get_sent_pn(handler, packet->enc_lv)) == NULL) {
            return -2;
        }
        gquic_packet_sent_mem_sent_packet(&sent_pn->mem, packet);
        gquic_sent_packet_handler_set_loss_detection_timer(handler);
    }

    return 0;
}

int gquic_packet_sent_packet_received_ack(gquic_packet_sent_packet_handler_t *const handler,
                                          const gquic_frame_ack_t *const ack_frame,
                                          const u_int64_t wpn,
                                          const u_int8_t enc_lv,
                                          const u_int64_t recv_time) {
    gquic_packet_sent_pn_t *pn_spec = NULL;
    u_int64_t largest_ack = 0;
    if (handler == NULL || ack_frame == NULL) {
        return -1;
    }
    pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv);
    largest_ack = ack_frame->largest_ack;
    if (largest_ack > pn_spec->largest_ack) {
        return -2;
    }
    pn_spec->largest_ack = pn_spec->largest_ack > largest_ack ? pn_spec->largest_ack : largest_ack;
    if (!gquic_packet_number_gen_valid(&pn_spec->pn_gen, ack_frame)) {
        return -3;
    }

    // TODO

    return 0;
}

static inline gquic_packet_sent_pn_t *gquic_sent_packet_handler_get_sent_pn(gquic_packet_sent_packet_handler_t *const handler,
                                                                            const u_int8_t enc_lv) {
    if (handler == NULL) {
        return NULL;
    }
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        return handler->initial_packets;
    case GQUIC_ENC_LV_HANDSHAKE:
        return handler->handshake_packets;
    case GQUIC_ENC_LV_1RTT:
        return handler->one_rtt_packets;
    }

    return NULL;
}

static inline int gquic_sent_packet_handler_get_earliest_loss_time_space(u_int64_t *const loss_time,
                                                                         u_int8_t *const enc_lv,
                                                                         gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    if (handler->initial_packets != NULL) {
        *loss_time = handler->initial_packets->loss_time;
        *enc_lv = GQUIC_ENC_LV_INITIAL;
    }
    if (handler->handshake_packets != NULL
        && (*loss_time == 0
            || (handler->handshake_packets->loss_time != 0
                && handler->handshake_packets->loss_time < *loss_time))) {
        *loss_time = handler->handshake_packets->loss_time;
        *enc_lv = GQUIC_ENC_LV_HANDSHAKE;
    }
    if (handler->handshake_complete
        && (*loss_time == 0
            || (handler->one_rtt_packets->loss_time != 0
                && handler->one_rtt_packets->loss_time < *loss_time))) {
        *loss_time = handler->one_rtt_packets->loss_time;
        *enc_lv = GQUIC_ENC_LV_1RTT;
    }
    return 0;
}
static inline int gquic_sent_packet_handler_get_earliest_sent_time_space(u_int64_t *const sent_time,
                                                                         u_int8_t *const enc_lv,
                                                                         gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
    }
    if (handler->initial_packets != NULL) {
        *sent_time = handler->initial_packets->last_sent_ack_time;
        *enc_lv = GQUIC_ENC_LV_INITIAL;
    }
    if (handler->handshake_packets != NULL
        && (*sent_time == 0
            || (handler->handshake_packets->last_sent_ack_time != 0
                && handler->handshake_packets->last_sent_ack_time < *sent_time))) {
        *sent_time = handler->handshake_packets->last_sent_ack_time;
        *enc_lv = GQUIC_ENC_LV_HANDSHAKE;
    }
    if (handler->handshake_complete
        && (*sent_time == 0
            || (handler->one_rtt_packets->last_sent_ack_time != 0
                && handler->one_rtt_packets->last_sent_ack_time < *sent_time))) {
        *sent_time = handler->one_rtt_packets->last_sent_ack_time;
        *enc_lv = GQUIC_ENC_LV_1RTT;
    }
    return 0;
}

static inline int gquic_sent_packet_handler_set_loss_detection_timer(gquic_packet_sent_packet_handler_t *const handler) {
    u_int64_t loss_time = 0;
    u_int64_t sent_time = 0;
    u_int8_t enc_lv = 0;
    if (handler == NULL) {
        return -1;
    }
    if (gquic_sent_packet_handler_get_earliest_loss_time_space(&loss_time, &enc_lv, handler) != 0 || loss_time != 0) {
        handler->alarm = loss_time;
    }
    if (!gquic_sent_packet_handler_has_outstanding_packets(handler)) {
        handler->alarm = 0;
        return 0;
    }
    gquic_sent_packet_handler_get_earliest_sent_time_space(&sent_time, &enc_lv, handler);
    handler->alarm = sent_time + gquic_time_pto(handler->rtt, (enc_lv == GQUIC_ENC_LV_1RTT) << handler->pto_count);
    return 0;
}

static inline int gquic_sent_packet_handler_has_outstanding_crypto_packets(const gquic_packet_sent_packet_handler_t *const handler) {
    int has_initial = 0;
    int has_handshake = 0;
    if (handler == NULL) {
        return -1;
    }
    if (handler->initial_packets != NULL) {
        has_initial = handler->initial_packets->mem.count > 0;
    }
    if (handler->handshake_packets != NULL) {
        has_handshake = handler->handshake_packets->mem.count > 0;
    }
    return has_initial || has_handshake;
}

static inline int gquic_sent_packet_handler_has_outstanding_packets(const gquic_packet_sent_packet_handler_t *const handler) {
    return (handler->handshake_complete && handler->one_rtt_packets->mem.count > 0)
        || gquic_sent_packet_handler_has_outstanding_crypto_packets(handler);
}

static inline int gquic_packet_sent_packet_sent_packet_inner(gquic_packet_sent_packet_handler_t *const handler, gquic_packet_t *const packet) {
    int ack_eliciting = 0;
    gquic_packet_sent_pn_t *pn_spc = NULL;
    if (handler == NULL || packet == NULL) {
        return 0;
    }
    if ((pn_spc = gquic_sent_packet_handler_get_sent_pn(handler, packet->enc_lv)) == NULL) {
        return 0;
    }
    pn_spc->largest_sent = packet->pn;
    ack_eliciting = !gquic_list_head_empty(&packet->frames);
    if (ack_eliciting) {
        pn_spc->last_sent_ack_time = packet->send_time;
        packet->included_infly = 1;
        handler->infly_bytes += packet->len;
        if (handler->num_probes_to_send > 0) {
            handler->num_probes_to_send--;
        }
    }
    gquic_cong_cubic_on_packet_sent(&handler->cong, packet->pn, packet->len, ack_eliciting);
    handler->next_send_time = (handler->next_send_time > packet->send_time ? handler->next_send_time : packet->send_time)
        + gquic_cong_cubic_time_util_send(&handler->cong, handler->infly_bytes);
    return ack_eliciting;
}
