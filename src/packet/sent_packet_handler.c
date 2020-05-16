#include "packet/sent_packet_handler.h"
#include "tls/common.h"
#include "packet/send_mode.h"
#include "frame/meta.h"
#include "exception.h"
#include <malloc.h>
#include <time.h>
#include <math.h>

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
static inline int gquic_packet_sent_packet_handler_sent_packet_inner(gquic_packet_sent_packet_handler_t *const, gquic_packet_t *const);
static int gquic_packet_sent_packet_handler_determine_newly_acked_packets(gquic_list_t *const,
                                                                          gquic_packet_sent_packet_handler_t *const,
                                                                          const gquic_list_t *const,
                                                                          const u_int8_t);
static int gquic_packet_sent_packet_handler_on_packet_acked(gquic_packet_sent_packet_handler_t *const,
                                                            const gquic_packet_t *const);
static int gquic_packet_sent_packet_handler_packet_release(gquic_packet_t *const);
static int gquic_packet_sent_packet_handler_detect_lost_packets(gquic_packet_sent_packet_handler_t *const,
                                                                const u_int64_t,
                                                                const u_int8_t,
                                                                const u_int64_t);
static int gquic_packet_sent_packet_handler_queue_frames_for_retrans(gquic_packet_t *const);
static int gquic_packet_sent_packet_handler_on_verified_loss_detection_timeout(gquic_packet_sent_packet_handler_t *const);


int gquic_packet_sent_mem_init(gquic_packet_sent_mem_t *const mem) {
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    mem->count = 0;
    gquic_list_head_init(&mem->list);
    gquic_rbtree_root_init(&mem->root);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_mem_dtor(gquic_packet_sent_mem_t *const mem) {
    gquic_rbtree_t *del = NULL;
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    while (!gquic_rbtree_is_nil(mem->root)) {
        del = mem->root;
        gquic_rbtree_remove(&mem->root, &del);
        gquic_rbtree_release(del, NULL);
    }
    while (!gquic_list_head_empty(&mem->list)) {
        gquic_packet_dtor(*(void **) GQUIC_LIST_FIRST(&mem->list));
        gquic_list_release(GQUIC_LIST_FIRST(&mem->list));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_mem_sent_packet(gquic_packet_sent_mem_t *const mem, const gquic_packet_t *const packet) {
    const gquic_packet_t **packet_storage = NULL;
    gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (mem == NULL || packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &packet_storage, sizeof(gquic_packet_t *)));
    GQUIC_ASSERT_FAST_RETURN(gquic_rbtree_alloc(&packet_storage_rb_node, sizeof(u_int64_t), sizeof(gquic_packet_t ***)));
    *packet_storage = packet;
    *(const gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node) = packet_storage;
    *(u_int64_t *) GQUIC_RBTREE_KEY(packet_storage_rb_node) = packet->pn;

    gquic_list_insert_before(&mem->list, packet_storage);
    gquic_rbtree_insert(&mem->root, packet_storage_rb_node);
    mem->count++;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_mem_get_packet(const gquic_packet_t **const packet, gquic_packet_sent_mem_t *const mem, const u_int64_t pn) {
    const gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (packet == NULL || mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *packet = NULL;
    if (gquic_rbtree_find(&packet_storage_rb_node, mem->root, &pn, sizeof(u_int64_t)) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
    }
    *packet = **(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_mem_remove(gquic_packet_sent_mem_t *const mem, const u_int64_t pn, int (*release_packet_func) (gquic_packet_t *const)) {
    gquic_packet_t *packet = NULL;
    gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &packet_storage_rb_node, mem->root, &pn, sizeof(u_int64_t)) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
    }
    packet = **(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node);

    gquic_rbtree_remove(&mem->root, &packet_storage_rb_node);
    gquic_list_release(*(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node));
    gquic_rbtree_release(packet_storage_rb_node, NULL);

    if (packet != NULL && release_packet_func != NULL) {
        GQUIC_ASSERT_FAST_RETURN(release_packet_func(packet));
    }
    mem->count--;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_pn_init(gquic_packet_sent_pn_t *const sent_pn) {
    if (sent_pn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_sent_mem_init(&sent_pn->mem);
    gquic_packet_number_gen_init(&sent_pn->pn_gen);
    sent_pn->largest_ack = -1;
    sent_pn->largest_sent = -1;
    sent_pn->loss_time = 0;
    sent_pn->last_sent_ack_time = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_pn_ctor(gquic_packet_sent_pn_t *const sent_pn, const u_int64_t init_pn) {
    if (sent_pn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_number_gen_ctor(&sent_pn->pn_gen, init_pn, 500);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_pn_dtor(gquic_packet_sent_pn_t *const sent_pn) {
    if (sent_pn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_sent_mem_dtor(&sent_pn->mem);
    gquic_packet_number_gen_dtor(&sent_pn->pn_gen);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_init(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_ctor(gquic_packet_sent_packet_handler_t *const handler, const u_int64_t initial_pn, gquic_rtt_t *const rtt) {
    if (handler == NULL || rtt == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_cong_cubic_ctor(&handler->cong, rtt, 32 * 1460, 1000 * 1460);
    if ((handler->initial_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if ((handler->handshake_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if ((handler->one_rtt_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_packet_sent_pn_init(handler->initial_packets);
    gquic_packet_sent_pn_init(handler->handshake_packets);
    gquic_packet_sent_pn_init(handler->one_rtt_packets);
    gquic_packet_sent_pn_ctor(handler->initial_packets, initial_pn);
    gquic_packet_sent_pn_ctor(handler->handshake_packets, 0);
    gquic_packet_sent_pn_ctor(handler->one_rtt_packets, 0);
    handler->rtt = rtt;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_dtor(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_drop_packets(gquic_packet_sent_packet_handler_t *const handler,
                                                  const u_int8_t enc_lv) {
    gquic_packet_sent_pn_t *sent_pn = NULL;
    const gquic_packet_t **packet_storage = NULL;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    gquic_sent_packet_handler_set_loss_detection_timer(handler);
    handler->pto_mode = GQUIC_SEND_MODE_NONE;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_sent_packet(gquic_packet_sent_packet_handler_t *const handler, gquic_packet_t *const packet) {
    gquic_packet_sent_pn_t *sent_pn = NULL;
    if (handler == NULL || packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_packet_sent_packet_handler_sent_packet_inner(handler, packet)) {
        if ((sent_pn = gquic_sent_packet_handler_get_sent_pn(handler, packet->enc_lv)) == NULL) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
        }
        gquic_packet_sent_mem_sent_packet(&sent_pn->mem, packet);
        gquic_sent_packet_handler_set_loss_detection_timer(handler);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_received_ack(gquic_packet_sent_packet_handler_t *const handler,
                                                  const gquic_frame_ack_t *const ack_frame,
                                                  const u_int8_t enc_lv,
                                                  const u_int64_t recv_time) {
    int exception = GQUIC_SUCCESS;
    gquic_packet_sent_pn_t *pn_spec = NULL;
    const gquic_packet_t *packet = NULL;
    const gquic_packet_t **packet_storage = NULL;
    u_int64_t largest_ack = 0;
    u_int64_t ack_delay = 0;
    gquic_list_t blocks;
    gquic_list_t acked_packets;
    if (handler == NULL || ack_frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&blocks);
    gquic_list_head_init(&acked_packets);
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_ack_ranges_to_blocks(&blocks, ack_frame));
    pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv);
    largest_ack = ack_frame->largest_ack;
    if (largest_ack > pn_spec->largest_ack) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RECV_UNSENT_PACKET_ACK);
        goto failure;
    }
    pn_spec->largest_ack = pn_spec->largest_ack > largest_ack ? pn_spec->largest_ack : largest_ack;
    if (!gquic_packet_number_gen_valid(&pn_spec->pn_gen, &blocks)) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RECV_SKIPPED_PACKET_ACK);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_sent_mem_get_packet(&packet, &pn_spec->mem, ack_frame->largest_ack))) {
        goto failure;
    }
    if (packet != NULL) {
        if (enc_lv == GQUIC_ENC_LV_1RTT) {
            ack_delay = ack_frame->delay < (u_int64_t) handler->rtt->max_delay ? ack_frame->delay : handler->rtt->max_delay;
        }
        gquic_rtt_update(handler->rtt, recv_time - packet->send_time, ack_delay);
        gquic_cong_cubic_try_exit_slow_start(&handler->cong);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_sent_packet_handler_determine_newly_acked_packets(&acked_packets, handler, &blocks, enc_lv))) {
        goto failure;
    }
    if (gquic_list_head_empty(&acked_packets)) {
        goto finished;
    }
    GQUIC_LIST_FOREACH(packet_storage, &acked_packets) {
        packet = *packet_storage;
        if (packet->largest_ack != (u_int64_t) -1 && enc_lv == GQUIC_ENC_LV_1RTT) {
            handler->lowest_not_confirm_acked = handler->lowest_not_confirm_acked > packet->largest_ack + 1
                ? handler->lowest_not_confirm_acked
                : packet->largest_ack + 1;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_sent_packet_handler_on_packet_acked(handler, packet))) {
            goto failure;
        }
        if (packet->included_infly) {
            gquic_cong_cubic_on_packet_acked(&handler->cong, packet->pn, packet->len, handler->infly_bytes, recv_time);
        }
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_sent_packet_handler_detect_lost_packets(handler, recv_time, enc_lv, handler->infly_bytes))) {
        goto failure;
    }
    handler->pto_count = 0;
    handler->num_probes_to_send = 0;
    gquic_sent_packet_handler_set_loss_detection_timer(handler);
finished:
    while (!gquic_list_head_empty(&blocks)) {
        gquic_list_release(GQUIC_LIST_FIRST(&blocks));
    }
    while (!gquic_list_head_empty(&acked_packets)) {
        gquic_list_release(GQUIC_LIST_FIRST(&acked_packets));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    while (!gquic_list_head_empty(&blocks)) {
        gquic_list_release(GQUIC_LIST_FIRST(&blocks));
    }
    while (!gquic_list_head_empty(&acked_packets)) {
        gquic_list_release(GQUIC_LIST_FIRST(&acked_packets));
    }
    GQUIC_PROCESS_DONE(exception);
}

static inline gquic_packet_sent_pn_t *gquic_sent_packet_handler_get_sent_pn(gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv) {
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
static inline int gquic_sent_packet_handler_get_earliest_sent_time_space(u_int64_t *const sent_time,
                                                                         u_int8_t *const enc_lv,
                                                                         gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_sent_packet_handler_set_loss_detection_timer(gquic_packet_sent_packet_handler_t *const handler) {
    u_int64_t loss_time = 0;
    u_int64_t sent_time = 0;
    u_int8_t enc_lv = 0;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_sent_packet_handler_get_earliest_loss_time_space(&loss_time, &enc_lv, handler);
    if (loss_time != 0) {
        handler->alarm = loss_time;
    }
    if (!gquic_sent_packet_handler_has_outstanding_packets(handler)) {
        handler->alarm = 0;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    gquic_sent_packet_handler_get_earliest_sent_time_space(&sent_time, &enc_lv, handler);
    handler->alarm = sent_time + (gquic_time_pto(handler->rtt, enc_lv == GQUIC_ENC_LV_1RTT) << handler->pto_count);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_sent_packet_handler_has_outstanding_crypto_packets(const gquic_packet_sent_packet_handler_t *const handler) {
    int has_initial = 0;
    int has_handshake = 0;
    if (handler == NULL) {
        return 0;
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

static inline int gquic_packet_sent_packet_handler_sent_packet_inner(gquic_packet_sent_packet_handler_t *const handler, gquic_packet_t *const packet) {
    int ack_eliciting = 0;
    gquic_packet_sent_pn_t *pn_spc = NULL;
    if (handler == NULL || packet == NULL) {
        return 0;
    }
    if ((pn_spc = gquic_sent_packet_handler_get_sent_pn(handler, packet->enc_lv)) == NULL) {
        return 0;
    }
    pn_spc->largest_sent = packet->pn;
    ack_eliciting = !gquic_list_head_empty(packet->frames);
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


static int gquic_packet_sent_packet_handler_determine_newly_acked_packets(gquic_list_t *const packets,
                                                                          gquic_packet_sent_packet_handler_t *const handler,
                                                                          const gquic_list_t *const blocks,
                                                                          const u_int8_t enc_lv) {
    int exception = GQUIC_SUCCESS;
    int has_mission_blocks = 0;
    gquic_packet_sent_pn_t *pn_spec = NULL;
    gquic_frame_ack_block_t *block = NULL;
    const gquic_packet_t **packet_storage = NULL;
    const gquic_packet_t **ret_packet_storage = NULL;
    u_int64_t lowest_ack = 0;
    u_int64_t largest_ack = 0;
    if (packets == NULL || handler == NULL || blocks == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(packets);
    if ((pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    lowest_ack = ((gquic_frame_ack_block_t *) GQUIC_LIST_LAST(blocks))->smallest;
    largest_ack = ((gquic_frame_ack_block_t *) GQUIC_LIST_FIRST(blocks))->largest;
    block = GQUIC_LIST_PAYLOAD(blocks);
    has_mission_blocks = !gquic_list_head_empty(blocks) && GQUIC_LIST_FIRST(blocks) != GQUIC_LIST_LAST(blocks);
    GQUIC_LIST_FOREACH(packet_storage, &pn_spec->mem.list) {
        if ((*packet_storage)->pn < lowest_ack) {
            continue;
        }
        if ((*packet_storage)->pn > largest_ack) {
            break;
        }
        if (has_mission_blocks) {
            block = gquic_list_prev(block);
            while ((*packet_storage)->pn > block->largest && block != GQUIC_LIST_PAYLOAD(blocks)) {
                block = gquic_list_prev(block);
            }
            if ((*packet_storage)->pn >= block->smallest) {
                if ((*packet_storage)->pn > block->largest) {
                    break;
                }
                if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &ret_packet_storage, sizeof(gquic_packet_t *)))) {
                    goto failure;
                }
                *ret_packet_storage = *packet_storage;
                gquic_list_insert_before(packets, ret_packet_storage);
            }
        }
        else {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &ret_packet_storage, sizeof(gquic_packet_t *)))) {
                goto failure;
            }
            *ret_packet_storage = *packet_storage;
            gquic_list_insert_before(packets, ret_packet_storage);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_packet_sent_packet_handler_on_packet_acked(gquic_packet_sent_packet_handler_t *const handler,
                                                            const gquic_packet_t *const packet) {
    gquic_packet_sent_pn_t *pn_spec = NULL;
    const gquic_packet_t *mem_packet = NULL;
    void **frame = NULL;
    if (handler == NULL || packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, packet->enc_lv)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_mem_get_packet(&mem_packet, &pn_spec->mem, packet->pn));
    if (mem_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_LIST_FOREACH(frame, packet->frames) {
        if (GQUIC_FRAME_META(*frame).on_acked.self != NULL) {
            GQUIC_FRAME_ON_ACKED(*frame);
        }
    }
    if (packet->included_infly) {
        handler->infly_bytes -= packet->len;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_mem_remove(&pn_spec->mem, packet->pn, gquic_packet_sent_packet_handler_packet_release));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_sent_packet_handler_packet_release(gquic_packet_t *const packet) {
    if (packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_dtor(packet);
    free(packet);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_sent_packet_handler_detect_lost_packets(gquic_packet_sent_packet_handler_t *const handler,
                                                                const u_int64_t now,
                                                                const u_int8_t enc_lv,
                                                                const u_int64_t infly) {
    double max_rtt = 0;
    double loss_delay = 0;
    u_int64_t lost_send_time = 0;
    gquic_packet_sent_pn_t *pn_spec = NULL;
    gquic_list_t lost_packets;
    gquic_packet_t **packet_storage = NULL;
    gquic_packet_t **lost_packet_storage = NULL;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&lost_packets);
    if ((pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    pn_spec->loss_time = 0;
    max_rtt = handler->rtt->latest > handler->rtt->smooth ? handler->rtt->latest : handler->rtt->smooth;
    loss_delay = 9.0 / 8 * max_rtt;
    loss_delay = loss_delay > 1000 ? loss_delay : 1000;
    lost_send_time = now - loss_delay;
    GQUIC_LIST_FOREACH(packet_storage, &pn_spec->mem.list) {
        if ((*packet_storage)->pn > pn_spec->largest_ack) {
            break;
        }
        if ((*packet_storage)->send_time < lost_send_time || pn_spec->largest_ack >= (*packet_storage)->pn + 3) {
            GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &lost_packet_storage, sizeof(gquic_packet_t *)));
            *lost_packet_storage = *packet_storage;
            gquic_list_insert_before(&lost_packets, lost_packet_storage);
        }
        else if (pn_spec->loss_time == 0) {
            pn_spec->loss_time = (*packet_storage)->send_time + loss_delay;
        }
    }
    GQUIC_LIST_FOREACH(lost_packet_storage, &lost_packets) {
        gquic_packet_sent_packet_handler_queue_frames_for_retrans(*lost_packet_storage);
        if ((*lost_packet_storage)->included_infly) {
            handler->infly_bytes -= (*lost_packet_storage)->len;
            gquic_cong_cubic_on_packet_lost(&handler->cong, (*lost_packet_storage)->pn, (*lost_packet_storage)->len, infly);
        }
        gquic_packet_sent_mem_remove(&pn_spec->mem, (*lost_packet_storage)->pn, gquic_packet_sent_packet_handler_packet_release);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_sent_packet_handler_queue_frames_for_retrans(gquic_packet_t *const packet) {
    void **frame_storage = NULL;
    if (packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LIST_FOREACH(frame_storage, packet->frames) {
        GQUIC_FRAME_ON_LOST(*frame_storage);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_on_loss_detection_timeout(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_sent_packet_handler_has_outstanding_packets(handler)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_packet_handler_on_verified_loss_detection_timeout(handler));
    }
    gquic_sent_packet_handler_set_loss_detection_timer(handler);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_sent_packet_handler_on_verified_loss_detection_timeout(gquic_packet_sent_packet_handler_t *const handler) {
    u_int64_t _;
    u_int64_t earliest_loss_time;
    u_int8_t enc_lv;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_sent_packet_handler_get_earliest_loss_time_space(&earliest_loss_time, &enc_lv, handler);
    if (earliest_loss_time != 0) {
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_packet_handler_detect_lost_packets(handler,
                                                                                      tv.tv_sec * 1000 * 1000 + tv.tv_usec,
                                                                                      enc_lv,
                                                                                      handler->infly_bytes));
    }
    gquic_sent_packet_handler_get_earliest_loss_time_space(&_, &enc_lv, handler);
    handler->pto_count++;
    handler->num_probes_to_send += 2;
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        handler->pto_mode = GQUIC_SEND_MODE_PTO_INITIAL;
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        handler->pto_mode = GQUIC_SEND_MODE_PTO_HANDSHAKE;
        break;
    case GQUIC_ENC_LV_1RTT:
        handler->pto_mode = GQUIC_SEND_MODE_PTO_APP;
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_peek_pn(u_int64_t *const pn,
                                             int *const pn_len,
                                             gquic_packet_sent_packet_handler_t *const handler,
                                             const u_int8_t enc_lv) {
    gquic_packet_t **packet_storage = NULL;
    gquic_packet_sent_pn_t *pn_spec = NULL;
    u_int64_t lowest_unacked = 0;
    if (pn == NULL || pn_len == NULL || handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    if (!gquic_list_head_empty(&pn_spec->mem.list)) {
        packet_storage = GQUIC_LIST_FIRST(&pn_spec->mem.list);
    }
    if (packet_storage != NULL) {
        lowest_unacked = (*packet_storage)->pn;
    }
    else {
        lowest_unacked = pn_spec->largest_ack + 1;
    }
    *pn = pn_spec->pn_gen.next;
    *pn_len = gquic_packet_number_len(*pn, lowest_unacked);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_pop_pn(u_int64_t *const ret, gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv) {
    gquic_packet_sent_pn_t *pn_spec = NULL;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_number_gen_next(ret, &pn_spec->pn_gen));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int8_t gquic_packet_sent_packet_handler_send_mode(gquic_packet_sent_packet_handler_t *const handler) {
    u_int64_t packets_count = 0;
    if (handler == NULL) {
        return GQUIC_SEND_MODE_NONE;
    }
    if (handler->one_rtt_packets == NULL) {
        return GQUIC_SEND_MODE_NONE;
    }
    packets_count = handler->one_rtt_packets->mem.count;
    if (handler->initial_packets != NULL) {
        packets_count += handler->initial_packets->mem.count;
    }
    if (handler->handshake_packets != NULL) {
        packets_count += handler->handshake_packets->mem.count;
    }
    if (packets_count >= 1000 * 2 * 5 / 4) {
        return GQUIC_SEND_MODE_NONE;
    }
    if (handler->num_probes_to_send > 0) {
        return handler->pto_mode;
    }
    if (!gquic_cong_cubic_allowable_send(&handler->cong, handler->infly_bytes)) {
        return GQUIC_SEND_MODE_ACK;
    }
    if (packets_count >= 1000 * 2) {
        return GQUIC_SEND_MODE_ACK;
    }

    return GQUIC_SEND_MODE_ANY;
}

int gquic_packet_sent_packet_handler_should_send_packets_count(gquic_packet_sent_packet_handler_t *const handler) {
    u_int64_t delay = 0;
    if (handler == NULL) {
        return 0;
    }
    if (handler->num_probes_to_send > 0) {
        return handler->num_probes_to_send;
    }
    delay = gquic_cong_cubic_time_util_send(&handler->cong, handler->infly_bytes);
    if (delay == 0 || delay > 100) {
        return 1;
    }

    return ceil(((double) 100) / delay);
}

int gquic_packet_sent_packet_handler_queue_probe_packet(gquic_packet_sent_packet_handler_t *const handler, const u_int8_t enc_lv) {
    gquic_packet_sent_pn_t *pn_spec = NULL;
    gquic_packet_t **packet_storage = 0;
    if (handler == NULL) {
        return 0;
    }
    if ((pn_spec = gquic_sent_packet_handler_get_sent_pn(handler, enc_lv)) == NULL) {
        return 0;
    }
    if (gquic_list_head_empty(&pn_spec->mem.list)) {
        return 0;
    }
    packet_storage = GQUIC_LIST_FIRST(&pn_spec->mem.list);
    gquic_packet_sent_packet_handler_queue_frames_for_retrans(*packet_storage);
    if ((*packet_storage)->included_infly) {
        handler->infly_bytes -= (*packet_storage)->len;
    }
    if (gquic_packet_sent_mem_remove(&pn_spec->mem, (*packet_storage)->pn, gquic_packet_sent_packet_handler_packet_release) != 0) {
        return 0;
    }

    return 1;
}

int gquic_packet_sent_packet_handler_reset_for_retry(gquic_packet_sent_packet_handler_t *const handler) {
    gquic_packet_t **packet_storage = NULL;
    u_int64_t pn = 0;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->infly_bytes = 0;
    GQUIC_LIST_FOREACH(packet_storage, &handler->initial_packets->mem.list) {
        gquic_packet_sent_packet_handler_queue_frames_for_retrans(*packet_storage);
    }
    if (handler->initial_packets == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_INITIIAL_SENT_HANDLER);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_number_gen_next(&pn, &handler->initial_packets->pn_gen));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_pn_dtor(handler->initial_packets));
    free(handler->initial_packets);
    if ((handler->initial_packets = malloc(sizeof(gquic_packet_sent_pn_t))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_packet_sent_pn_init(handler->initial_packets);
    gquic_packet_sent_pn_ctor(handler->initial_packets, pn);
    gquic_sent_packet_handler_set_loss_detection_timer(handler);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_sent_packet_handler_set_handshake_complete(gquic_packet_sent_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->handshake_complete = 1;
    gquic_sent_packet_handler_set_loss_detection_timer(handler);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
