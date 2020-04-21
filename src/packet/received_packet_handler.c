#include "packet/received_packet_handler.h"
#include "frame/meta.h"
#include "tls/common.h"
#include "exception.h"

static int gquic_packet_received_mem_add(gquic_packet_received_mem_t *const, const u_int64_t);

static int gquic_packet_received_packet_handler_miss(const gquic_packet_received_packet_handler_t *const, const u_int64_t);
static int gquic_packet_received_packet_handler_has_miss_packet(const gquic_packet_received_packet_handler_t *const);

int gquic_packet_received_mem_init(gquic_packet_received_mem_t *const mem) {
    if (mem == NULL) {
         GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&mem->ranges);
    mem->deleted_below = 0;
    mem->ranges_count = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_mem_dtor(gquic_packet_received_mem_t *const mem) {
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (!gquic_list_head_empty(&mem->ranges)) {
        gquic_list_release(GQUIC_LIST_FIRST(&mem->ranges));
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_reveived_mem_received(gquic_packet_received_mem_t *const mem, const u_int64_t pn) {
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (pn < mem->deleted_below) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    gquic_packet_received_mem_add(mem, pn);
    if (mem->ranges_count > 500) {
        mem->ranges_count--;
        gquic_list_release(GQUIC_LIST_FIRST(&mem->ranges));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_received_mem_add(gquic_packet_received_mem_t *const mem, const u_int64_t pn) {
    gquic_packet_interval_t *interval = NULL;
    gquic_packet_interval_t *prev_interval = NULL;
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_list_head_empty(&mem->ranges)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &interval, sizeof(gquic_packet_interval_t)));
        interval->end = pn;
        interval->start = pn;
        mem->ranges_count++;
        if (gquic_list_insert_before(&mem->ranges, interval) != 0) {
            return GQUIC_EXCEPTION_INTERNAL_ERROR;
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_LIST_RFOREACH(interval, &mem->ranges) {
        if (interval->start <= pn && pn <= interval->end) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }

        int extended = 0;
        if (interval->end + 1 == pn) {
            extended = 1;
            interval->end++;
        }
        else if (interval->start - 1 == pn) {
            extended = 1;
            interval->start--;
        }

        if (extended) {
            prev_interval = gquic_list_prev(interval);
            if (prev_interval != GQUIC_LIST_PAYLOAD(&mem->ranges) && prev_interval->end + 1 == interval->start) {
                prev_interval->end = interval->end;
                gquic_list_release(interval);
                GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
            }
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }

        if (pn > interval->end) {
            prev_interval = interval;
            GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &interval, sizeof(gquic_packet_interval_t)));
            interval->start = pn;
            interval->end = pn;
            mem->ranges_count++;
            gquic_list_insert_after(&GQUIC_LIST_META(prev_interval), interval);
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &interval, sizeof(gquic_packet_interval_t)));
    interval->end = pn;
    interval->start = pn;
    mem->ranges_count++;
    gquic_list_insert_after(&mem->ranges, interval);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_mem_delete_below(gquic_packet_received_mem_t *const mem, const u_int64_t pn) {
    gquic_packet_interval_t *prev = NULL;
    gquic_packet_interval_t *cur = NULL;
    if (mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (pn < mem->deleted_below) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    mem->deleted_below = pn;
    prev = GQUIC_LIST_FIRST(&mem->ranges);
    GQUIC_LIST_FOREACH(cur, &mem->ranges) {
        prev = gquic_list_prev(cur);

        if (cur->end < pn) {
            gquic_list_release(cur);
            cur = prev;
        }
        else if (cur->start < pn && pn <= cur->end) {
            cur->start = pn;
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        else {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handler_init(gquic_packet_received_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    handler->largest_observed = 0;
    handler->ignore_below = 0;
    handler->largest_obeserved_time = 0;
    gquic_packet_received_mem_init(&handler->mem);
    handler->max_ack_delay = 0;
    handler->rtt = NULL;
    handler->since_last_ack.ack_eliciting_count = 0;
    handler->since_last_ack.packets_count = 0;
    handler->ack_queued = 0;
    handler->ack_alarm = 0;
    handler->last_ack = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handler_ctor(gquic_packet_received_packet_handler_t *const handler, gquic_rtt_t *const rtt) {
    if (handler == NULL || rtt == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->max_ack_delay = 25 * 1000;
    handler->rtt = rtt;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handler_dtor(gquic_packet_received_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_received_mem_dtor(&handler->mem);
    if (handler->last_ack != NULL) {
        gquic_frame_release(handler->last_ack);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handler_received_packet(gquic_packet_received_packet_handler_t *const handler,
                                                         const u_int64_t pn,
                                                         const u_int64_t recv_time,
                                                         const int should_inst_ack) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (pn < handler->ignore_below) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (pn >= handler->largest_observed) {
        handler->largest_observed = pn;
        handler->largest_obeserved_time = recv_time;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_reveived_mem_received(&handler->mem, pn));

    handler->since_last_ack.packets_count++;
    if (handler->last_ack == NULL) {
        handler->ack_queued = 1;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (gquic_packet_received_packet_handler_miss(handler, pn)) {
        handler->ack_queued = 1;
    }
    if (!handler->ack_queued && should_inst_ack) {
        handler->since_last_ack.ack_eliciting_count++;
        if (pn > 100) {
            if (handler->since_last_ack.ack_eliciting_count >= 10) {
                handler->ack_queued = 1;
            }
            else if (handler->ack_alarm == 0) {
                u_int64_t ack_delay = handler->rtt->min / 4;
                ack_delay = handler->max_ack_delay < ack_delay ? handler->max_ack_delay : ack_delay;
                handler->ack_alarm = recv_time + ack_delay;
            }
        }
        else {
            if (handler->since_last_ack.ack_eliciting_count >= 2) {
                handler->ack_queued = 1;
            }
            else if (handler->ack_alarm == 0) {
                handler->ack_alarm = recv_time + handler->max_ack_delay;
            }
        }
        if (gquic_packet_received_packet_handler_has_miss_packet(handler)) {
            u_int64_t ack_delay = handler->rtt->min / 8;
            u_int64_t ack_time = recv_time + ack_delay;
            if (handler->ack_alarm == 0 || ack_time > handler->ack_alarm) {
                handler->ack_alarm = ack_time;
            }
        }
    }
    if (handler->ack_queued) {
        handler->ack_alarm = 0;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_mem_get_blocks(gquic_list_t *const blocks, const gquic_packet_received_mem_t *const mem) {
    gquic_packet_interval_t *interval = NULL;
    gquic_frame_ack_block_t *block = NULL;
    if (blocks == NULL || mem == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(blocks);
    if (mem->ranges_count == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_LIST_RFOREACH(interval, &mem->ranges) {
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &block, sizeof(gquic_frame_ack_block_t)));
        block->smallest = interval->start;
        block->largest = interval->end;
        gquic_list_insert_before(blocks, block);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handler_get_ack_frame(gquic_frame_ack_t **const ack, gquic_packet_received_packet_handler_t *const handler) {
    int exception = GQUIC_SUCCESS;
    gquic_list_t blocks;
    if (ack == NULL || handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&blocks);
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_mem_get_blocks(&blocks, &handler->mem));
    if (gquic_list_head_empty(&blocks)) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_frame_ack_alloc(ack))) {
        while (!gquic_list_head_empty(&blocks)) {
            gquic_list_release(GQUIC_LIST_FIRST(&blocks));
        }
        GQUIC_PROCESS_DONE(exception);
    }
    GQUIC_FRAME_INIT(*ack);
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    (*ack)->delay = tv.tv_sec * 1000 * 1000 + tv.tv_usec - handler->largest_obeserved_time;
    gquic_frame_ack_ranges_from_blocks(*ack, &blocks);

    handler->last_ack = *ack;
    handler->ack_alarm = 0;
    handler->ack_queued = 0;
    handler->since_last_ack.ack_eliciting_count = 0;
    handler->since_last_ack.packets_count = 0;

    while (!gquic_list_head_empty(&blocks)) {
        gquic_list_release(GQUIC_LIST_FIRST(&blocks));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handler_ignore_below(gquic_packet_received_packet_handler_t *const handler, const u_int64_t pn) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (pn <= handler->ignore_below) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_mem_delete_below(&handler->mem, pn));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_packet_received_packet_handler_miss(const gquic_packet_received_packet_handler_t *const handler, const u_int64_t pn) {
    int ret = 0;
    gquic_list_t blocks;
    if (handler == NULL) {
        return 0;
    }
    if (handler->last_ack == NULL || pn < handler->ignore_below) {
        return 0;
    }
    gquic_list_head_init(&blocks);
    gquic_frame_ack_ranges_to_blocks(&blocks, handler->last_ack);
    ret = pn < ((gquic_frame_ack_block_t *) GQUIC_LIST_FIRST(&blocks))->largest && gquic_frame_ack_acks_packet(&blocks, pn);
    while (!gquic_list_head_empty(&blocks)) {
        gquic_list_release(GQUIC_LIST_FIRST(&blocks));
    }

    return ret;
}

static int gquic_packet_received_packet_handler_has_miss_packet(const gquic_packet_received_packet_handler_t *const handler) {
    if (handler == NULL) {
        return 0;
    }
    if (handler->last_ack == NULL) {
        return 0;
    }
    if (gquic_list_head_empty(&handler->mem.ranges)) {
        return 0;
    }
    gquic_packet_interval_t *interval = GQUIC_LIST_LAST(&handler->mem.ranges);

    return interval->start >= handler->last_ack->largest_ack && interval->end - interval->start + 1 <= 4;
}

int gquic_packet_received_packet_handlers_init(gquic_packet_received_packet_handlers_t *const handlers) {
    if (handlers == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_received_packet_handler_init(&handlers->initial);
    gquic_packet_received_packet_handler_init(&handlers->handshake);
    gquic_packet_received_packet_handler_init(&handlers->one_rtt);
    handlers->handshake_dropped = 1;
    handlers->initial_dropped = 1;
    handlers->one_rtt_dropped = 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handlers_ctor(gquic_packet_received_packet_handlers_t *const handlers, gquic_rtt_t *const rtt) {
    if (handlers == NULL || rtt == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_received_packet_handler_ctor(&handlers->initial, rtt);
    gquic_packet_received_packet_handler_ctor(&handlers->handshake, rtt);
    gquic_packet_received_packet_handler_ctor(&handlers->one_rtt, rtt);
    handlers->handshake_dropped = 0;
    handlers->initial_dropped = 0;
    handlers->one_rtt_dropped = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handlers_dtor(gquic_packet_received_packet_handlers_t *const handlers) {
    if (handlers == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_received_packet_handler_dtor(&handlers->initial);
    gquic_packet_received_packet_handler_dtor(&handlers->handshake);
    gquic_packet_received_packet_handler_dtor(&handlers->one_rtt);
    handlers->handshake_dropped = 0;
    handlers->initial_dropped = 0;
    handlers->one_rtt_dropped = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handlers_received_packet(gquic_packet_received_packet_handlers_t *const handlers,
                                                          const u_int64_t pn,
                                                          const u_int64_t recv_time,
                                                          const int should_inst_ack,
                                                          const u_int8_t enc_lv) {
    if (handlers == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        if (handlers->initial_dropped) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RECV_HANDLER_DROPPED);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handler_received_packet(&handlers->initial, pn, recv_time, should_inst_ack));
        break;

    case GQUIC_ENC_LV_HANDSHAKE:
        if (handlers->handshake_dropped) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RECV_HANDLER_DROPPED);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handler_received_packet(&handlers->handshake, pn, recv_time, should_inst_ack));
        break;

    case GQUIC_ENC_LV_1RTT:
        if (handlers->one_rtt_dropped) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RECV_HANDLER_DROPPED);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handler_received_packet(&handlers->one_rtt, pn, recv_time, should_inst_ack));
        break;

    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_received_packet_handlers_ignore_below(gquic_packet_received_packet_handlers_t *const handlers, const u_int64_t pn) {
    if (handlers == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    return gquic_packet_received_packet_handler_ignore_below(&handlers->one_rtt, pn);
}

int gquic_packet_received_packet_handlers_drop_packets(gquic_packet_received_packet_handlers_t *const handlers, const u_int8_t enc_lv) {
    if (handlers == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        gquic_packet_received_packet_handler_dtor(&handlers->initial);
        handlers->initial_dropped = 1;
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        gquic_packet_received_packet_handler_dtor(&handlers->handshake);
        handlers->handshake_dropped = 1;
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int64_t gquic_packet_received_packet_handlers_get_alarm_timeout(gquic_packet_received_packet_handlers_t *const handlers) {
    u_int64_t initial_alarm = 0;
    u_int64_t handshake_alarm = 0;
    u_int64_t one_rtt_alarm = 0;
    u_int64_t ret = 0;
    if (handlers == NULL) {
        return 0;
    }
    if (!handlers->initial_dropped) {
        initial_alarm = handlers->initial.ack_alarm;
    }
    if (!handlers->handshake_dropped) {
        handshake_alarm = handlers->handshake.ack_alarm;
    }
    one_rtt_alarm = handlers->one_rtt.ack_alarm;
    if (initial_alarm != 0) {
        ret = initial_alarm;
    }
    if (handshake_alarm < ret && handshake_alarm != 0) {
        ret = handshake_alarm;
    }
    if (one_rtt_alarm < ret && one_rtt_alarm != 0) {
        ret = one_rtt_alarm;
    }
    return ret;
}

int gquic_packet_received_packet_handlers_get_ack_frame(gquic_frame_ack_t **const ack,
                                                        gquic_packet_received_packet_handlers_t *const handlers,
                                                        const u_int8_t enc_lv) {
    if (ack == NULL || handlers == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        if (!handlers->initial_dropped) {
            GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handler_get_ack_frame(ack, &handlers->initial));
        }
        break;

    case GQUIC_ENC_LV_HANDSHAKE:
        if (!handlers->handshake_dropped) {
            GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handler_get_ack_frame(ack, &handlers->handshake));
        }
        break;

    case GQUIC_ENC_LV_1RTT:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handler_get_ack_frame(ack, &handlers->one_rtt));
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);

    default:
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (*ack != NULL) {
        (*ack)->delay = 0;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
