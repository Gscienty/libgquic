#include "packet/received_packet_handler.h"
#include <malloc.h>

static int gquic_packet_received_mem_add(gquic_packet_received_mem_t *const, const u_int64_t);

static int gquic_packet_received_packet_handler_miss(const gquic_packet_received_packet_handler_t *const, const u_int64_t);
static int gquic_packet_received_packet_handler_has_miss_packet(const gquic_packet_received_packet_handler_t *const);

int gquic_packet_received_mem_init(gquic_packet_received_mem_t *const mem) {
    if (mem == NULL) {
         return -1;
    }
    gquic_list_head_init(&mem->ranges);
    mem->deleted_below = 0;
    mem->ranges_count = 0;

    return 0;
}

int gquic_packet_reveived_mem_received(gquic_packet_received_mem_t *const mem, const u_int64_t pn) {
    if (mem == NULL) {
        return -1;
    }
    if (pn < mem->deleted_below) {
        return 0;
    }

    gquic_packet_received_mem_add(mem, pn);
    if (mem->ranges_count > 500) {
        mem->ranges_count--;
        gquic_list_release(GQUIC_LIST_FIRST(&mem->ranges));
    }
    return 0;
}

static int gquic_packet_received_mem_add(gquic_packet_received_mem_t *const mem, const u_int64_t pn) {
    gquic_packet_interval_t *interval = NULL;
    gquic_packet_interval_t *prev_interval = NULL;
    if (mem == NULL) {
        return -1;
    }
    if (gquic_list_head_empty(&mem->ranges)) {
        if ((interval = malloc(sizeof(gquic_packet_interval_t))) == NULL) {
            return -1;
        }
        interval->end = pn;
        interval->start = pn;
        mem->ranges_count++;
        if (gquic_list_insert_before(&mem->ranges, interval) != 0) {
            return -2;
        }
        return 0;
    }

    GQUIC_LIST_RFOREACH(interval, &mem->ranges) {
        if (interval->start <= pn && pn <= interval->end) {
            return 0;
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
                return 0;
            }
            return 0;
        }

        if (pn > interval->end) {
            prev_interval = interval;
            if ((interval = gquic_list_alloc(sizeof(gquic_packet_interval_t))) == NULL) {
                return -3;
            }
            interval->start = pn;
            interval->end = pn;
            mem->ranges_count++;
            gquic_list_insert_after(&GQUIC_LIST_META(prev_interval), interval);
            return 0;
        }
    }

    if ((interval = gquic_list_alloc(sizeof(gquic_packet_interval_t))) == NULL) {
        return -4;
    }
    interval->end = pn;
    interval->start = pn;
    mem->ranges_count++;
    gquic_list_insert_after(&mem->ranges, interval);
    return 0;
}

int gquic_packet_received_mem_delete_below(gquic_packet_received_mem_t *const mem, const u_int64_t pn) {
    gquic_packet_interval_t *prev = NULL;
    gquic_packet_interval_t *cur = NULL;
    if (mem == NULL) {
        return -1;
    }
    if (pn < mem->deleted_below) {
        return 0;
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
            return 0;
        }
        else {
            return 0;
        }
    }

    return 0;
}

int gquic_packet_received_packet_handler_init(gquic_packet_received_packet_handler_t *const handler) {
    if (handler == NULL) {
        return -1;
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

    return 0;
}

int gquic_packet_received_packet_handler_received_packet(gquic_packet_received_packet_handler_t *const handler,
                                                         u_int64_t pn,
                                                         u_int64_t recv_time,
                                                         int should_inst_ack) {
    if (handler == NULL) {
        return -1;
    }
    if (pn < handler->ignore_below) {
        return 0;
    }
    if (pn >= handler->largest_observed) {
        handler->largest_observed = pn;
        handler->largest_obeserved_time = recv_time;
    }
    if (gquic_packet_reveived_mem_received(&handler->mem, pn) != 0) {
        return -2;
    }

    handler->since_last_ack.packets_count++;
    if (handler->last_ack == NULL) {
        handler->ack_queued = 1;
        return 0;
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
    return 0;
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

int gquic_packet_received_packet_handler_get_blocks(gquic_list_t *const blocks,
                                                    gquic_packet_received_packet_handler_t *const handler) {
    if (blocks == NULL || handler == NULL) {
        return -1;
    }

    // TODO

    return 0;
}
