#include "frame/frame_sorter.h"
#include "exception.h"
#include <stddef.h>

static int gquic_frame_sorter_entry_release(void *const);
static int gquic_frame_sorter_push_inner(gquic_frame_sorter_t *const,
                                         const gquic_str_t *const,
                                         u_int64_t,
                                         int (*) (void *const),
                                         void *);

int gquic_frame_sorter_entry_init(gquic_frame_sorter_entry_t *const entry) {
    if (entry == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_str_init(&entry->data);
    entry->done_cb.cb = NULL;
    entry->done_cb.self = NULL;

    return GQUIC_SUCCESS;
}

int gquic_frame_sorter_init(gquic_frame_sorter_t *const sorter) {
    if (sorter == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_list_head_init(&sorter->gaps);
    gquic_rbtree_root_init(&sorter->root);
    sorter->read_pos = 0;
    sorter->gaps_count = 0;

    return GQUIC_SUCCESS;
}

int gquic_frame_sorter_ctor(gquic_frame_sorter_t *const sorter) {
    gquic_byte_interval_t *interval = NULL;
    if (sorter == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((interval = gquic_list_alloc(sizeof(gquic_byte_interval_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    interval->start = 0;
    interval->end = (1UL << 62) - 1;
    sorter->gaps_count++;
    gquic_list_insert_after(&sorter->gaps, interval);

    return GQUIC_SUCCESS;
}

int gquic_frame_sorter_dtor(gquic_frame_sorter_t *const sorter) {
    gquic_rbtree_t *node = NULL;
    if (sorter == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    while (!gquic_list_head_empty(&sorter->gaps)) {
        sorter->gaps_count--;
        gquic_list_release(GQUIC_LIST_FIRST(&sorter->gaps));
    }
    while (!gquic_rbtree_is_nil(sorter->root)) {
        node = sorter->root;
        gquic_rbtree_remove(&sorter->root, &node);
        gquic_rbtree_release(node, gquic_frame_sorter_entry_release);
    }

    return GQUIC_SUCCESS;
}

static int gquic_frame_sorter_entry_release(void *const entry) {
    gquic_frame_sorter_entry_t *spec = entry;
    if (entry == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_str_reset(&spec->data);

    return GQUIC_SUCCESS;
}

static int gquic_frame_sorter_push_inner(gquic_frame_sorter_t *const sorter,
                                         const gquic_str_t *const data,
                                         u_int64_t off,
                                         int (*done_cb) (void *const),
                                         void *done_cb_self) {
    const gquic_rbtree_t *old_entry = NULL;
    gquic_frame_sorter_entry_t *old_entry_spec = NULL;
    gquic_byte_interval_t *gap = NULL;
    gquic_byte_interval_t *end_gap = NULL;
    gquic_byte_interval_t *next_end_gap = NULL;
    gquic_byte_interval_t *intv = NULL;
    const gquic_rbtree_t *cb_rbt = NULL;
    gquic_frame_sorter_entry_t *entry = NULL;
    u_int64_t start = 0;
    u_int64_t end = 0;
    u_int64_t cut_len = 0;
    u_int64_t len = 0;
    int cut_flag = 0;
    gquic_str_t tmp_data = { GQUIC_STR_SIZE(data), GQUIC_STR_VAL(data) };
    if (sorter == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_STR_SIZE(&tmp_data) == 0) {
        return GQUIC_EXCEPTION_DATA_EMPTY;
    }
    if (gquic_rbtree_find(&old_entry, sorter->root, &off, sizeof(u_int64_t)) == 0) {
        old_entry_spec = GQUIC_RBTREE_VALUE(old_entry);
        if (GQUIC_STR_SIZE(&tmp_data) <= GQUIC_STR_SIZE(&old_entry_spec->data)) {
            return GQUIC_EXCEPTION_DATA_DUPLICATE;
        }
        if (old_entry_spec->done_cb.self != NULL) {
            GQUIC_FRAME_SORTER_ENTRY_DONE(old_entry_spec);
        }
        gquic_str_reset(&old_entry_spec->data);
        gquic_str_copy(&old_entry_spec->data, &tmp_data);
        old_entry_spec->done_cb.cb = done_cb;
        old_entry_spec->done_cb.self = done_cb_self;
    }
    start = off;
    end = off + GQUIC_STR_SIZE(&tmp_data);
    GQUIC_LIST_FOREACH(gap, &sorter->gaps) {
        if (end < gap->start) {
            return GQUIC_EXCEPTION_DATA_DUPLICATE;
        }
        if (start <= gap->end && gap->start < end) {
            break;
        }
    }
    if (gap == NULL || gap == GQUIC_LIST_PAYLOAD(&sorter->gaps)) {
        return GQUIC_EXCEPTION_INTERNAL_ERROR;
    }
    if (start < gap->start) {
        cut_flag = 1;
        u_int64_t added = gap->start - start;
        off += added;
        start += added;
        tmp_data.size -= added;
        tmp_data.val += added;
    }
    end_gap = gap;
    while (end >= end_gap->end) {
        next_end_gap = gquic_list_next(end_gap);
        if (next_end_gap == GQUIC_LIST_PAYLOAD(&sorter->gaps)) {
            return GQUIC_EXCEPTION_INTERNAL_ERROR;
        }
        u_int64_t tmp_end = end_gap->end;
        if (end_gap != gap) {
            sorter->gaps_count--;
            gquic_list_release(end_gap);
        }
        if (end < next_end_gap->start) {
            break;
        }
        if (tmp_end != off) {
            if (gquic_rbtree_find(&cb_rbt, sorter->root, &tmp_end, sizeof(tmp_end)) == 0) {
                GQUIC_FRAME_SORTER_ENTRY_DONE((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt));
                gquic_rbtree_remove(&sorter->root, (gquic_rbtree_t **) &cb_rbt);
                gquic_rbtree_release((gquic_rbtree_t *) cb_rbt, gquic_frame_sorter_entry_release);
            }
        }
        end_gap = next_end_gap;
    }
    if (end > end_gap->end) {
        cut_len = end - end_gap->end;
        len = GQUIC_STR_SIZE(&tmp_data) - cut_len;
        end -= cut_len;
        tmp_data.size = len;
        cut_flag = 1;
    }
    if (start == gap->start) {
        if (end >= gap->end) {
            sorter->gaps_count--;
            gquic_list_remove(gap);
        }
        if (end < end_gap->end) {
            end_gap->start = end;
        }
    }
    else if (end == end_gap->end) {
        gap->end = start;
    }
    else {
        if (gap == end_gap) {
            if ((intv = gquic_list_alloc(sizeof(gquic_byte_interval_t))) == NULL) {
                return GQUIC_EXCEPTION_ALLOCATION_FAILED;
            }
            intv->start = end;
            intv->end = gap->end;
            gquic_list_insert_after(&GQUIC_LIST_META(gap), intv);
            gap->end = start;
        }
        else {
            gap->end = start;
            end_gap->start = end;
        }
    }

    if (sorter->gaps_count > 1000) {
        return GQUIC_EXCEPTION_TOO_MANY_GAPS;
    }

    if (cut_flag && GQUIC_STR_SIZE(&tmp_data) < 128) {
        if (done_cb_self != NULL) {
            done_cb(done_cb_self);
            done_cb_self = NULL;
        }
    }
    if (gquic_rbtree_find(&cb_rbt, sorter->root, &off, sizeof(u_int64_t)) == 0) {
        entry = GQUIC_RBTREE_VALUE(cb_rbt);
        gquic_str_reset(&entry->data);
        gquic_str_copy(&entry->data, &tmp_data);
        entry->done_cb.cb = done_cb;
        entry->done_cb.self = NULL;
    }
    else {
        if (gquic_rbtree_alloc((gquic_rbtree_t **) &cb_rbt, sizeof(u_int64_t), sizeof(gquic_frame_sorter_entry_t)) != 0) {
            return GQUIC_EXCEPTION_ALLOCATION_FAILED;
        }
        *((u_int64_t *) GQUIC_RBTREE_KEY(cb_rbt)) = off;
        ((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->done_cb.cb = done_cb;
        ((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->done_cb.self = done_cb_self;
        gquic_str_copy(&((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->data, &tmp_data);
        gquic_rbtree_insert(&sorter->root, (gquic_rbtree_t *) cb_rbt);
    }

    return GQUIC_SUCCESS;
}

int gquic_frame_sorter_push(gquic_frame_sorter_t *const sorter,
                            const gquic_str_t *const data,
                            const u_int64_t off,
                            int (*done_cb) (void *const),
                            void *const done_cb_self) {
    int exception = GQUIC_SUCCESS;
    if (sorter == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    exception = gquic_frame_sorter_push_inner(sorter, data, off, done_cb, done_cb_self);
    if (exception == GQUIC_EXCEPTION_DATA_EMPTY || exception == GQUIC_EXCEPTION_DATA_DUPLICATE) {
        if (done_cb != NULL && done_cb_self != NULL) {
            done_cb(done_cb_self);
        }
        return GQUIC_SUCCESS;
    }

    return exception;
}

int gquic_frame_sorter_pop(u_int64_t *const off,
                           gquic_str_t *const data,
                           int (**done_cb) (void *const),
                           void **done_cb_self,
                           gquic_frame_sorter_t *const sorter) {
    const gquic_rbtree_t *cb_rbt = NULL;
    if (off == NULL || data == NULL || done_cb == NULL || done_cb_self == NULL || sorter == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_rbtree_find(&cb_rbt, sorter->root, &sorter->read_pos, sizeof(u_int64_t)) != 0) {
        *off = sorter->read_pos;
        *done_cb = NULL;
        *done_cb_self = NULL;
        return GQUIC_SUCCESS;
    }
    gquic_rbtree_remove(&sorter->root, (gquic_rbtree_t **) &cb_rbt);
    *off = sorter->read_pos;
    sorter->read_pos += GQUIC_STR_SIZE(&((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->data);
    *data = ((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->data;
    *done_cb = ((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->done_cb.cb;
    *done_cb_self = ((gquic_frame_sorter_entry_t *) GQUIC_RBTREE_VALUE(cb_rbt))->done_cb.self;
    gquic_rbtree_release((gquic_rbtree_t *) cb_rbt, NULL);

    return GQUIC_SUCCESS;
}
