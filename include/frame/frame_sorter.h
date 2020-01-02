#ifndef _LIBGQUIC_FRAME_FRAME_SORTER_H
#define _LIBGQUIC_FRAME_FRAME_SORTER_H

#include "util/str.h"
#include "util/rbtree.h"
#include "util/list.h"

typedef struct gquic_byte_interval_s gquic_byte_interval_t;
struct gquic_byte_interval_s {
    u_int64_t start;
    u_int64_t end;
};

typedef struct gquic_frame_sorter_entry_s gquic_frame_sorter_entry_t;
struct gquic_frame_sorter_entry_s {
    gquic_str_t data;
    struct {
        void *self;
        int (*cb) (void *const);
    } done_cb;
};

#define GQUIC_FRAME_SORTER_ENTRY_DONE(entry) ((entry)->done_cb.self != NULL \
                                              ? (entry)->done_cb.cb((entry)->done_cb.self) \
                                              : -1);

int gquic_frame_sorter_entry_init(gquic_frame_sorter_entry_t *const entry);

typedef struct gquic_frame_sorter_s gquic_frame_sorter_t;
struct gquic_frame_sorter_s {
    gquic_rbtree_t *root; /* u_int64_t: gquic_frame_sorter_entry_t */
    u_int64_t read_pos;
    int gaps_count;
    gquic_list_t gaps;
};

int gquic_frame_sorter_init(gquic_frame_sorter_t *const sorter);
int gquic_frame_sorter_ctor(gquic_frame_sorter_t *const sorter);
int gquic_frame_sorter_dtor(gquic_frame_sorter_t *const sorter);
int gquic_frame_sorter_push(gquic_frame_sorter_t *const sorter,
                            const gquic_str_t *const data,
                            const u_int64_t off,
                            int (*done_cb) (void *const),
                            void *const done_cb_self);
int gquic_frame_sorter_pop(u_int64_t *const off,
                           gquic_str_t *const data,
                           int (**done_cb) (void *const),
                           void **done_cb_self,
                           gquic_frame_sorter_t *const sorter);

#endif
