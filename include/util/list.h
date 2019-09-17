#ifndef _LIBGQUIC_UTIL_LIST_H
#define _LIBGQUIC_UTIL_LIST_H

#include <unistd.h>

typedef void *gquic_abstract_list_ptr_t;

typedef struct gquic_list_s gquic_list_t;
struct gquic_list_s {
    gquic_list_t *prev;
    gquic_list_t *next;
    size_t payload_size;
};

#define GQUIC_LIST_PAYLOAD(p) (((gquic_abstract_list_ptr_t) (p)) + (sizeof(gquic_list_t)))
#define GQUIC_LIST_META(p) (*((gquic_list_t *) (((gquic_abstract_list_ptr_t) (p)) - (sizeof(gquic_list_t)))))
#define GQUIC_LIST_FOREACH(p, h) for ((p) = gquic_list_next(GQUIC_LIST_PAYLOAD((h))); (p) != GQUIC_LIST_PAYLOAD((h)); (p) = gquic_list_next((p)))

gquic_abstract_list_ptr_t gquic_list_alloc(size_t size);
int gquic_list_release(gquic_abstract_list_ptr_t list);

int gquic_list_head_init(gquic_list_t *head);
int gquic_list_head_empty(gquic_list_t *head);

int gquic_list_insert_after(gquic_list_t *ref, gquic_abstract_list_ptr_t node);
int gquic_list_insert_before(gquic_list_t *ref, gquic_abstract_list_ptr_t node);

gquic_abstract_list_ptr_t gquic_list_next(gquic_abstract_list_ptr_t node);
gquic_abstract_list_ptr_t gquic_list_prev(gquic_abstract_list_ptr_t node);

int gquic_list_remove(gquic_abstract_list_ptr_t node);

#endif
