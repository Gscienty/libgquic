#ifndef _LIBGQUIC_UTIL_LIST_H
#define _LIBGQUIC_UTIL_LIST_H

#include <unistd.h>

typedef struct gquic_list_s gquic_list_t;
struct gquic_list_s {
    gquic_list_t *prev;
    gquic_list_t *next;
    size_t payload_size;
};

#define GQUIC_LIST_PAYLOAD(p) (((void *) (p)) + (sizeof(gquic_list_t)))
#define GQUIC_LIST_META(p) (*((gquic_list_t *) (((void *) (p)) - (sizeof(gquic_list_t)))))
#define GQUIC_LIST_FIRST(h) (gquic_list_next(GQUIC_LIST_PAYLOAD((h))))
#define GQUIC_LIST_LAST(h) (gquic_list_prev(GQUIC_LIST_PAYLOAD((h))))
#define GQUIC_LIST_FOREACH(p, h) \
    for (({\
          gquic_list_t *_$check = NULL;\
          (void) (_$check == (h));\
          (p) = GQUIC_LIST_FIRST((h));\
          }); (p) != GQUIC_LIST_PAYLOAD((h)); (p) = gquic_list_next((p)))
#define GQUIC_LIST_RFOREACH(p, h) \
    for (({\
          gquic_list_t *_$check = NULL;\
          (void) (_$check == (h));\
          (p) = GQUIC_LIST_LAST((h));\
          }); (p) != GQUIC_LIST_PAYLOAD((h)); (p) = gquic_list_prev((p)))

int gquic_list_alloc(void **const result, size_t size);
int gquic_list_release(void *const list);

int gquic_list_head_init(gquic_list_t *head);
int gquic_list_head_empty(const gquic_list_t *head);

int gquic_list_insert_after(gquic_list_t *ref, void *const node);
int gquic_list_insert_before(gquic_list_t *ref, void *const node);

void *gquic_list_next(void *const node);
void *gquic_list_prev(void *const node);

int gquic_list_remove(void *const node);

int gquic_list_copy(gquic_list_t *list, const gquic_list_t *ref, int (*fptr) (void *const, const void *const));

#endif
