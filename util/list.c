#include "util/list.h"
#include <malloc.h>
#include <string.h>

gquic_abstract_list_ptr_t gquic_list_alloc(size_t size) {
    gquic_list_t *meta = (gquic_list_t *) malloc(sizeof(gquic_list_t) + size);
    if (meta == NULL) {
        return NULL;
    }
    gquic_list_head_init(meta);
    meta->payload_size = size;
    return GQUIC_LIST_PAYLOAD(meta);
}

int gquic_list_head_init(gquic_list_t *head) {
    if (head == NULL) {
        return -1;
    }
    head->next = head;
    head->prev = head;
    return 0;
}

int gquic_list_head_empty(const gquic_list_t *head) {
    if (head == NULL) {
        return 0;
    }
    return head->next == head;
}

int gquic_list_release(gquic_abstract_list_ptr_t list) {
    if (list == NULL) {
        return -1;
    }
    gquic_list_remove(list);
    free(&GQUIC_LIST_META(list));
    return 0;
}

int gquic_list_insert_after(gquic_list_t *ref, gquic_abstract_list_ptr_t node) {
    if (ref == NULL || node == NULL) {
        return -1;
    }
    GQUIC_LIST_META(node).next = ref->next;
    GQUIC_LIST_META(node).prev = ref;
    ref->next->prev = &GQUIC_LIST_META(node);
    ref->next = &GQUIC_LIST_META(node);
    return 0;
}

int gquic_list_insert_before(gquic_list_t *ref, gquic_abstract_list_ptr_t node) {
    if (ref == NULL || node == NULL) {
        return -1;
    }
    GQUIC_LIST_META(node).prev = ref->prev;
    GQUIC_LIST_META(node).next = ref;
    ref->prev->next = &GQUIC_LIST_META(node);
    ref->prev = &GQUIC_LIST_META(node);
    return 0;
}

gquic_abstract_list_ptr_t gquic_list_next(gquic_abstract_list_ptr_t node) {
    if (node == NULL) {
        return NULL;
    }

    return GQUIC_LIST_PAYLOAD(GQUIC_LIST_META(node).next);
}

gquic_abstract_list_ptr_t gquic_list_prev(gquic_abstract_list_ptr_t node) {
    if (node == NULL) {
        return NULL;
    }

    return GQUIC_LIST_PAYLOAD(GQUIC_LIST_META(node).prev);
}

int gquic_list_remove(gquic_abstract_list_ptr_t node) {
    if (node == NULL) {
        return -1;
    }
    GQUIC_LIST_META(node).prev->next = GQUIC_LIST_META(node).next;
    GQUIC_LIST_META(node).next->prev = GQUIC_LIST_META(node).prev;
    GQUIC_LIST_META(node).prev = &GQUIC_LIST_META(node);
    GQUIC_LIST_META(node).next = &GQUIC_LIST_META(node);
    return 0;
}

int gquic_list_copy(gquic_list_t *list, const gquic_list_t *ref, gquic_list_copy_payload_fptr_t fptr) {
    void *field;
    void *ref_field;
    if (list == NULL || ref == NULL) {
        return -1;
    }
    if (gquic_list_head_init(list) != 0) {
        return -2;
    }
    GQUIC_LIST_FOREACH(ref_field, ref) {
        if ((field = gquic_list_alloc(GQUIC_LIST_META(ref_field).payload_size)) == NULL) {
            return -3;
        }
        if (fptr == NULL) {
            memcpy(field, ref_field, GQUIC_LIST_META(ref_field).payload_size);
        }
        else if (fptr(field, ref_field) != 0) {
            return -4;
        }
        gquic_list_insert_before(list, field);
    }
    return 0;
}
