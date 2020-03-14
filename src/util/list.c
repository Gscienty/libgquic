#include "util/list.h"
#include <malloc.h>
#include <string.h>
#include "exception.h"

void *gquic_list_alloc(size_t size) {
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
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    head->next = head;
    head->prev = head;
    return GQUIC_SUCCESS;
}

int gquic_list_head_empty(const gquic_list_t *head) {
    if (head == NULL) {
        return 1;
    }
    return head->next == head;
}

int gquic_list_release(void *const list) {
    if (list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_list_remove(list);
    free(&GQUIC_LIST_META(list));
    return GQUIC_SUCCESS;
}

int gquic_list_insert_after(gquic_list_t *ref, void *const node) {
    if (ref == NULL || node == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_LIST_META(node).next = ref->next;
    GQUIC_LIST_META(node).prev = ref;
    ref->next->prev = &GQUIC_LIST_META(node);
    ref->next = &GQUIC_LIST_META(node);
    return GQUIC_SUCCESS;
}

int gquic_list_insert_before(gquic_list_t *ref, void *const node) {
    if (ref == NULL || node == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_LIST_META(node).prev = ref->prev;
    GQUIC_LIST_META(node).next = ref;
    ref->prev->next = &GQUIC_LIST_META(node);
    ref->prev = &GQUIC_LIST_META(node);
    return GQUIC_SUCCESS;
}

void *gquic_list_next(void *const node) {
    if (node == NULL) {
        return NULL;
    }

    return GQUIC_LIST_PAYLOAD(GQUIC_LIST_META(node).next);
}

void *gquic_list_prev(void *const node) {
    if (node == NULL) {
        return NULL;
    }

    return GQUIC_LIST_PAYLOAD(GQUIC_LIST_META(node).prev);
}

int gquic_list_remove(void *const node) {
    if (node == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_LIST_META(node).prev->next = GQUIC_LIST_META(node).next;
    GQUIC_LIST_META(node).next->prev = GQUIC_LIST_META(node).prev;
    GQUIC_LIST_META(node).prev = &GQUIC_LIST_META(node);
    GQUIC_LIST_META(node).next = &GQUIC_LIST_META(node);
    return GQUIC_SUCCESS;
}

int gquic_list_copy(gquic_list_t *list, const gquic_list_t *ref, int (*fptr) (void *const, const void *const)) {
    void *field;
    void *ref_field;
    int ret = 0;
    if (list == NULL || ref == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_list_head_init(list) != 0) {
        return GQUIC_EXCEPTION_INITIAL_FAILED;
    }
    GQUIC_LIST_FOREACH(ref_field, ref) {
        if ((field = gquic_list_alloc(GQUIC_LIST_META(ref_field).payload_size)) == NULL) {
            return GQUIC_EXCEPTION_ALLOCATION_FAILED;
        }
        if (fptr == NULL) {
            memcpy(field, ref_field, GQUIC_LIST_META(ref_field).payload_size);
        }
        else if (GQUIC_ASSERT_CAUSE(ret, fptr(field, ref_field))) {
            return ret;
        }
        gquic_list_insert_before(list, field);
    }
    return GQUIC_SUCCESS;
}
