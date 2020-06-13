#include "util/list.h"
#include "util/malloc.h"
#include <string.h>
#include "exception.h"

int gquic_list_alloc(void **const result, size_t size) {
    if (result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_t *meta = NULL;
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &meta, sizeof(gquic_list_t) + size));
    gquic_list_head_init(meta);
    meta->payload_size = size;
    *result = GQUIC_LIST_PAYLOAD(meta);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_list_head_init(gquic_list_t *head) {
    if (head == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    head->next = head;
    head->prev = head;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_list_head_empty(const gquic_list_t *head) {
    if (head == NULL) {
        return 1;
    }

    return head->next == head;
}

int gquic_list_release(void *const list) {
    if (list == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_remove(list);
    gquic_free(&GQUIC_LIST_META(list));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_list_insert_after(gquic_list_t *ref, void *const node) {
    if (ref == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LIST_META(node).next = ref->next;
    GQUIC_LIST_META(node).prev = ref;
    ref->next->prev = &GQUIC_LIST_META(node);
    ref->next = &GQUIC_LIST_META(node);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_list_insert_before(gquic_list_t *ref, void *const node) {
    if (ref == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LIST_META(node).prev = ref->prev;
    GQUIC_LIST_META(node).next = ref;
    ref->prev->next = &GQUIC_LIST_META(node);
    ref->prev = &GQUIC_LIST_META(node);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LIST_META(node).prev->next = GQUIC_LIST_META(node).next;
    GQUIC_LIST_META(node).next->prev = GQUIC_LIST_META(node).prev;
    GQUIC_LIST_META(node).prev = &GQUIC_LIST_META(node);
    GQUIC_LIST_META(node).next = &GQUIC_LIST_META(node);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_list_copy(gquic_list_t *list, const gquic_list_t *ref, int (*fptr) (void *const, const void *const)) {
    void *field;
    void *ref_field;
    int ret = 0;
    if (list == NULL || ref == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_list_head_init(list) != 0) {
        return GQUIC_EXCEPTION_INITIAL_FAILED;
    }
    GQUIC_LIST_FOREACH(ref_field, ref) {
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc(&field, GQUIC_LIST_META(ref_field).payload_size));
        if (fptr == NULL) {
            memcpy(field, ref_field, GQUIC_LIST_META(ref_field).payload_size);
        }
        else if (GQUIC_ASSERT_CAUSE(ret, fptr(field, ref_field))) {
            return ret;
        }
        gquic_list_insert_before(list, field);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
