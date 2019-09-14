#include "util/list.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int max_numeric;
    if (argc != 2) {
        return -1;
    }
    gquic_list_t list;
    gquic_list_head_init(&list);
    max_numeric = atoi(argv[1]);
    int i;
    for (i = 0; i < max_numeric; i++) {
        gquic_list_insert_after(&list, gquic_list_alloc(sizeof(int)));
        *((int *) gquic_list_next(GQUIC_LIST_PAYLOAD(&list))) = i;
    }

    gquic_abstract_list_ptr_t ptr = GQUIC_LIST_PAYLOAD(&list);
    for (ptr = gquic_list_prev(GQUIC_LIST_PAYLOAD(&list)); ptr != GQUIC_LIST_PAYLOAD(&list); ptr = gquic_list_prev(ptr)) {
        printf("%d", *(int *) ptr);
    }
    printf("\n");

    return 0;
}
