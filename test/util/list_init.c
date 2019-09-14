#include "util/list.h"
#include <stdio.h>

int main() {

    gquic_list_t list;
    gquic_list_head_init(&list);
    printf("%d\n", gquic_list_head_empty(&list));

    return 0;
}
