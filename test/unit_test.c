#include "unit_test.h"
#include <stdio.h>
#include "util/big_endian.h"

GQUIC_UNIT_TEST(__$anchor) { return 0; }

int main() {
    gquic_unit_test_t *unit_test_begin = &GQUIC_UNIT_TEST_STRUCT_NAME(__$anchor);
    gquic_unit_test_t *unit_test_end = &GQUIC_UNIT_TEST_STRUCT_NAME(__$anchor);
    gquic_unit_test_t *itr = NULL;

    for ( ;; ) {
        itr = unit_test_begin - 1;
        if (itr->magic != GQUIC_UNIT_TEST_MAGIC) {
            break;
        }
        unit_test_begin--;
    }

    for ( ;; ) {
        itr = unit_test_end + 1;
        if (itr->magic != GQUIC_UNIT_TEST_MAGIC) {
            break;
        }
        unit_test_end++;
    }
    unit_test_end++;

    for (itr = unit_test_begin; itr != unit_test_end; itr++) {
        if (itr == &GQUIC_UNIT_TEST_STRUCT_NAME(__$anchor)) {
            continue;
        }
        printf("UNIT TEST BEGIN: %s\n", itr->title);
        int ret = itr->cb();
        printf("UNIT TEST RESULT: %s\e[97m\n\n", ret == 0 ? "\e[32mSuccess" : "\e[31mFailure");
    }
    return 0;
}

