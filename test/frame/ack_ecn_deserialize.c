#include "frame/ack.h"
#include "frame/meta.h"
#include <malloc.h>
#include <string.h>

#define CHAR_2_HEX(n) ('0' <= (n) && (n) <= '9' ? ((n) - '0') : (((n) - 'a') + 10))

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }
    int size = strlen(argv[1]);
    void *buf = malloc(size / 2);
    if (buf == NULL) {
        return -2;
    }

    int i = 0;
    for (i = 0; i < size; i += 2) {
        ((unsigned char *) buf)[i / 2] = CHAR_2_HEX(argv[1][i]) << 4;
        ((unsigned char *) buf)[i / 2] |= CHAR_2_HEX(argv[1][i + 1]);
    }

    gquic_frame_ack_t *ack = gquic_frame_ack_alloc();
    if (ack == NULL) {
        return -2;
    }
    gquic_frame_init(ack);
    gquic_frame_deserialize(ack, buf, size / 2);

    printf("%02x ", GQUIC_FRAME_META(ack).type);
    printf("%ld ", ack->count.value);
    printf("%ld ", ack->delay.value);
    printf("%ld ", ack->largest_ack.value);
    printf("%ld ", ack->first_range.value);
    gquic_frame_range_t *range = NULL;
    GQUIC_LIST_FOREACH(range, &ack->range) {
        printf("%ld %ld ", range->gap.value, range->range.value);
    }
    printf("%ld ", ack->ecn.ect[0].value);
    printf("%ld ", ack->ecn.ect[1].value);
    printf("%ld ", ack->ecn.ecn_ce.value);
    printf("\n");

    return 0;
}
