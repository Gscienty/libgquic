#include "frame/ack.h"
#include "frame/meta.h"
#include <malloc.h>

int main() {
    gquic_frame_ack_t *ack = gquic_frame_ack_alloc();
    if (ack == NULL) {
        return -1;
    }
    gquic_frame_init(ack);
    gquic_varint_wrap(&ack->count, 4);
    gquic_varint_wrap(&ack->delay, 0xff);
    gquic_varint_wrap(&ack->largest_ack, 1 + 2 + 3 + 4 + 5 + 6 + 7);
    gquic_varint_wrap(&ack->first_range, 1);
    gquic_varint_wrap(&ack->ecn.ect[0], 10);
    gquic_varint_wrap(&ack->ecn.ect[1], 20);
    gquic_varint_wrap(&ack->ecn.ecn_ce, 30);
    GQUIC_FRAME_META(ack).type = 0x03;

    int i = 0;
    for (i = 0; i < 3; i++) {
        gquic_list_insert_before(&ack->range, gquic_list_alloc(sizeof(gquic_frame_range_t)));
        gquic_varint_wrap(&((gquic_frame_range_t *) gquic_list_prev(GQUIC_LIST_PAYLOAD(&ack->range)))->gap, (i + 1) * 2);
        gquic_varint_wrap(&((gquic_frame_range_t *) gquic_list_prev(GQUIC_LIST_PAYLOAD(&ack->range)))->range, (i + 1) * 2 + 1);
    }

    int size = gquic_frame_size(ack);
    void *buf = malloc(size);
    gquic_frame_serialize(ack, buf, size);
    for (i = 0; i < size; i++) {
        printf("%02x", ((unsigned char *) buf)[i]);
    }
    printf("\n");
    return 0;
}
