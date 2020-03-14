#include "util/prr.h"
#include <stddef.h>

int gquic_prr_init(gquic_prr_t *const prr) {
    if (prr == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    prr->ack_count = 0;
    prr->delivered_bytes = 0;
    prr->infly_bytes = 0;
    prr->sent_bytes = 0;

    return GQUIC_SUCCESS;
}

int gquic_prr_packet_lost(gquic_prr_t *const prr, const u_int64_t infly) {
    if (prr == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    prr->ack_count = 0;
    prr->delivered_bytes = 0;
    prr->infly_bytes = infly;
    prr->sent_bytes = 0;

    return GQUIC_SUCCESS;
}

int gquic_prr_allowable_send(gquic_prr_t *const prr, const u_int64_t cwnd, const u_int64_t infly, const u_int64_t slowstart_thd) {
    if (prr == NULL) {
        return 0;
    }
    if (prr->sent_bytes == 0 || infly < 1460) {
        return 1;
    }
    if (cwnd > infly) {
        return prr->delivered_bytes + prr->ack_count * 1460 > prr->sent_bytes;
    }
    return prr->delivered_bytes * slowstart_thd > prr->sent_bytes * prr->infly_bytes;
}
