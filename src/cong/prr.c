/* src/cong/prr.c 快速恢复模块实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "cong/prr.h"
#include <stddef.h>

gquic_exception_t gquic_prr_init(gquic_prr_t *const prr) {
    if (prr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    prr->ack_count = 0;
    prr->delivered_bytes = 0;
    prr->infly_bytes = 0;
    prr->sent_bytes = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_prr_packet_lost(gquic_prr_t *const prr, const u_int64_t infly) {
    if (prr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    prr->ack_count = 0;
    prr->delivered_bytes = 0;
    prr->infly_bytes = infly;
    prr->sent_bytes = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_prr_allowable_send(gquic_prr_t *const prr, const u_int64_t cwnd, const u_int64_t infly, const u_int64_t slowstart_thd) {
    if (prr == NULL) {
        return false;
    }
    if (prr->sent_bytes == 0 || infly < 1460) {
        return true;
    }

    // PRR-SSRB
    if (cwnd > infly) {
        return prr->delivered_bytes + prr->ack_count * 1460 > prr->sent_bytes;
    }
    return prr->delivered_bytes * slowstart_thd > prr->sent_bytes * prr->infly_bytes;
}
