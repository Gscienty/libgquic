/* src/flowcontrol/base.c 流量控制基础模块实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "flowcontrol/base.h"
#include "util/time.h"

static inline gquic_exception_t gquic_flowcontrol_base_try_adjust_wnd_size(gquic_flowcontrol_base_t *const);

gquic_exception_t gquic_flowcontrol_base_init(gquic_flowcontrol_base_t *const base) {
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    base->sent_bytes = 0;
    base->swnd = 0;
    base->last_blocked_at = 0;
    pthread_mutex_init(&base->mtx, NULL);
    base->read_bytes = 0;
    base->highest_recv = 0;
    base->rwnd = 0;
    base->rwnd_size = 0;
    base->max_rwnd_size = 0;
    base->epoch_time = 0;
    base->epoch_off = 0;
    base->rtt = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_flowcontrol_base_dtor(gquic_flowcontrol_base_t *const base) {
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_destroy(&base->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_flowcontrol_base_is_newly_blocked(u_int64_t *const swnd, gquic_flowcontrol_base_t *const base) {
    if (base == NULL) {
        return false;
    }
    if (gquic_flowcontrol_base_swnd_size(base) != 0 || base->swnd == base->last_blocked_at) {
        if (swnd != NULL) {
            *swnd = 0;
        }
        return false;
    }

    base->last_blocked_at = base->swnd;
    if (swnd != NULL) {
        *swnd = base->swnd;
    }
    return true;
}

u_int64_t gquic_flowcontrol_base_get_wnd_update(gquic_flowcontrol_base_t *const base) {
    if (base == NULL) {
        return 0;
    }
    if (!gquic_flowcontrol_base_has_wnd_update(base)) {
        return 0;
    }
    gquic_flowcontrol_base_try_adjust_wnd_size(base);
    base->rwnd = base->read_bytes + base->rwnd_size;
    return base->rwnd;
}

static inline gquic_exception_t gquic_flowcontrol_base_try_adjust_wnd_size(gquic_flowcontrol_base_t *const base) {
    u_int64_t in_epoch_read_bytes = 0;
    u_int64_t now;
    double frac = 0;
    if (base == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    in_epoch_read_bytes = base->read_bytes - base->epoch_off;
    if (in_epoch_read_bytes <= base->rwnd_size / 2) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (base->rtt->smooth == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    frac = ((double) in_epoch_read_bytes) / base->rwnd_size;

    now = gquic_time_now();
    if (now - base->epoch_time < 4 * frac * base->rtt->smooth) {
        base->rwnd_size = 2 * base->rwnd_size < base->max_rwnd_size ? 2 * base->rwnd_size : base->max_rwnd_size;
    }
    base->epoch_time = now;
    base->epoch_off = base->read_bytes;
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
