#ifndef _LIBGQUIC_TLS_KEY_SCHEDULE_H
#define _LIBGQUIC_TLS_KEY_SCHEDULE_H

#include "tls/config.h"
#include "util/str.h"

typedef struct gquic_tls_ecdhe_params_s gquic_tls_ecdhe_params_t;
struct gquic_tls_ecdhe_params_s {
    void *self;
    gquic_curve_id_t (*curve_id)(const void *const);
    int (*public_key)(const void *const, gquic_str_t *const);
    int (*shared_key)(const void *const, gquic_str_t *const, const gquic_str_t *const);
};

#define GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(p) \
    (((gquic_tls_ecdhe_params_t *) (p))->curve_id(((gquic_tls_ecdhe_params_t *) (p))->self))
#define GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(p, s) \
    (((gquic_tls_ecdhe_params_t *) (p))->public_key(\
                                                    ((gquic_tls_ecdhe_params_t *) (p))->self,\
                                                    (s)))
#define GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(p, r, s) \
    (((gquic_tls_ecdhe_params_t *) (p))->shared_key(\
                                                    ((gquic_tls_ecdhe_params_t *) (p))->self,\
                                                    (r),\
                                                    (s)))

int gquic_tls_ecdhe_params_generate(gquic_tls_ecdhe_params_t *param, const gquic_curve_id_t curve_id);

int gquic_tls_ecdhe_params_init(gquic_tls_ecdhe_params_t *param);

int gquic_tls_ecdhe_params_release(gquic_tls_ecdhe_params_t *param);



#endif
