#ifndef _LIBGQUIC_TLS_KEY_SCHEDULE_H
#define _LIBGQUIC_TLS_KEY_SCHEDULE_H

#include "tls/config.h"
#include "util/str.h"

typedef gquic_curve_id_t (*gquic_ecdhe_params_curve_id_fptr_t) (const void *);
typedef int (*gquic_ecdhe_params_public_key_fptr_t) (const void *, gquic_str_t *);
typedef int (*gquic_ecdhe_params_shared_key_fptr_t) (const void *, gquic_str_t *, const gquic_str_t *);

typedef struct gquic_tls_ecdhe_params_s gquic_tls_ecdhe_params_t;
struct gquic_tls_ecdhe_params_s {
    void *self;
    gquic_ecdhe_params_curve_id_fptr_t curve_id_fptr;
    gquic_ecdhe_params_public_key_fptr_t public_key_fptr;
    gquic_ecdhe_params_shared_key_fptr_t shared_key_fptr;
};

#define GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(p) \
    (((gquic_tls_ecdhe_params_t *) (p))->curve_id_fptr(((gquic_tls_ecdhe_params_t *) (p))->self))
#define GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(p, s) \
    (((gquic_tls_ecdhe_params_t *) (p))->public_key_fptr(\
                                                         ((gquic_tls_ecdhe_params_t *) (p))->self,\
                                                         (s)))
#define GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(p, r, s) \
    (((gquic_tls_ecdhe_params_t *) (p))->shared_key_fptr(\
                                                         ((gquic_tls_ecdhe_params_t *) (p))->self,\
                                                         (r),\
                                                         (s)))

int gquic_tls_ecdhe_params_generate(gquic_tls_ecdhe_params_t *param, const gquic_curve_id_t curve_id);

int gquic_tls_ecdhe_params_release(gquic_tls_ecdhe_params_t *param);

#endif
