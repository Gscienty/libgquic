#ifndef _LIBGQUIC_TLS_KEY_SCHEDULE_H
#define _LIBGQUIC_TLS_KEY_SCHEDULE_H

#include "util/str.h"
#include "tls/cipher_suite.h"

typedef struct gquic_tls_ecdhe_params_s gquic_tls_ecdhe_params_t;
struct gquic_tls_ecdhe_params_s {
    void *self;
    u_int16_t (*curve_id) (const void *const);
    int (*public_key) (const void *const, gquic_str_t *const);
    int (*shared_key) (const void *const, gquic_str_t *const, const gquic_str_t *const);
    int (*release) (void *const);
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

int gquic_tls_ecdhe_params_generate(gquic_tls_ecdhe_params_t *param, const u_int16_t curve_id);
int gquic_tls_ecdhe_params_init(gquic_tls_ecdhe_params_t *param);
int gquic_tls_ecdhe_params_release(gquic_tls_ecdhe_params_t *param);

int gquic_tls_hkdf_extract(gquic_str_t *const ret, gquic_tls_mac_t *const hash, const gquic_str_t *const secret, const gquic_str_t *const salt);

int gquic_tls_hkdf_expand_label(gquic_str_t *const ret,
                                gquic_tls_mac_t *const hash,
                                const gquic_str_t *const secret,
                                const gquic_str_t *const content,
                                const gquic_str_t *const label,
                                const size_t length);


#endif
