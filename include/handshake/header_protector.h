#ifndef _LIBGQUIC_HANDSHAKE_HEADER_PROTECTOR_H
#define _LIBGQUIC_HANDSHAKE_HEADER_PROTECTOR_H

#include "util/str.h"
#include "tls/cipher_suite.h"

typedef struct gquic_header_protector_s gquic_header_protector_t;
struct gquic_header_protector_s {
    void *self;
    int (*set_key) (void *const, gquic_str_t *const);
    int (*encrypt) (gquic_str_t *const, u_int8_t *const, void *const);
    int (*decrypt) (gquic_str_t *const, u_int8_t *const, void *const);
    int (*dtor) (void *const);
};

#define GQUIC_HEADER_PROTECTOR_SET_KEY(p, s) ((p)->set_key((p)->self, (s)))
#define GQUIC_HEADER_PROTECTOR_ENCRYPT(h, f, p) ((p)->encrypt((h), (f), (p)->self))
#define GQUIC_HEADER_PROTECTOR_DECRYPT(h, f, p) ((p)->decrypt((h), (f), (p)->self))

int gquic_header_protector_init(gquic_header_protector_t *const protector);
int gquic_header_protector_ctor(gquic_header_protector_t *const protector,
                                  const gquic_tls_cipher_suite_t *const suite,
                                  const gquic_str_t *const traffic_sec,
                                  int is_long_header);
int gquic_header_protector_dtor(gquic_header_protector_t *const protector);

#endif
