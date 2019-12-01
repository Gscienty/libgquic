#ifndef _LIBGQUIC_HANDSHAKE_HEADER_PROTECTOR_H
#define _LIBGQUIC_HANDSHAKE_HEADER_PROTECTOR_H

#include "util/str.h"
#include "tls/cipher_suite.h"

typedef struct gquic_header_protector_s gquic_header_protector_t;
struct gquic_header_protector_s {
    void *self;
    int (*encrypt) (gquic_str_t *const, u_int8_t *const, void *const, gquic_str_t *const);
    int (*decrypt) (gquic_str_t *const, u_int8_t *const, void *const, gquic_str_t *const);
    int (*release) (void *const);
};

#define GQUIC_HEADER_PROTECTOR_ENCRYPT(h, f, p, s) ((p)->encrypt((h), (f), (p)->self, (s)))
#define GQUIC_HEADER_PROTECTOR_DECRYPT(h, f, p, s) ((p)->decrypt((h), (f), (p)->self, (s)))

int gquic_header_protector_init(gquic_header_protector_t *const protector);
int gquic_header_protector_assign(gquic_header_protector_t *const protector,
                                  const gquic_tls_cipher_suite_t *const suite,
                                  const gquic_str_t *const traffic_sec,
                                  int is_long_header);
int gquic_header_protector_release(gquic_header_protector_t *const protector);

#endif
