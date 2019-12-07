#ifndef _LIBGQUIC_HANDSHAKE_AEAD_H
#define _LIBGQUIC_HANDSHAKE_AEAD_H

#include "handshake/header_protector.h"
#include "util/str.h"

typedef struct gquic_long_header_sealer_s gquic_long_header_sealer_t;
struct gquic_long_header_sealer_s {
    gquic_tls_aead_t aead;
    gquic_header_protector_t protector;
    gquic_str_t nonce_buf;
};

int gquic_long_header_sealer_init(gquic_long_header_sealer_t *const sealer);
int gquic_long_header_sealer_release(gquic_long_header_sealer_t *const sealer);
int gquic_long_header_sealer_seal(gquic_str_t *const tag,
                                  gquic_str_t *const cipher_text,
                                  gquic_long_header_sealer_t *const sealer,
                                  const u_int64_t pn,
                                  const gquic_str_t *const plain_text,
                                  const gquic_str_t *const addata);

typedef struct gquic_long_header_opener_s gquic_long_header_opener_t;
struct gquic_long_header_opener_s {
    gquic_tls_aead_t aead;
    gquic_header_protector_t protector;
    gquic_str_t nonce_buf;
};

int gquic_long_header_opener_init(gquic_long_header_opener_t *const opener);
int gquic_long_header_opener_release(gquic_long_header_opener_t *const opener);
int gquic_long_header_opener_open(gquic_str_t *const plain_text,
                                  gquic_long_header_opener_t *const opener,
                                  const u_int64_t pn,
                                  const gquic_str_t *const tag,
                                  const gquic_str_t *const cipher_text,
                                  const gquic_str_t *const addata);

typedef struct gquic_handshake_sealer_s gquic_handshake_sealer_t;
struct gquic_handshake_sealer_s {
    gquic_long_header_sealer_t sealer;
    void *drop_keys_self;
    int (*drop_keys) (void *const);
    int dropped;
    int is_client;
};

int gquic_handshake_sealer_init(gquic_handshake_sealer_t *const sealer);
int gquic_handshake_sealer_release(gquic_handshake_sealer_t *const sealer);
int gquic_handshake_sealer_seal(gquic_str_t *const tag,
                                gquic_str_t *const cipher_text,
                                gquic_handshake_sealer_t *const sealer,
                                const u_int64_t pn,
                                const gquic_str_t *const plain_text,
                                const gquic_str_t *const addata);

typedef struct gquic_handshake_opener_s gquic_handshake_opener_t;
struct gquic_handshake_opener_s {
    gquic_long_header_opener_t opener;
    void *drop_keys_self;
    int (*drop_keys) (void *const);
    int dropped;
    int is_client;
};

int gquic_handshake_opener_init(gquic_handshake_opener_t *const opener);
int gquic_handshake_opener_release(gquic_handshake_opener_t *const opener);
int gquic_handshake_opener_open(gquic_str_t *const plain_text,
                                gquic_handshake_opener_t *const opener,
                                const u_int64_t pn,
                                const gquic_str_t *const tag,
                                const gquic_str_t *const cipher_text,
                                const gquic_str_t *const addata);

#endif
