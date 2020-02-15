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
int gquic_long_header_sealer_ctor(gquic_long_header_sealer_t *const sealer,
                                  const gquic_tls_cipher_suite_t *const aead_suite,
                                  const gquic_str_t *key,
                                  const gquic_str_t *iv,
                                  const gquic_tls_cipher_suite_t *const protector_suite,
                                  const gquic_str_t *const traffic_sec);
int gquic_long_header_sealer_traffic_ctor(gquic_long_header_sealer_t *const sealer,
                                          const gquic_tls_cipher_suite_t *const suite,
                                          const gquic_str_t *const traffic_sec);
int gquic_long_header_sealer_dtor(gquic_long_header_sealer_t *const sealer);
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
int gquic_long_header_opener_ctor(gquic_long_header_opener_t *const opener,
                                  const gquic_tls_cipher_suite_t *const aead_suite,
                                  const gquic_str_t *key,
                                  const gquic_str_t *iv,
                                  const gquic_tls_cipher_suite_t *const protector_suite,
                                  const gquic_str_t *const traffic_sec);
int gquic_long_header_opener_traffic_ctor(gquic_long_header_opener_t *const opener,
                                          const gquic_tls_cipher_suite_t *const suite,
                                          const gquic_str_t *const traffic_sec);
int gquic_long_header_opener_dtor(gquic_long_header_opener_t *const opener);
int gquic_long_header_opener_open(gquic_str_t *const plain_text,
                                  gquic_long_header_opener_t *const opener,
                                  const u_int64_t pn,
                                  const gquic_str_t *const tag,
                                  const gquic_str_t *const cipher_text,
                                  const gquic_str_t *const addata);

typedef struct gquic_handshake_sealer_s gquic_handshake_sealer_t;
struct gquic_handshake_sealer_s {
    gquic_long_header_sealer_t sealer;
    struct {
        void *self;
        int (*cb) (void *const);
    } drop_keys;
    int dropped;
};

int gquic_handshake_sealer_init(gquic_handshake_sealer_t *const sealer);
int gquic_handshake_sealer_ctor(gquic_handshake_sealer_t *const sealer,
                                const gquic_tls_cipher_suite_t *const aead_suite,
                                const gquic_str_t *key,
                                const gquic_str_t *iv,
                                const gquic_tls_cipher_suite_t *const protector_suite,
                                const gquic_str_t *const traffic_sec,
                                void *drop_keys_self,
                                int (*drop_keys_cb) (void *const));
int gquic_handshake_sealer_traffic_ctor(gquic_handshake_sealer_t *const sealer,
                                        const gquic_tls_cipher_suite_t *const suite,
                                        const gquic_str_t *const traffic_sec,
                                        void *drop_keys_self,
                                        int (*drop_keys_cb) (void *const));
int gquic_handshake_sealer_dtor(gquic_handshake_sealer_t *const sealer);
int gquic_handshake_sealer_seal(gquic_str_t *const tag,
                                gquic_str_t *const cipher_text,
                                gquic_handshake_sealer_t *const sealer,
                                const u_int64_t pn,
                                const gquic_str_t *const plain_text,
                                const gquic_str_t *const addata);

#define GQUIC_HANDSHAKE_SEALER_DROP_KEYS(sealer) ((sealer)->drop_keys.cb((sealer)->drop_keys.self))

typedef struct gquic_handshake_opener_s gquic_handshake_opener_t;
struct gquic_handshake_opener_s {
    gquic_long_header_opener_t opener;
    struct {
        void *self;
        int (*cb) (void *const);
    } drop_keys;
    int dropped;
};

#define GQUIC_HANDSHAKE_OPENER_DROP_KEYS(opener) ((opener)->drop_keys.cb((opener)->drop_keys.self))

int gquic_handshake_opener_init(gquic_handshake_opener_t *const opener);
int gquic_handshake_opener_ctor(gquic_handshake_opener_t *const opener,
                                const gquic_tls_cipher_suite_t *const aead_suite,
                                const gquic_str_t *key,
                                const gquic_str_t *iv,
                                const gquic_tls_cipher_suite_t *const protector_suite,
                                const gquic_str_t *const traffic_sec,
                                void *drop_keys_self,
                                int (*drop_keys_cb) (void *const));
int gquic_handshake_opener_traffic_ctor(gquic_handshake_opener_t *const opener,
                                        const gquic_tls_cipher_suite_t *const suite,
                                        const gquic_str_t *const traffic_sec,
                                        void *drop_keys_self,
                                        int (*drop_keys_cb) (void *const));
int gquic_handshake_opener_dtor(gquic_handshake_opener_t *const opener);
int gquic_handshake_opener_open(gquic_str_t *const plain_text,
                                gquic_handshake_opener_t *const opener,
                                const u_int64_t pn,
                                const gquic_str_t *const tag,
                                const gquic_str_t *const cipher_text,
                                const gquic_str_t *const addata);

typedef struct gquic_common_long_header_sealer_s gquic_common_long_header_sealer_t;
struct gquic_common_long_header_sealer_s {
    int available;
    int use_handshake;
    union {
        gquic_long_header_sealer_t long_header_sealer;
        gquic_handshake_sealer_t handshake_sealer;
    } sealer;
};

int gquic_common_long_header_sealer_init(gquic_common_long_header_sealer_t *const sealer);
int gquic_common_long_header_sealer_long_header_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                     const gquic_tls_cipher_suite_t *const aead_suite,
                                                     const gquic_str_t *key,
                                                     const gquic_str_t *iv,
                                                     const gquic_tls_cipher_suite_t *const protector_suite,
                                                     const gquic_str_t *const traffic_sec);
int gquic_common_long_header_sealer_long_header_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                             const gquic_tls_cipher_suite_t *const suite,
                                                             const gquic_str_t *const traffic_sec);
int gquic_common_long_header_sealer_handshake_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                   const gquic_tls_cipher_suite_t *const aead_suite,
                                                   const gquic_str_t *key,
                                                   const gquic_str_t *iv,
                                                   const gquic_tls_cipher_suite_t *const protector_suite,
                                                   const gquic_str_t *const traffic_sec,
                                                   void *drop_keys_self,
                                                   int (*drop_keys_cb) (void *const),
                                                   int is_client);
int gquic_common_long_header_sealer_handshake_traffic_ctor(gquic_common_long_header_sealer_t *const sealer,
                                                           const gquic_tls_cipher_suite_t *const suite,
                                                           const gquic_str_t *const traffic_sec,
                                                           void *drop_keys_self,
                                                           int (*drop_keys_cb) (void *const),
                                                           int is_client);
int gquic_common_long_header_sealer_dtor(gquic_common_long_header_sealer_t *const sealer);
int gquic_common_long_header_sealer_seal(gquic_str_t *const tag,
                                         gquic_str_t *const cipher_text,
                                         gquic_common_long_header_sealer_t *const sealer,
                                         const u_int64_t pn,
                                         const gquic_str_t *const plain_text,
                                         const gquic_str_t *const addata);
int gquic_common_long_header_sealer_get_header_sealer(gquic_header_protector_t **const protector,
                                                      gquic_common_long_header_sealer_t *const sealer);

typedef struct gquic_common_long_header_opener_s gquic_common_long_header_opener_t;
struct gquic_common_long_header_opener_s {
    int available;
    int use_handshake;
    union {
        gquic_long_header_opener_t long_header_opener;
        gquic_handshake_opener_t handshake_opener;
    } opener;
};
int gquic_common_long_header_opener_init(gquic_common_long_header_opener_t *const opener);
int gquic_common_long_header_opener_long_header_ctor(gquic_common_long_header_opener_t *const opener,
                                                     const gquic_tls_cipher_suite_t *const aead_suite,
                                                     const gquic_str_t *key,
                                                     const gquic_str_t *iv,
                                                     const gquic_tls_cipher_suite_t *const protector_suite,
                                                     const gquic_str_t *const traffic_sec);
int gquic_common_long_header_opener_long_header_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                             const gquic_tls_cipher_suite_t *const suite,
                                                             const gquic_str_t *const traffic_sec);
int gquic_common_long_header_opener_handshake_ctor(gquic_common_long_header_opener_t *const opener,
                                                   const gquic_tls_cipher_suite_t *const aead_suite,
                                                   const gquic_str_t *key,
                                                   const gquic_str_t *iv,
                                                   const gquic_tls_cipher_suite_t *const protector_suite,
                                                   const gquic_str_t *const traffic_sec,
                                                   void *drop_keys_self,
                                                   int (*drop_keys_cb) (void *const),
                                                   int is_client);
int gquic_common_long_header_opener_handshake_traffic_ctor(gquic_common_long_header_opener_t *const opener,
                                                           const gquic_tls_cipher_suite_t *const suite,
                                                           const gquic_str_t *const traffic_sec,
                                                           void *drop_keys_self,
                                                           int (*drop_keys_cb) (void *const),
                                                           int is_client);
int gquic_common_long_header_opener_dtor(gquic_common_long_header_opener_t *const opener);
int gquic_common_long_header_opener_open(gquic_str_t *const plain_text,
                                         gquic_common_long_header_opener_t *const opener,
                                         const u_int64_t pn,
                                         const gquic_str_t *const tag,
                                         const gquic_str_t *const cipher_text,
                                         const gquic_str_t *const addata);
int gquic_common_long_header_opener_get_header_sealer(gquic_header_protector_t **const protector,
                                                      gquic_common_long_header_opener_t *const opener);


#endif
