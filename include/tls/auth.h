#ifndef _LIBGQUIC_TLS_AUTH_H
#define _LIBGQUIC_TLS_AUTH_H

#include "util/list.h"
#include "util/str.h"
#include <openssl/evp.h>

int gquic_tls_selected_sigalg(u_int16_t *const sigalg,
                              u_int8_t *const sig_type,
                              const EVP_MD **const hash,
                              const EVP_PKEY *const pkey,
                              const gquic_list_t *const peer_sigalgs,
                              const gquic_list_t *const self_sigalgs,
                              const u_int16_t tls_ver);

int gquic_tls_verify_handshake_sign(const u_int8_t sig_type,
                                    const EVP_MD *const hash,
                                    const EVP_PKEY *const pubkey,
                                    const gquic_str_t *sign,
                                    const gquic_str_t *sig);

#endif
