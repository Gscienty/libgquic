#ifndef _LIBGQUIC_TLS_PRF_H
#define _LIBGQUIC_TLS_PRF_H

#include <openssl/evp.h>
#include <sys/types.h>

int gquic_tls_hash_from_sigalg(const EVP_MD **const hash, u_int16_t sigalg);

#endif
