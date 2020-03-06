#include "tls/prf.h"
#include "tls/common.h"

int gquic_tls_hash_from_sigalg(const EVP_MD **const hash, u_int16_t sigalg) {
    if (hash == NULL) {
        return -1;
    }
    switch (sigalg) {
    case GQUIC_SIGALG_ECDSA_SHA1:
    case GQUIC_SIGALG_PKCS1_SHA1:
        *hash = EVP_sha1();
        break;
    case GQUIC_SIGALG_PSS_SHA256:
    case GQUIC_SIGALG_PKCS1_SHA256:
    case GQUIC_SIGALG_ECDSA_P256_SHA256:
        *hash = EVP_sha256();
        break;
    case GQUIC_SIGALG_PSS_SHA384:
    case GQUIC_SIGALG_PKCS1_SHA384:
    case GQUIC_SIGALG_ECDSA_P384_SHA384:
        *hash = EVP_sha384();
        break;
    case GQUIC_SIGALG_PSS_SHA512:
    case GQUIC_SIGALG_PKCS1_SHA512:
    case GQUIC_SIGALG_ECDSA_P512_SHA512:
        *hash = EVP_sha512();
        break;
    case GQUIC_SIGALG_ED25519:
        *hash = NULL;
        break;
    default:
        return -2;
    }
    return 0;
}
