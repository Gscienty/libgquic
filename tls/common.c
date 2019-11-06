#include "tls/common.h"
#include <unistd.h>

static const u_int8_t hello_retry_request_random_payload[] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};
static const gquic_str_t hello_retry_request_random = { sizeof(hello_retry_request_random_payload), (void *) hello_retry_request_random_payload };

const gquic_str_t *gquic_tls_hello_retry_request_random() {
    return &hello_retry_request_random;
}

int gquic_tls_is_supported_sigalg(const u_int16_t sigalg, const gquic_list_t *const sigalgs) {
    u_int16_t *sigalg_supported;
    if (sigalgs == NULL) {
        return 0;
    }

    GQUIC_LIST_FOREACH(sigalg_supported, sigalgs) {
        if (*sigalg_supported == sigalg) {
            return 1;
        }
    }
    return 0;
}

u_int8_t gquic_tls_sig_from_sigalg(const u_int16_t sigalg) {
    switch (sigalg) {
    case GQUIC_SIGALG_PKCS1_SHA1:
    case GQUIC_SIGALG_PKCS1_SHA256:
    case GQUIC_SIGALG_PKCS1_SHA384:
    case GQUIC_SIGALG_PKCS1_SHA512:
        return GQUIC_SIG_PKCS1V15;
    case GQUIC_SIGALG_PSS_SHA256:
    case GQUIC_SIGALG_PSS_SHA384:
    case GQUIC_SIGALG_PSS_SHA512:
        return GQUIC_SIG_RSAPSS;
    case GQUIC_SIGALG_ECDSA_SHA1:
    case GQUIC_SIGALG_ECDSA_P256_SHA256:
    case GQUIC_SIGALG_ECDSA_P384_SHA384:
    case GQUIC_SIGALG_ECDSA_P512_SHA512:
        return GQUIC_SIG_ECDSA;
    case GQUIC_SIGALG_ED25519:
        return GQUIC_SIG_ED25519;
    }
    return 0xFF;
}
