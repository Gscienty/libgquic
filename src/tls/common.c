/* src/tls/common.c TLS 常量定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

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

bool gquic_tls_is_supported_sigalg(const u_int16_t sigalg, const gquic_list_t *const sigalgs) {
    u_int16_t *sigalg_supported;
    if (sigalgs == NULL) {
        return false;
    }

    GQUIC_LIST_FOREACH(sigalg_supported, sigalgs) {
        if (*sigalg_supported == sigalg) {
            return true;
        }
    }
    return false;
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

bool gquic_tls_requires_cli_cert(u_int8_t c) {
    switch (c) {
    case GQUIC_CLI_AUTH_REQ_ANY:
    case GQUIC_CLI_AUTH_REQ_VERIFY:
        return true;
    default:
        return false;
    }
}

#if LOG
const char *gquic_enc_lv_to_string_inner(const int enc_lv) {
    switch (enc_lv) {
    case 1:
        return "ENC_LV_INITIAL";
    case 2:
        return "ENC_LV_HANDSHAKE";
    case 3:
        return "ENC_LV_1RTT";
    case 4:
        return "ENC_LV_APP";
    }
    return "ENC_LV_UNKNOW";
}

#endif
