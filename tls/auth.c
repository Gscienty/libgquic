#include "tls/auth.h"
#include "tls/config.h"
#include "tls/prf.h"
#include "util/str.h"

int gquic_tls_selected_sigalg(u_int16_t *const sigalg,
                              u_int8_t *const sig_type,
                              const EVP_MD **const hash,
                              const EVP_PKEY *const pubkey,
                              const gquic_list_t *const peer_sigalgs,
                              const gquic_list_t *const self_sigalgs,
                              const u_int16_t tls_ver) {
    int pkey_id;
    if (sigalg == NULL || sig_type == NULL || hash == NULL || pubkey == NULL || peer_sigalgs == NULL || self_sigalgs == NULL || tls_ver == 0) {
        return -1;
    }
    pkey_id = EVP_PKEY_id(pubkey);
    if (tls_ver < GQUIC_TLS_VERSION_12 || gquic_list_head_empty(peer_sigalgs)) {
        switch (pkey_id) {
        case EVP_PKEY_RSA:
            if (tls_ver < GQUIC_TLS_VERSION_12) {
                *sigalg = 0;
                *sig_type = GQUIC_SIG_PKCS1V15;
                *hash = EVP_md5_sha1();
            }
            else {
                *sigalg = GQUIC_SIGALG_PKCS1_SHA1;
                *sig_type = GQUIC_SIG_PKCS1V15;
                *hash = EVP_sha1();
            }
            break;
        case EVP_PKEY_EC:
            *sigalg = GQUIC_SIGALG_ECDSA_SHA1;
            *sig_type = GQUIC_SIG_ECDSA;
            *hash = EVP_sha1();
            break;
        case EVP_PKEY_ED25519:
            if (tls_ver < GQUIC_TLS_VERSION_12) {
                return -2;
            }
            *sigalg = GQUIC_SIGALG_ED25519;
            *sig_type = GQUIC_SIG_ED25519;
            *hash = NULL;
            break;
        default:
            return -3;
        }
        return 0;
    }
    u_int16_t *peer_sigalg;
    GQUIC_LIST_FOREACH(peer_sigalg, peer_sigalgs) {
        if (!gquic_tls_is_supported_sigalg(*peer_sigalg, self_sigalgs)) {
            continue;
        }
        if (gquic_tls_hash_from_sigalg(hash, *peer_sigalg) != 0) {
            return -4;
        }
        if (gquic_tls_sig_trans(sig_type, *peer_sigalg) != 0) {
            return -5;
        }
        switch (pkey_id) {
        case EVP_PKEY_RSA:
            if (*sig_type == GQUIC_SIG_PKCS1V15 || *sig_type == GQUIC_SIG_RSAPSS) {
                *sigalg = *peer_sigalg;
                return 0;
            }
            break;
        case EVP_PKEY_EC:
            if (*sig_type == GQUIC_SIG_ECDSA) {
                *sigalg = *peer_sigalg;
                return 0;
            }
            break;
        case EVP_PKEY_ED25519:
            if (*sig_type == GQUIC_SIG_ED25519) {
                *sigalg = *peer_sigalg;
                return 0;
            }
            break;
        default:
            return -6;
        }
    }

    return -7;
}

int gquic_tls_verify_handshake_sign(const u_int8_t sig_type,
                                    const EVP_MD *const hash,
                                    const EVP_PKEY *const pubkey,
                                    const gquic_str_t *sign,
                                    const gquic_str_t *sig) {
    (void) sig_type;
    EVP_MD_CTX *ctx;
    int pubkey_type = 0;
    int ret = 0;
    if (pubkey == NULL || sign == NULL || sig == NULL) {
        return -1;
    }
    switch (sig_type) {
    case GQUIC_SIG_ECDSA:
        pubkey_type = EVP_PKEY_EC;
        break;
    case GQUIC_SIG_ED25519:
        pubkey_type = EVP_PKEY_ED25519;
        break;
    case GQUIC_SIG_PKCS1V15:
    case GQUIC_SIG_RSAPSS:
        pubkey_type = EVP_PKEY_RSA;
        break;
    default:
        return -2;
    }
    ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, NULL, hash, NULL, (EVP_PKEY *const) pubkey) <= 0) {
        goto failure;
    }
    if ((ret = EVP_DigestVerify(ctx, GQUIC_STR_VAL(sig), GQUIC_STR_SIZE(sig), GQUIC_STR_VAL(sign), GQUIC_STR_SIZE(sign))) != 1) {
        goto failure;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
failure:
    EVP_MD_CTX_free(ctx);
    return -3;
}
