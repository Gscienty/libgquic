#include "tls/auth.h"
#include "tls/common.h"
#include "tls/config.h"
#include "tls/prf.h"
#include "util/str.h"
#include <string.h>

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

int gquic_tls_verify_handshake_sign(const EVP_MD *const hash,
                                    EVP_PKEY *const pubkey,
                                    const gquic_str_t *sign,
                                    const gquic_str_t *sig) {
    EVP_MD_CTX *ctx;
    int ret = 0;
    if (pubkey == NULL || sign == NULL || sig == NULL) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, NULL, hash, NULL, pubkey) <= 0) {
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

int gquic_tls_signed_msg(gquic_str_t *const sign, const EVP_MD *const sig_hash, const gquic_str_t *const cnt, gquic_tls_mac_t *const mac) {
    int ret = 0;
    unsigned int len = 0;
    gquic_str_t buf = { 0, NULL };
    EVP_MD_CTX *ctx = NULL;
    if (sign == NULL || cnt == NULL || mac == NULL) {
        return -1;
    }
    if (gquic_tls_mac_md_sum(&buf, mac) != 0) {
        return -2;
    }
    if (sig_hash == NULL) {
        if (gquic_str_alloc(sign, GQUIC_STR_SIZE(cnt) + GQUIC_STR_SIZE(&buf))) {
            ret = -3;
            goto failure;
        }
        memcpy(GQUIC_STR_VAL(sign), GQUIC_STR_VAL(cnt), GQUIC_STR_SIZE(cnt));
        memcpy(GQUIC_STR_VAL(sign) + GQUIC_STR_SIZE(cnt), GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf));
        return 0;
    }
    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        ret = -4;
        goto failure;
    }
    if (EVP_DigestInit_ex(ctx, sig_hash, NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if (EVP_DigestUpdate(ctx, GQUIC_STR_VAL(cnt), GQUIC_STR_SIZE(cnt)) <= 0) {
        ret = -6;
        goto failure;
    }
    if (EVP_DigestUpdate(ctx, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) <= 0) {
        ret = -7;
        goto failure;
    }
    if (gquic_str_alloc(sign, EVP_MD_size(sig_hash)) != 0) {
        ret = -8;
        goto failure;
    }
    if (EVP_DigestFinal_ex(ctx, GQUIC_STR_VAL(sign), &len) <= 0) {
        ret = -9;
        goto failure;
    }

    gquic_str_reset(&buf);
    if (ctx == NULL) {
        EVP_MD_CTX_free(ctx);
    }
    return 0;
failure:
    gquic_str_reset(&buf);
    if (ctx == NULL) {
        EVP_MD_CTX_free(ctx);
    }
    return ret;
}

int gquic_tls_sig_pubkey(EVP_PKEY **const pubkey, const u_int8_t sig_type, const gquic_str_t *const pubkey_s) {
    if (pubkey == NULL || pubkey_s == NULL) {
        return -1;
    }
    switch (sig_type) {
    case GQUIC_SIG_ECDSA:
        if ((*pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, NULL, GQUIC_STR_VAL(pubkey_s), GQUIC_STR_SIZE(pubkey_s))) == NULL) {
            return -2;
        }
        break;
    case GQUIC_SIG_PKCS1V15:
    case GQUIC_SIG_RSAPSS:
        if ((*pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_RSA_PSS, NULL, GQUIC_STR_VAL(pubkey_s), GQUIC_STR_SIZE(pubkey_s))) == NULL) {
            return -3;
        }
        break;
    case GQUIC_SIG_ED25519:
        if ((*pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, GQUIC_STR_VAL(pubkey_s), GQUIC_STR_SIZE(pubkey_s))) == NULL) {
            return -3;
        }
        break;
    default:
        return -2;
    }
    return 0;
}
