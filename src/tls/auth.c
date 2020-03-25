#include "tls/auth.h"
#include "tls/common.h"
#include "tls/config.h"
#include "tls/prf.h"
#include "util/str.h"
#include "exception.h"
#include <string.h>
#include <openssl/pkcs12.h>

int gquic_tls_selected_sigalg(u_int16_t *const sigalg,
                              u_int8_t *const sig_type,
                              const EVP_MD **const hash,
                              const EVP_PKEY *const pubkey,
                              const gquic_list_t *const peer_sigalgs,
                              const gquic_list_t *const self_sigalgs,
                              const u_int16_t tls_ver) {
    int pkey_id;
    if (sigalg == NULL || sig_type == NULL || hash == NULL || pubkey == NULL || peer_sigalgs == NULL || self_sigalgs == NULL || tls_ver == 0) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
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
                return GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD;
            }
            *sigalg = GQUIC_SIGALG_ED25519;
            *sig_type = GQUIC_SIG_ED25519;
            *hash = NULL;
            break;
        default:
            return GQUIC_EXCEPTION_INVALID_PKEY;
        }
        return GQUIC_SUCCESS;
    }
    u_int16_t *peer_sigalg;
    GQUIC_LIST_FOREACH(peer_sigalg, peer_sigalgs) {
        if (!gquic_tls_is_supported_sigalg(*peer_sigalg, self_sigalgs)) {
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_tls_hash_from_sigalg(hash, *peer_sigalg));
        GQUIC_ASSERT_FAST_RETURN(gquic_tls_sig_trans(sig_type, *peer_sigalg));
        switch (pkey_id) {
        case EVP_PKEY_RSA:
            if (*sig_type == GQUIC_SIG_PKCS1V15 || *sig_type == GQUIC_SIG_RSAPSS) {
                *sigalg = *peer_sigalg;
                return GQUIC_SUCCESS;
            }
            break;
        case EVP_PKEY_EC:
            if (*sig_type == GQUIC_SIG_ECDSA) {
                *sigalg = *peer_sigalg;
                return GQUIC_SUCCESS;
            }
            break;
        case EVP_PKEY_ED25519:
            if (*sig_type == GQUIC_SIG_ED25519) {
                *sigalg = *peer_sigalg;
                return GQUIC_SUCCESS;
            }
            break;
        default:
            return GQUIC_EXCEPTION_INVALID_PKEY;
        }
    }

    return GQUIC_EXCEPTION_INVALID_PKEY;
}

int gquic_tls_verify_handshake_sign(const EVP_MD *const hash,
                                    EVP_PKEY *const pubkey,
                                    const gquic_str_t *sign,
                                    const gquic_str_t *sig) {
    EVP_MD_CTX *ctx;
    if (pubkey == NULL || sign == NULL || sig == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, NULL, hash, NULL, pubkey) <= 0) {
        goto failure;
    }
    if (EVP_DigestVerify(ctx, GQUIC_STR_VAL(sig), GQUIC_STR_SIZE(sig), GQUIC_STR_VAL(sign), GQUIC_STR_SIZE(sign)) != 1) {
        goto failure;
    }

    EVP_MD_CTX_free(ctx);
    return GQUIC_SUCCESS;
failure:
    EVP_MD_CTX_free(ctx);
    return GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED;
}

int gquic_tls_signed_msg(gquic_str_t *const sign, const EVP_MD *const sig_hash, const gquic_str_t *const cnt, gquic_tls_mac_t *const mac) {
    int exception = GQUIC_SUCCESS;
    unsigned int len = 0;
    gquic_str_t buf = { 0, NULL };
    EVP_MD_CTX *ctx = NULL;
    if (sign == NULL || cnt == NULL || mac == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_mac_md_sum(&buf, mac));
    if (sig_hash == NULL) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(sign, GQUIC_STR_SIZE(cnt) + GQUIC_STR_SIZE(&buf)))) {
            goto failure;
        }
        memcpy(GQUIC_STR_VAL(sign), GQUIC_STR_VAL(cnt), GQUIC_STR_SIZE(cnt));
        memcpy(GQUIC_STR_VAL(sign) + GQUIC_STR_SIZE(cnt), GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf));
        return 0;
    }
    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        exception = GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED;
        goto failure;
    }
    if (EVP_DigestInit_ex(ctx, sig_hash, NULL) <= 0) {
        exception = GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED;
        goto failure;
    }
    if (EVP_DigestUpdate(ctx, GQUIC_STR_VAL(cnt), GQUIC_STR_SIZE(cnt)) <= 0) {
        exception = GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED;
        goto failure;
    }
    if (EVP_DigestUpdate(ctx, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) <= 0) {
        exception = GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED;
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(sign, EVP_MD_size(sig_hash)))) {
        goto failure;
    }
    if (EVP_DigestFinal_ex(ctx, GQUIC_STR_VAL(sign), &len) <= 0) {
        exception = GQUIC_EXCEPTION_DIGEST_VERIFY_FAILED;
        goto failure;
    }

    gquic_str_reset(&buf);
    if (ctx == NULL) {
        EVP_MD_CTX_free(ctx);
    }
    return GQUIC_SUCCESS;
failure:
    gquic_str_reset(&buf);
    if (ctx == NULL) {
        EVP_MD_CTX_free(ctx);
    }
    return exception;
}

int gquic_tls_sig_pubkey(EVP_PKEY **const pubkey, const u_int8_t sig_type, const gquic_str_t *const pubkey_s) {
    if (pubkey == NULL || pubkey_s == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    switch (sig_type) {
    case GQUIC_SIG_ECDSA:
        if ((*pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, NULL, GQUIC_STR_VAL(pubkey_s), GQUIC_STR_SIZE(pubkey_s))) == NULL) {
            return GQUIC_EXCEPTION_ALLOCATION_FAILED;
        }
        break;

    case GQUIC_SIG_PKCS1V15:
    case GQUIC_SIG_RSAPSS:
        if ((*pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_RSA_PSS, NULL, GQUIC_STR_VAL(pubkey_s), GQUIC_STR_SIZE(pubkey_s))) == NULL) {
            return GQUIC_EXCEPTION_ALLOCATION_FAILED;
        }
        break;

    case GQUIC_SIG_ED25519:
        if ((*pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, GQUIC_STR_VAL(pubkey_s), GQUIC_STR_SIZE(pubkey_s))) == NULL) {
            return GQUIC_EXCEPTION_ALLOCATION_FAILED;
        }
        break;

    default:
        return GQUIC_EXCEPTION_INVALID_SIG;
    }
    return GQUIC_SUCCESS;
}

int gquic_tls_sig_pubkey_from_x509(EVP_PKEY **const pubkey, const u_int8_t sig_type, X509 *const x509) {
    if (pubkey == NULL || x509 == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((*pubkey = X509_get_pubkey(x509)) == NULL) {
        return GQUIC_EXCEPTION_X509_CANNOT_GET_PUBKEY;
    }
    int x509_sig_type = X509_get_signature_type(x509);

    switch (sig_type) {
    case GQUIC_SIG_ECDSA:
        if (x509_sig_type == EVP_PKEY_EC) {
            return GQUIC_SUCCESS;
        }
    case GQUIC_SIG_PKCS1V15:
    case GQUIC_SIG_RSAPSS:
        if (x509_sig_type == EVP_PKEY_RSA) {
            return GQUIC_SUCCESS;
        }
        break;
    case GQUIC_SIG_ED25519:
        if (x509_sig_type == EVP_PKEY_ED25519) {
            return GQUIC_SUCCESS;
        }
        break;
    default:
        return GQUIC_EXCEPTION_INVALID_SIG;
    }

    return GQUIC_EXCEPTION_INVALID_SIG;
}

int gquic_tls_sig_schemes_from_cert(gquic_list_t *const sig_schemes, PKCS12 *const p12) {
    X509 *x509 = NULL;
    EVP_PKEY *_ = NULL;
    u_int16_t *sig_scheme = NULL;
    if (sig_schemes == NULL || p12 == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    int i;
    gquic_list_head_init(sig_schemes);
    if (PKCS12_parse(p12, NULL, &_, &x509, NULL) <= 0) {
        return GQUIC_EXCEPTION_P12_CANNOT_GET_X509;
    }
    static const u_int16_t pkcs1_sig_schemes[] = {
        GQUIC_SIGALG_PKCS1_SHA1,
        GQUIC_SIGALG_PKCS1_SHA256,
        GQUIC_SIGALG_PKCS1_SHA384,
        GQUIC_SIGALG_PKCS1_SHA512
    };

    switch (X509_get_signature_type(x509)) {
    case EVP_PKEY_RSA:
        for (i = 0; i < 4; i++) {
            if ((sig_scheme = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                return GQUIC_EXCEPTION_ALLOCATION_FAILED;
            }
            *sig_scheme = pkcs1_sig_schemes[i];
            gquic_list_insert_before(sig_schemes, sig_scheme);
        }
        break;
    case EVP_PKEY_ED25519:
        if ((sig_scheme = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
            return GQUIC_EXCEPTION_ALLOCATION_FAILED;
        }
        *sig_scheme = GQUIC_SIGALG_ED25519;
        gquic_list_insert_before(sig_schemes, sig_scheme);
        break;
    }

    return GQUIC_SUCCESS;
}
