#include "handshake/auto_update_aead.h"
#include "tls/key_schedule.h"
#include "util/big_endian.h"

static int gquic_auto_update_aead_next_traffic_sec(gquic_str_t *const,
                                                   const gquic_tls_cipher_suite_t *const,
                                                   const gquic_str_t *const);

int gquic_auto_update_aead_init(gquic_auto_update_aead_t *const aead) {
    if (aead == NULL) {
        return -1;
    }
    aead->suite = NULL;
    aead->times = 0;
    aead->last_ack_pn = -1;
    aead->update_interval = 0;

    aead->prev_recv_aead_expire.tv_sec = 0;
    aead->prev_recv_aead_expire.tv_usec = 0;
    gquic_tls_aead_init(&aead->prev_recv_aead);

    aead->cur_key_first_recv_pn = -1;
    aead->cur_key_first_sent_pn = -1;
    aead->cur_key_num_recv = 0;
    aead->cur_key_num_sent = 0;

    gquic_tls_aead_init(&aead->recv_aead);
    gquic_tls_aead_init(&aead->send_aead);

    gquic_tls_aead_init(&aead->next_recv_aead);
    gquic_tls_aead_init(&aead->next_send_aead);

    gquic_str_init(&aead->next_recv_traffic_sec);
    gquic_str_init(&aead->next_send_traffic_sec);

    gquic_header_protector_init(&aead->header_enc);
    gquic_header_protector_init(&aead->header_dec);

    aead->rtt = NULL;

    gquic_str_init(&aead->nonce_buf);

    return 0;
}

int gquic_auto_update_aead_roll(gquic_auto_update_aead_t *const aead, const struct timeval *const now) {
    int ret = 0;
    useconds_t pto = 0;
    gquic_str_t next_recv_traffic_sec = { 0, NULL };
    gquic_str_t next_send_traffic_sec = { 0, NULL };
    if (aead == NULL || now == NULL) {
        return -1;
    }

    aead->times++;
    aead->cur_key_first_recv_pn = -1;
    aead->cur_key_first_sent_pn = -1;
    aead->cur_key_num_recv = 0;
    aead->cur_key_num_sent = 0;

    gquic_tls_aead_dtor(&aead->prev_recv_aead);
    gquic_tls_aead_init(&aead->prev_recv_aead);
    gquic_tls_aead_copy(&aead->prev_recv_aead, &aead->recv_aead);
    pto = 3 * gquic_time_pto(aead->rtt, 1);
    aead->prev_recv_aead_expire.tv_sec = (now->tv_sec + pto / 1000000) + (now->tv_usec + pto % 1000000) / 1000000;
    aead->prev_recv_aead_expire.tv_usec = now->tv_usec + pto % 1000000;
    gquic_tls_aead_copy(&aead->recv_aead, &aead->next_recv_aead);
    gquic_tls_aead_dtor(&aead->send_aead);
    gquic_tls_aead_init(&aead->send_aead);
    gquic_tls_aead_copy(&aead->send_aead, &aead->next_send_aead);

    if (gquic_auto_update_aead_next_traffic_sec(&next_recv_traffic_sec, aead->suite, &aead->next_recv_traffic_sec) != 0) {
        ret = -2;
        goto failure;
    }
    if (gquic_auto_update_aead_next_traffic_sec(&next_send_traffic_sec, aead->suite, &aead->next_send_traffic_sec) != 0) {
        ret = -3;
        goto failure;
    }
    gquic_str_reset(&aead->next_recv_traffic_sec);
    gquic_str_reset(&aead->next_send_traffic_sec);
    gquic_str_copy(&aead->next_recv_traffic_sec, &next_recv_traffic_sec);
    gquic_str_copy(&aead->next_send_traffic_sec, &next_send_traffic_sec);
    
    if (gquic_tls_create_aead(&aead->next_recv_aead, aead->suite, &aead->next_recv_traffic_sec) != 0) {
        ret = -4;
        goto failure;
    }
    if (gquic_tls_create_aead(&aead->next_send_aead, aead->suite, &aead->next_send_traffic_sec) != 0) {
        ret = -5;
        goto failure;
    }

    gquic_str_reset(&next_recv_traffic_sec);
    gquic_str_reset(&next_send_traffic_sec);
    return 0;
failure:

    gquic_str_reset(&next_recv_traffic_sec);
    gquic_str_reset(&next_send_traffic_sec);
    return ret;
}

static int gquic_auto_update_aead_next_traffic_sec(gquic_str_t *const ret,
                                                   const gquic_tls_cipher_suite_t *const suite,
                                                   const gquic_str_t *const traffic_sec) {
    static const gquic_str_t label = { 7, "quic ku" };
    gquic_tls_mac_t hash;
    if (ret == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_tls_mac_init(&hash);
    if (suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL) != 0) {
        return -2;
    }
    if (gquic_tls_hkdf_expand_label(ret, &hash, traffic_sec, NULL, &label, EVP_MD_size(hash.md)) != 0) {
        return -3;
    }

    gquic_tls_mac_dtor(&hash);
    return 0;
}

int gquic_auto_update_aead_set_rkey(gquic_auto_update_aead_t *const aead,
                                    const gquic_tls_cipher_suite_t *const suite,
                                    const gquic_str_t *const traffic_sec) {
    gquic_str_t next_recv_traffic_sec = { 0, NULL };
    if (aead == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_header_protector_release(&aead->header_dec);
    gquic_header_protector_init(&aead->header_dec);

    gquic_tls_aead_dtor(&aead->recv_aead);
    gquic_tls_aead_init(&aead->recv_aead);
    if (gquic_tls_create_aead(&aead->recv_aead, suite, traffic_sec) != 0) {
        return -2;
    }
    if (gquic_header_protector_assign(&aead->header_dec, suite, traffic_sec, 0) != 0) {
        return -3;
    }
    if (aead->suite == NULL) {
        gquic_str_reset(&aead->nonce_buf);
        if (gquic_str_alloc(&aead->nonce_buf, 12) != 0) {
            return -4;
        }
        aead->suite = suite;
    }
    if (gquic_auto_update_aead_next_traffic_sec(&next_recv_traffic_sec, suite, traffic_sec) != 0) {
        return -5;
    }
    gquic_str_reset(&aead->next_recv_traffic_sec);
    gquic_str_copy(&aead->next_recv_traffic_sec, &next_recv_traffic_sec);
    gquic_tls_aead_dtor(&aead->next_recv_aead);
    gquic_tls_aead_init(&aead->next_recv_aead);
    if (gquic_tls_create_aead(&aead->next_recv_aead, suite, &aead->next_recv_traffic_sec) != 0) {
        return -6;
    }

    gquic_str_reset(&next_recv_traffic_sec);
    return 0;
}

int gquic_auto_update_aead_set_wkey(gquic_auto_update_aead_t *const aead,
                                    const gquic_tls_cipher_suite_t *const suite,
                                    const gquic_str_t *const traffic_sec) {
    gquic_str_t next_send_traffic_sec = { 0, NULL };
    if (aead == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    gquic_header_protector_release(&aead->header_enc);
    gquic_header_protector_init(&aead->header_enc);

    gquic_tls_aead_dtor(&aead->send_aead);
    gquic_tls_aead_init(&aead->send_aead);
    if (gquic_tls_create_aead(&aead->send_aead, suite, traffic_sec) != 0) {
        return -2;
    }
    if (gquic_header_protector_assign(&aead->header_enc, suite, traffic_sec, 0) != 0) {
        return -3;
    }
    if (aead->suite == NULL) {
        gquic_str_reset(&aead->nonce_buf);
        if (gquic_str_alloc(&aead->nonce_buf, 12) != 0) {
            return -4;
        }
        aead->suite = suite;
    }
    if (gquic_auto_update_aead_next_traffic_sec(&next_send_traffic_sec, suite, traffic_sec) != 0) {
        return -5;
    }
    gquic_str_reset(&aead->next_send_traffic_sec);
    gquic_str_copy(&aead->next_send_traffic_sec, &next_send_traffic_sec);
    gquic_tls_aead_dtor(&aead->next_send_aead);
    gquic_tls_aead_init(&aead->next_send_aead);
    if (gquic_tls_create_aead(&aead->next_send_aead, suite, &aead->next_send_traffic_sec) != 0) {
        return -6;
    }

    gquic_str_reset(&next_send_traffic_sec);
    return 0;
}

int gquic_auto_update_aead_open(gquic_str_t *const plain_text,
                                gquic_auto_update_aead_t *const aead,
                                const struct timeval *const recv_time,
                                const u_int64_t pn,
                                int kp,
                                const gquic_str_t *const tag,
                                const gquic_str_t *const cipher_text,
                                const gquic_str_t *const addata) {
    if (plain_text == NULL || aead == NULL || recv_time == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        return -1;
    }
    if (aead->prev_recv_aead.self != NULL
        && (recv_time->tv_sec > aead->prev_recv_aead_expire.tv_sec
            || (recv_time->tv_sec == aead->prev_recv_aead_expire.tv_sec
                && recv_time->tv_usec > aead->prev_recv_aead_expire.tv_usec))) {
        gquic_tls_aead_dtor(&aead->prev_recv_aead);
        gquic_tls_aead_init(&aead->prev_recv_aead);
        aead->prev_recv_aead_expire.tv_sec = 0;
        aead->prev_recv_aead_expire.tv_usec = 0;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(&aead->nonce_buf) - 8, &pn, 8);
    if (kp != (aead->times % 2 == 1)) {
        if (aead->cur_key_first_recv_pn == ((u_int64_t) -1) || pn < aead->cur_key_first_recv_pn) {
            if (aead->times == 0) {
                return -2;
            }
            if (aead->prev_recv_aead.self == NULL) {
                return -3;
            }
            if (GQUIC_TLS_AEAD_OPEN(plain_text, &aead->prev_recv_aead, &aead->nonce_buf, tag, cipher_text, addata) != 0) {
                return -4;
            }
            return 0;
        }
        if (GQUIC_TLS_AEAD_OPEN(plain_text, &aead->next_recv_aead, &aead->nonce_buf, tag, cipher_text, addata) != 0) {
            return -5;
        }
        if (aead->cur_key_first_sent_pn == ((u_int64_t) -1)) {
            return -6;
        }
        if (gquic_auto_update_aead_roll(aead, recv_time) != 0) {
            return -7;
        }
        aead->cur_key_first_recv_pn = pn;
        return 0;
    }
    if (GQUIC_TLS_AEAD_OPEN(plain_text, &aead->recv_aead, &aead->nonce_buf, tag, cipher_text, addata) != 0) {
        return -8;
    }
    aead->cur_key_num_recv++;
    if (aead->cur_key_first_recv_pn == ((u_int64_t) -1)) {
        aead->cur_key_first_recv_pn = pn;
    }

    return 0;
}

int gquic_auto_update_aead_seal(gquic_str_t *const tag,
                                gquic_str_t *const cipher_text,
                                gquic_auto_update_aead_t *const aead,
                                const u_int64_t pn,
                                const gquic_str_t *const plain_text,
                                const gquic_str_t *const addata) {
    if (cipher_text == NULL || tag == NULL || aead == NULL || plain_text == NULL || addata == NULL) {
        return -1;
    }
    if (aead->cur_key_first_sent_pn == ((u_int64_t) -1)) {
        aead->cur_key_first_sent_pn = pn;
    }
    aead->cur_key_num_sent++;
    gquic_big_endian_transfer(GQUIC_STR_VAL(&aead->nonce_buf) - 8, &pn, 8);
    if (GQUIC_TLS_AEAD_SEAL(tag, cipher_text, &aead->send_aead, &aead->nonce_buf, plain_text, addata) != 0) {
        return -2;
    }
    return 0;
}
