#include "handshake/auto_update_aead.h"
#include "tls/key_schedule.h"
#include "util/big_endian.h"
#include "exception.h"

static int gquic_auto_update_aead_next_traffic_sec(gquic_str_t *const,
                                                   const gquic_tls_cipher_suite_t *const,
                                                   const gquic_str_t *const);

int gquic_auto_update_aead_init(gquic_auto_update_aead_t *const aead) {
    if (aead == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    aead->suite = NULL;
    aead->times = 0;
    aead->last_ack_pn = -1;
    aead->update_interval = 0;

    aead->prev_recv_aead_expire = 0;
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

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_auto_update_aead_roll(gquic_auto_update_aead_t *const aead, const u_int64_t now) {
    int exception = GQUIC_SUCCESS;
    useconds_t pto = 0;
    gquic_str_t next_recv_traffic_sec = { 0, NULL };
    gquic_str_t next_send_traffic_sec = { 0, NULL };
    if (aead == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
    aead->prev_recv_aead_expire = now + pto;
    gquic_tls_aead_copy(&aead->recv_aead, &aead->next_recv_aead);
    gquic_tls_aead_dtor(&aead->send_aead);
    gquic_tls_aead_init(&aead->send_aead);
    gquic_tls_aead_copy(&aead->send_aead, &aead->next_send_aead);

    if (GQUIC_ASSERT_CAUSE(exception, gquic_auto_update_aead_next_traffic_sec(&next_recv_traffic_sec, aead->suite, &aead->next_recv_traffic_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_auto_update_aead_next_traffic_sec(&next_send_traffic_sec, aead->suite, &aead->next_send_traffic_sec))) {
        goto failure;
    }
    gquic_str_reset(&aead->next_recv_traffic_sec);
    gquic_str_reset(&aead->next_send_traffic_sec);
    gquic_str_copy(&aead->next_recv_traffic_sec, &next_recv_traffic_sec);
    gquic_str_copy(&aead->next_send_traffic_sec, &next_send_traffic_sec);
    
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_create_aead(&aead->next_recv_aead, aead->suite, &aead->next_recv_traffic_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_create_aead(&aead->next_send_aead, aead->suite, &aead->next_send_traffic_sec))) {
        goto failure;
    }

    gquic_str_reset(&next_recv_traffic_sec);
    gquic_str_reset(&next_send_traffic_sec);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:

    gquic_str_reset(&next_recv_traffic_sec);
    gquic_str_reset(&next_send_traffic_sec);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_auto_update_aead_next_traffic_sec(gquic_str_t *const ret,
                                                   const gquic_tls_cipher_suite_t *const suite,
                                                   const gquic_str_t *const traffic_sec) {
    static const gquic_str_t label = { 7, "quic ku" };
    gquic_tls_mac_t hash;
    if (ret == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_mac_init(&hash);
    GQUIC_ASSERT_FAST_RETURN(suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_hkdf_expand_label(ret, &hash, traffic_sec, NULL, &label, EVP_MD_size(hash.md)));
    gquic_tls_mac_dtor(&hash);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_auto_update_aead_set_rkey(gquic_auto_update_aead_t *const aead,
                                    const gquic_tls_cipher_suite_t *const suite,
                                    const gquic_str_t *const traffic_sec) {
    gquic_str_t next_recv_traffic_sec = { 0, NULL };
    if (aead == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_header_protector_dtor(&aead->header_dec);
    gquic_header_protector_init(&aead->header_dec);

    gquic_tls_aead_dtor(&aead->recv_aead);
    gquic_tls_aead_init(&aead->recv_aead);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_create_aead(&aead->recv_aead, suite, traffic_sec));
    GQUIC_ASSERT_FAST_RETURN(gquic_header_protector_ctor(&aead->header_dec, suite, traffic_sec, 0));
    if (aead->suite == NULL) {
        gquic_str_reset(&aead->nonce_buf);
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&aead->nonce_buf, 12));
        aead->suite = suite;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_auto_update_aead_next_traffic_sec(&next_recv_traffic_sec, suite, traffic_sec));
    gquic_str_reset(&aead->next_recv_traffic_sec);
    gquic_str_copy(&aead->next_recv_traffic_sec, &next_recv_traffic_sec);
    gquic_tls_aead_dtor(&aead->next_recv_aead);
    gquic_tls_aead_init(&aead->next_recv_aead);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_create_aead(&aead->next_recv_aead, suite, &aead->next_recv_traffic_sec));

    gquic_str_reset(&next_recv_traffic_sec);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_auto_update_aead_set_wkey(gquic_auto_update_aead_t *const aead,
                                    const gquic_tls_cipher_suite_t *const suite,
                                    const gquic_str_t *const traffic_sec) {
    gquic_str_t next_send_traffic_sec = { 0, NULL };
    if (aead == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_header_protector_dtor(&aead->header_enc);
    gquic_header_protector_init(&aead->header_enc);

    gquic_tls_aead_dtor(&aead->send_aead);
    gquic_tls_aead_init(&aead->send_aead);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_create_aead(&aead->send_aead, suite, traffic_sec));
    GQUIC_ASSERT_FAST_RETURN(gquic_header_protector_ctor(&aead->header_enc, suite, traffic_sec, 0));
    if (aead->suite == NULL) {
        gquic_str_reset(&aead->nonce_buf);
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&aead->nonce_buf, 12));
        aead->suite = suite;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_auto_update_aead_next_traffic_sec(&next_send_traffic_sec, suite, traffic_sec));
    gquic_str_reset(&aead->next_send_traffic_sec);
    gquic_str_copy(&aead->next_send_traffic_sec, &next_send_traffic_sec);
    gquic_tls_aead_dtor(&aead->next_send_aead);
    gquic_tls_aead_init(&aead->next_send_aead);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_create_aead(&aead->next_send_aead, suite, &aead->next_send_traffic_sec));

    gquic_str_reset(&next_send_traffic_sec);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_auto_update_aead_open(gquic_str_t *const plain_text,
                                gquic_auto_update_aead_t *const aead,
                                const u_int64_t recv_time,
                                const u_int64_t pn,
                                int kp,
                                const gquic_str_t *const tag,
                                const gquic_str_t *const cipher_text,
                                const gquic_str_t *const addata) {
    if (plain_text == NULL || aead == NULL || tag == NULL || cipher_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (aead->prev_recv_aead.self != NULL && recv_time > aead->prev_recv_aead_expire) {
        gquic_tls_aead_dtor(&aead->prev_recv_aead);
        gquic_tls_aead_init(&aead->prev_recv_aead);
        aead->prev_recv_aead_expire = 0;
    }
    if (GQUIC_STR_SIZE(&aead->nonce_buf) < 8) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(&aead->nonce_buf) - 8, &pn, 8);
    if (kp != (aead->times % 2 == 1)) {
        if (aead->cur_key_first_recv_pn == ((u_int64_t) -1) || pn < aead->cur_key_first_recv_pn) {
            if (aead->times == 0) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_TIMES_ERROR);
            }
            if (aead->prev_recv_aead.self == NULL) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_DROPPED);
            }
            if (GQUIC_ASSERT(GQUIC_TLS_AEAD_OPEN(plain_text, &aead->prev_recv_aead, &aead->nonce_buf, tag, cipher_text, addata))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DECRYPTION_FAILED);
            }

            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        if (GQUIC_ASSERT(GQUIC_TLS_AEAD_OPEN(plain_text, &aead->next_recv_aead, &aead->nonce_buf, tag, cipher_text, addata))) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DECRYPTION_FAILED);
        }
        if (aead->cur_key_first_sent_pn == ((u_int64_t) -1)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UPDATE_KEY_QUICKLY);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_auto_update_aead_roll(aead, recv_time));
        aead->cur_key_first_recv_pn = pn;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT(GQUIC_TLS_AEAD_OPEN(plain_text, &aead->recv_aead, &aead->nonce_buf, tag, cipher_text, addata))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DECRYPTION_FAILED);
    }
    aead->cur_key_num_recv++;
    if (aead->cur_key_first_recv_pn == ((u_int64_t) -1)) {
        aead->cur_key_first_recv_pn = pn;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_auto_update_aead_seal(gquic_str_t *const tag,
                                gquic_str_t *const cipher_text,
                                gquic_auto_update_aead_t *const aead,
                                const u_int64_t pn,
                                const gquic_str_t *const plain_text,
                                const gquic_str_t *const addata) {
    if (cipher_text == NULL || tag == NULL || aead == NULL || plain_text == NULL || addata == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (aead->cur_key_first_sent_pn == ((u_int64_t) -1)) {
        aead->cur_key_first_sent_pn = pn;
    }
    aead->cur_key_num_sent++;
    if (GQUIC_STR_SIZE(&aead->nonce_buf) < 8) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(&aead->nonce_buf) - 8, &pn, 8);
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_AEAD_SEAL(tag, cipher_text, &aead->send_aead, &aead->nonce_buf, plain_text, addata));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
