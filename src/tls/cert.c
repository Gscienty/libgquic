#include "tls/cert.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "exception.h"
#include <openssl/x509.h>
#include <unistd.h>

int gquic_tls_cert_init(gquic_tls_cert_t *const msg) {
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&msg->certs);
    gquic_str_init(&msg->ocsp_staple);
    gquic_list_head_init(&msg->scts);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_cert_dtor(gquic_tls_cert_t *const msg) {
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&msg->ocsp_staple);
    while (!gquic_list_head_empty(&msg->scts)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&msg->scts));
        gquic_list_release(GQUIC_LIST_FIRST(&msg->scts));
    }
    while (!gquic_list_head_empty(&msg->certs)) {
        X509_free(*(X509 **) GQUIC_LIST_FIRST(&msg->certs));
        gquic_list_release(GQUIC_LIST_FIRST(&msg->certs));
    }
    gquic_tls_cert_init(msg);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

ssize_t gquic_tls_cert_size(const gquic_tls_cert_t *const msg) {
    size_t off = 0;
    X509 **cert_storage = NULL;
    gquic_str_t *sct;
    int leaf_flag = 1;
    if (msg == NULL) {
        return 0;
    }
    off += 3;
    GQUIC_LIST_FOREACH(cert_storage, &msg->certs) {
        off += 3 + i2d_X509(*cert_storage, NULL) + 2;
        if (leaf_flag == 0) {
            continue;
        }
        if (msg->ocsp_staple.size > 0) {
            off += 2 + 2 + 1 + 3 + msg->ocsp_staple.size;
        }
        if (!gquic_list_head_empty(&msg->scts)) {
            off += 2 + 2 + 2;
            GQUIC_LIST_FOREACH(sct, &msg->scts) {
                off += 2 + sct->size;
            }
        }
        leaf_flag = 0;
    }
    return off;
}

int gquic_tls_cert_serialize(const gquic_tls_cert_t *const msg, gquic_writer_str_t *const writer) {
    gquic_list_t prefix_len_stack;
    X509 **cert_storage = NULL;
    gquic_str_t *sct;
    int leaf_flag = 1;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_cert_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 3));
    GQUIC_LIST_FOREACH(cert_storage, &msg->certs) {
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_x509(writer, *cert_storage, 3));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        if (leaf_flag == 1) {
            if (msg->ocsp_staple.size > 0) {
                GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_STATUS_REQUEST));
                GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
                GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, GQUIC_TLS_CERT_STATUS_TYPE_OCSP));
                GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &msg->ocsp_staple, 3));
                GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
            }
            if (!gquic_list_head_empty(&msg->scts)) {
                GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SCT));
                GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
                GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
                GQUIC_LIST_FOREACH(sct, &msg->scts) {
                    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, sct, 2));
                }
                GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
                GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
            }
            leaf_flag = 0;
        }
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_cert_deserialize(gquic_tls_cert_t *const msg, gquic_reader_str_t *const reader) {
    size_t payload_len = 0;
    size_t ext_prefix_len = 0;
    size_t sct_prefix_len = 0;
    void * start_position = NULL;
    void * ext_start_position = NULL;
    void * sct_start_position = NULL;
    u_int16_t opt_type = 0;
    int leaf_flag = 1;
    gquic_str_t *field;
    X509 *x509 = NULL;
    X509 **x509_storage = NULL;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&payload_len, 3, reader));
    start_position = GQUIC_STR_VAL(reader);
    while ((size_t) (GQUIC_STR_VAL(reader) - start_position) < payload_len) {
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_x509(&x509, 3, reader));
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &x509_storage, sizeof(X509 *)));
        *x509_storage = x509;
        GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&msg->certs, x509_storage));
        
        if (leaf_flag == 1) {
            leaf_flag = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&ext_prefix_len, 2, reader));
            ext_start_position = GQUIC_STR_VAL(reader);
            while ((size_t) (GQUIC_STR_VAL(reader) - ext_start_position) < ext_prefix_len) {
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&opt_type, 2, reader));
                switch (opt_type) {
                case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
                    gquic_reader_str_readed_size(reader, 2 + 1);
                    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&msg->ocsp_staple, 3, reader));
                    break;

                case GQUIC_TLS_EXTENSION_SCT:
                    gquic_reader_str_readed_size(reader, 2);
                    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&sct_prefix_len, 2, reader));
                    sct_start_position = GQUIC_STR_VAL(reader);
                    while ((size_t) (GQUIC_STR_VAL(reader) - sct_start_position) < sct_prefix_len) {
                        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &field, sizeof(gquic_str_t)));
                        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(field, 2, reader));
                        GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&msg->scts, field));
                    }
                    break;
                }
            }
        }
        else {
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
        }
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
