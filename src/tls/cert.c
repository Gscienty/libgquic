#include "tls/cert.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include <unistd.h>

int gquic_tls_cert_init(gquic_tls_cert_t *const msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_list_head_init(&msg->certs);
    gquic_str_init(&msg->ocsp_staple);
    gquic_list_head_init(&msg->scts);
    return 0;
}

int gquic_tls_cert_dtor(gquic_tls_cert_t *const msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->ocsp_staple);
    while (!gquic_list_head_empty(&msg->scts)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&msg->scts));
        gquic_list_release(GQUIC_LIST_FIRST(&msg->scts));
    }
    while (!gquic_list_head_empty(&msg->certs)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&msg->certs));
        gquic_list_release(GQUIC_LIST_FIRST(&msg->certs));
    }
    gquic_tls_cert_init(msg);
    return 0;
}

ssize_t gquic_tls_cert_size(const gquic_tls_cert_t *const msg) {
    size_t off = 0;
    gquic_str_t *cert;
    gquic_str_t *sct;
    int leaf_flag = 1;
    if (msg == NULL) {
        return -1;
    }
    off += 3;
    GQUIC_LIST_FOREACH(cert, &msg->certs) {
        off += 3 + cert->size + 2;
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
    gquic_str_t *cert;
    gquic_str_t *sct;
    int leaf_flag = 1;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    GQUIC_LIST_FOREACH(cert, &msg->certs) {
        __gquic_fill_str(writer, cert, 3);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        if (leaf_flag == 1) {
            if (msg->ocsp_staple.size > 0) {
                gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
                __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
                gquic_big_endian_writer_1byte(writer, GQUIC_TLS_CERT_STATUS_TYPE_OCSP);
                __gquic_fill_str(writer, &msg->ocsp_staple, 3);
                __gquic_fill_prefix_len(&prefix_len_stack, writer);
            }
            if (!gquic_list_head_empty(&msg->scts)) {
                gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SCT);
                __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
                __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
                GQUIC_LIST_FOREACH(sct, &msg->scts) {
                    __gquic_fill_str(writer, sct, 2);
                }
                __gquic_fill_prefix_len(&prefix_len_stack, writer);
                __gquic_fill_prefix_len(&prefix_len_stack, writer);
            }
            leaf_flag = 0;
        }
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    return 0;
}

int gquic_tls_cert_deserialize(gquic_tls_cert_t *const msg, gquic_reader_str_t *const reader) {
    int ret = 0;
    size_t payload_len = 0;
    size_t ext_prefix_len = 0;
    size_t sct_prefix_len = 0;
    void * start_position = NULL;
    void * ext_start_position = NULL;
    void * sct_start_position = NULL;
    u_int16_t opt_type = 0;
    int leaf_flag = 1;
    gquic_str_t *field;
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    if (__gquic_recovery_bytes(&payload_len, 3, reader) != 0) {
        return -2;
    }
    start_position = GQUIC_STR_VAL(reader);
    while ((size_t) (GQUIC_STR_VAL(reader) - start_position) < payload_len) {
        if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
            return -3;
        }
        gquic_str_init(field);
        if ((ret = __gquic_recovery_str(field, 3, reader)) != 0) {
            return -4;
        }
        if (gquic_list_insert_before(&msg->certs, field) != 0) {
            return -5;
        }
        if (leaf_flag == 1) {
            leaf_flag = 0;
            if (__gquic_recovery_bytes(&ext_prefix_len, 2, reader) != 0) {
                return -6;
            }
            ext_start_position = GQUIC_STR_VAL(reader);
            while ((size_t) (GQUIC_STR_VAL(reader) - ext_start_position) < ext_prefix_len) {
                if (__gquic_recovery_bytes(&opt_type, 2, reader) != 0) {
                    return -7;
                }
                switch (opt_type) {

                case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
                    gquic_reader_str_readed_size(reader, 2 + 1);
                    if (__gquic_recovery_str(&msg->ocsp_staple, 3, reader) != 0) {
                        return -8;
                    }
                    break;

                case GQUIC_TLS_EXTENSION_SCT:
                    gquic_reader_str_readed_size(reader, 2);
                    if (__gquic_recovery_bytes(&sct_prefix_len, 2, reader) != 0) {
                        return -9;
                    }
                    sct_start_position = GQUIC_STR_VAL(reader);
                    while ((size_t) (GQUIC_STR_VAL(reader) - sct_start_position) < sct_prefix_len) {
                        if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                            return -10;
                        }
                        if (__gquic_recovery_str(field, 2, reader) != 0) {
                            return -11;
                        }
                        if (gquic_list_insert_before(&msg->scts, field) != 0) {
                            return -12;
                        }
                    }
                    break;
                }
            }
        }
        else {
            if (gquic_reader_str_readed_size(reader, 2) != 0) {
                return -13;
            }
        }
    }
    return 0;
}
