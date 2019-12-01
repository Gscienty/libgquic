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

int gquic_tls_cert_reset(gquic_tls_cert_t *const msg) {
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

ssize_t gquic_tls_cert_serialize(const gquic_tls_cert_t *const msg, void *const buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    gquic_str_t *cert;
    gquic_str_t *sct;
    int leaf_flag = 1;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    GQUIC_LIST_FOREACH(cert, &msg->certs) {
        __gquic_fill_str_full(buf, &off, cert, 3);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        if (leaf_flag == 1) {
            if (msg->ocsp_staple.size > 0) {
                __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
                __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
                __gquic_fill_1byte(buf, &off, GQUIC_TLS_CERT_STATUS_TYPE_OCSP);
                __gquic_fill_str_full(buf, &off, &msg->ocsp_staple, 3);
                __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
            }
            if (!gquic_list_head_empty(&msg->scts)) {
                __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SCT);
                __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
                __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
                GQUIC_LIST_FOREACH(sct, &msg->scts) {
                    __gquic_fill_str_full(buf, &off, sct, 2);
                }
                __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
                __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
            }
            leaf_flag = 0;
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

ssize_t gquic_tls_cert_deserialize(gquic_tls_cert_t *const msg, const void *const buf, const size_t size) {
    size_t off = 0;
    size_t prefix_len = 0;
    size_t ext_prefix_len = 0;
    size_t sct_prefix_len = 0;
    size_t start_position = 0;
    size_t ext_start_position = 0;
    size_t sct_start_position = 0;
    u_int16_t opt_type = 0;
    int leaf_flag = 1;
    gquic_str_t *field;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (__gquic_recovery_bytes(&prefix_len, 3, buf, size, &off) != 0) {
        return -2;
    }
    start_position = off;
    while (off - start_position < prefix_len) {
        if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
            return -2;
        }
        if (__gquic_recovery_str_full(field, 3, buf, size, &off) != 0) {
            return -3;
        }
        if (gquic_list_insert_before(&msg->certs, field) != 0) {
            return -3;
        }
        if (leaf_flag == 1) {
            leaf_flag = 0;
            if (__gquic_recovery_bytes(&ext_prefix_len, 2, buf, size, &off) != 0) {
                return -3;
            }
            ext_start_position = off;
            while (off - ext_start_position < ext_prefix_len) {
                if (__gquic_recovery_bytes(&opt_type, 2, buf, size, &off) != 0) {
                    return -3;
                }
                switch (opt_type) {

                case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
                    off += 2 + 1;
                    if (__gquic_recovery_str_full(&msg->ocsp_staple, 3, buf, size, &off) != 0) {
                        return -3;
                    }
                    break;

                case GQUIC_TLS_EXTENSION_SCT:
                    off += 2;
                    if (__gquic_recovery_bytes(&sct_prefix_len, 2, buf, size, &off) != 0) {
                        return -3;
                    }
                    sct_start_position = off;
                    while (off - sct_start_position < sct_prefix_len) {
                        if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                            return -3;
                        }
                        if (__gquic_recovery_str_full(field, 2, buf, size, &off) != 0) {
                            return -3;
                        }
                        if (gquic_list_insert_before(&msg->scts, field) != 0) {
                            return -3;
                        }
                    }
                    break;
                }
            }
        }
        else {
            off += 2;
        }
    }
    return off;
}
