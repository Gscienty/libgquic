#include "streams/crypto.h"
#include "tls/common.h"
#include <malloc.h>

static int gquic_crypto_stream_calc_readed_bytes(u_int64_t *const, gquic_crypto_stream_t *const);
static int gquic_crypto_stream_calc_writed_bytes(u_int64_t *const, gquic_crypto_stream_t *const);

int gquic_crypto_stream_init(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    gquic_frame_sorter_init(&str->queue);
    gquic_str_init(&str->reader);
    gquic_str_init(&str->msg_buf);
    str->highest_off = 0;
    str->write_off = 0;
    str->finished = 0;
    gquic_str_init(&str->writer);
    gquic_str_init(&str->write_buf);

    return 0;
}

int gquic_crypto_stream_ctor(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    gquic_frame_sorter_ctor(&str->queue);

    return 0;
}

int gquic_crypto_stream_handle_crypto_frame(gquic_crypto_stream_t *const str, gquic_frame_crypto_t *const frame) {
    u_int64_t highest_off = 0;
    if (str == NULL || frame == NULL) {
        return -1;
    }
    highest_off = frame->off + frame->len;
    if (highest_off > 16 * (1 << 10)) {
        return -2;
    }
    if (str->finished) {
        if (highest_off > str->highest_off) {
            return -3;
        }
        return 0;
    }
    if (highest_off > str->highest_off) {
        str->highest_off = highest_off;
    }
    gquic_str_t data = { frame->len, frame->data };
    if (gquic_frame_sorter_push(&str->queue, &data, frame->off, NULL, NULL) != 0) {
        return -4;
    }
    for ( ;; ) {
        u_int64_t off_useless;
        u_int64_t readed_size = 0;
        int (*fptr_useless)(void *const);
        void *fptr_self_useless;
        gquic_str_t data = { 0, NULL };
        gquic_str_t concated = { 0, NULL };

        if (gquic_crypto_stream_calc_readed_bytes(&readed_size, str) != 0) {
            return -5;
        }

        if (gquic_frame_sorter_pop(&off_useless, &data, &fptr_useless, &fptr_self_useless, &str->queue) != 0) {
            return -6;
        }
        if (GQUIC_STR_SIZE(&data) == 0) {
            return 0;
        }
        if (gquic_str_concat(&concated, &str->msg_buf, &data) != 0) {
            return -7;
        }
        gquic_str_reset(&data);
        gquic_str_reset(&str->msg_buf);

        str->msg_buf = concated;
        str->reader = str->msg_buf;
        if (gquic_reader_str_readed_size(&str->reader, readed_size) != 0) {
            return -8;
        }
    }
    
    return 0;
}

static int gquic_crypto_stream_calc_readed_bytes(u_int64_t *const ret, gquic_crypto_stream_t *const str) {
    gquic_str_t tmp = { 0, NULL };
    if (ret == NULL || str == NULL) {
        return -1;
    }
    *ret = GQUIC_STR_VAL(&str->reader) - GQUIC_STR_VAL(&str->msg_buf);
    if (*ret > 2048) {
        *ret = 0;
        if (gquic_str_alloc(&tmp, GQUIC_STR_SIZE(&str->reader)) != 0) {
            return -2;
        }
        if (gquic_reader_str_read(&tmp, &str->reader) != 0) {
            return -3;
        }
        gquic_str_reset(&str->msg_buf);
        str->msg_buf = tmp;
        str->reader = str->msg_buf;
    }
    return 0;
}

static int gquic_crypto_stream_calc_writed_bytes(u_int64_t *const ret, gquic_crypto_stream_t *const str) {
    gquic_str_t tmp = { 0, NULL };
    if (ret == NULL || str == NULL) {
        return -1;
    }
    *ret = GQUIC_STR_VAL(&str->writer) - GQUIC_STR_VAL(&str->write_buf);
    if (*ret > 2048) {
        *ret = 0;
        if (gquic_str_alloc(&tmp, GQUIC_STR_SIZE(&str->writer)) != 0) {
            return -2;
        }
        gquic_reader_str_t reader = str->writer;
        if (gquic_reader_str_read(&tmp, &reader) != 0) {
            return -3;
        }
        gquic_str_reset(&str->write_buf);
        str->write_buf = tmp;
        str->writer = str->write_buf;
    }
    return 0;
}

int gquic_crypto_stream_get_data(gquic_str_t *const data, gquic_crypto_stream_t *const str) {
    u_int64_t slice_len = 0;
    if (data == NULL || str == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&str->reader) < 4) {
        return 0;
    }
    slice_len = 4
        + (((u_int64_t) ((u_int8_t *) GQUIC_STR_VAL(&str->reader))[1]) << 16)
        + (((u_int64_t) ((u_int8_t *) GQUIC_STR_VAL(&str->reader))[2]) << 8)
        + (((u_int64_t) ((u_int8_t *) GQUIC_STR_VAL(&str->reader))[3]));
    if (GQUIC_STR_SIZE(&str->reader) < slice_len) {
        return 0;
    }
    if (gquic_str_alloc(data, slice_len) != 0) {
        return -2;
    }
    gquic_reader_str_read(data, &str->reader);
    if (gquic_crypto_stream_calc_readed_bytes(&slice_len, str) != 0) {
        return -3;
    }

    return 0;
}

int gquic_crypto_stream_finish(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    if (!gquic_rbtree_is_nil(str->queue.root)) {
        return -2;
    }
    str->finished = 1;

    return 0;
}

int gquic_crypto_stream_write(gquic_crypto_stream_t *const str, gquic_writer_str_t *const writer) {
    u_int64_t writed_size = 0;
    gquic_str_t concated = { 0, NULL };
    if (str == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_crypto_stream_calc_writed_bytes(&writed_size, str) != 0) {
        return -2;
    }
    if (gquic_str_concat(&concated, &str->write_buf, writer) != 0) {
        return -3;
    }
    str->write_buf = concated;
    str->writer = str->write_buf;
    if (gquic_writer_str_writed_size(&str->writer, writed_size) != 0) {
        return -4;
    }
    if (gquic_writer_str_writed_size(writer, GQUIC_STR_SIZE(writer)) != 0) {
        return -5;
    }
    return 0;
}

int gquic_crypto_stream_has_data(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        return 0;
    }
    return GQUIC_STR_SIZE(&str->writer) != 0;
}

int gquic_crypto_stream_pop_crypto_frame(gquic_frame_crypto_t **frame_storage, gquic_crypto_stream_t *const str, const u_int64_t max_len) {
    u_int64_t write_size = max_len;
    if (frame_storage == NULL || str == NULL) {
        return -1;
    }
    if ((*frame_storage = gquic_frame_crypto_alloc()) == NULL) {
        return -2;
    }
    (*frame_storage)->off = str->write_off;
    if (write_size > GQUIC_STR_SIZE(&str->writer)) {
        write_size = GQUIC_STR_SIZE(&str->writer);
    }
    if (((*frame_storage)->data = malloc(sizeof(write_size))) == NULL) {
        return -3;
    }
    (*frame_storage)->len = write_size;
    gquic_str_t tmp = { write_size, (*frame_storage)->data };
    if (gquic_writer_str_write(&str->writer, &tmp) != 0) {
        return -4;
    }
    return gquic_crypto_stream_calc_writed_bytes(&write_size, str);
}

int gquic_post_handshake_crypto_stream_init(gquic_post_handshake_crypto_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    gquic_crypto_stream_init(&str->stream);
    str->framer = NULL;
    return 0;
}

int gquic_post_handshake_crypto_ctor(gquic_post_handshake_crypto_stream_t *const str, gquic_framer_t *const framer) {
    if (str == NULL || framer == NULL) {
        return -1;
    }
    gquic_crypto_stream_ctor(&str->stream);
    str->framer = framer;
    return 0;
}

int gquic_post_handshake_crypto_write(gquic_post_handshake_crypto_stream_t *const str, gquic_writer_str_t *const writer) {
    gquic_frame_crypto_t *frame = NULL;
    if (str == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_crypto_stream_write(&str->stream, writer) != 0) {
        return -2;
    }
    while (gquic_crypto_stream_has_data(&str->stream)) {
        gquic_crypto_stream_pop_crypto_frame(&frame, &str->stream, 1000);
        gquic_framer_queue_ctrl_frame(str->framer, frame);
    }

    return 0;
}

int gquic_crypto_stream_manager_init(gquic_crypto_stream_manager_t *const manager) {
    if (manager == NULL) {
        return -1;
    }
    manager->handle_msg.cb = NULL;
    manager->handle_msg.self = NULL;
    manager->handshake_stream = NULL;
    manager->initial_stream = NULL;
    manager->one_rtt_stream = NULL;

    return 0;
}

int gquic_crypto_stream_manager_ctor(gquic_crypto_stream_manager_t *const manager,
                                     void *handle_msg_self,
                                     int (*handle_msg_cb) (void *const, const gquic_str_t *const, const u_int8_t),
                                     gquic_crypto_stream_t *const initial_stream,
                                     gquic_crypto_stream_t *const handshake_stream,
                                     gquic_post_handshake_crypto_stream_t *const one_rtt_stream) {
    if (manager == NULL || handle_msg_self == NULL || handle_msg_cb == NULL || initial_stream == NULL || handshake_stream == NULL || one_rtt_stream == NULL) {
        return -1;
    }
    manager->handle_msg.cb = handle_msg_cb;
    manager->handle_msg.self = handle_msg_self;
    manager->initial_stream = initial_stream;
    manager->handshake_stream = handshake_stream;
    manager->one_rtt_stream = one_rtt_stream;

    return 0;
}

int gquic_crypto_stream_manager_handle_crypto_frame(int *const changed,
                                                    gquic_crypto_stream_manager_t *const manager,
                                                    gquic_frame_crypto_t *const frame,
                                                    const u_int8_t enc_lv) {
    int ret = 0;
    gquic_crypto_stream_t *str = NULL;
    gquic_str_t data = { 0, NULL };
    if (changed == NULL || manager == NULL || frame == NULL) {
        return -1;
    }
    *changed = 0;
    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        str = manager->initial_stream;
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        str = manager->handshake_stream;
        break;
    case GQUIC_ENC_LV_1RTT:
        str = &manager->one_rtt_stream->stream;
        break;
    default:
        return -2;
    }
    if (gquic_crypto_stream_handle_crypto_frame(str, frame) != 0) {
        return -3;
    }

    for ( ;; ) {
        gquic_str_init(&data);
        gquic_crypto_stream_get_data(&data, str);
        if (GQUIC_STR_SIZE(&data) == 0) {
            return 0;
        }
        if ((ret = GQUIC_CRYPTO_STREAM_MANAGER_HANDLE_MSG(manager, &data, enc_lv)) < 0) {
            return -4;
        }
        else if (ret) {
            *changed = 1;
            return gquic_crypto_stream_finish(str);
        }
    }

    return 0;
}
