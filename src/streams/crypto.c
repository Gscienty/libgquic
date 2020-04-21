#include "streams/crypto.h"
#include "tls/common.h"
#include "exception.h"
#include <malloc.h>

static int gquic_crypto_stream_calc_readed_bytes(u_int64_t *const, gquic_crypto_stream_t *const);
static int gquic_crypto_stream_calc_writed_bytes(u_int64_t *const, gquic_crypto_stream_t *const);

int gquic_crypto_stream_init(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_frame_sorter_init(&str->sorter);
    gquic_str_init(&str->in_reader);
    gquic_str_init(&str->in_buf);
    str->highest_off = 0;
    str->out_off = 0;
    str->finished = 0;
    gquic_str_init(&str->out_reader);
    gquic_str_init(&str->out_buf);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_ctor(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_frame_sorter_ctor(&str->sorter);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_handle_crypto_frame(gquic_crypto_stream_t *const str, gquic_frame_crypto_t *const frame) {
    u_int64_t highest_off = 0;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    highest_off = frame->off + frame->len;
    if (highest_off > 16 * (1 << 10)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CRYPTO_BUFFER_EXCEEDED);
    }
    if (str->finished) {
        if (highest_off > str->highest_off) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CRYPTO_RECV_DATA_AFTER_CHANGE_ENC_LV);
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (highest_off > str->highest_off) {
        str->highest_off = highest_off;
    }
    gquic_str_t data = { frame->len, frame->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_sorter_push(&str->sorter, &data, frame->off, NULL, NULL));
    for ( ;; ) {
        u_int64_t off_useless;
        u_int64_t readed_size = 0;
        int (*fptr_useless)(void *const);
        void *fptr_self_useless;
        gquic_str_t data = { 0, NULL };
        gquic_str_t concated = { 0, NULL };

        GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_calc_readed_bytes(&readed_size, str));
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_sorter_pop(&off_useless, &data, &fptr_useless, &fptr_self_useless, &str->sorter));

        if (GQUIC_STR_SIZE(&data) == 0) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_str_concat(&concated, &str->in_buf, &data));
        gquic_str_reset(&data);
        gquic_str_reset(&str->in_buf);

        str->in_buf = concated;
        str->in_reader = str->in_buf;
        GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(&str->in_reader, readed_size));
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_crypto_stream_calc_readed_bytes(u_int64_t *const ret, gquic_crypto_stream_t *const str) {
    gquic_str_t tmp = { 0, NULL };
    if (ret == NULL || str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *ret = GQUIC_STR_VAL(&str->in_reader) - GQUIC_STR_VAL(&str->in_buf);
    if (*ret > 2048) {
        *ret = 0;
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&tmp, GQUIC_STR_SIZE(&str->in_reader)));
        GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&tmp, &str->in_reader));
        gquic_str_reset(&str->in_buf);
        str->in_buf = tmp;
        str->in_reader = str->in_buf;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_crypto_stream_calc_writed_bytes(u_int64_t *const ret, gquic_crypto_stream_t *const str) {
    gquic_str_t tmp = { 0, NULL };
    if (ret == NULL || str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *ret = GQUIC_STR_VAL(&str->out_reader) - GQUIC_STR_VAL(&str->out_buf);
    if (*ret > 2048) {
        *ret = 0;
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&tmp, GQUIC_STR_SIZE(&str->out_reader)));
        GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&tmp, &str->out_reader));
        gquic_str_reset(&str->out_buf);
        str->out_buf = tmp;
        str->out_reader = str->out_buf;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_get_data(gquic_str_t *const data, gquic_crypto_stream_t *const str) {
    u_int64_t slice_len = 0;
    if (data == NULL || str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&str->in_reader) < 4) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    slice_len = 4
        + (((u_int64_t) ((u_int8_t *) GQUIC_STR_VAL(&str->in_reader))[1]) << 16)
        + (((u_int64_t) ((u_int8_t *) GQUIC_STR_VAL(&str->in_reader))[2]) << 8)
        + (((u_int64_t) ((u_int8_t *) GQUIC_STR_VAL(&str->in_reader))[3]));
    if (GQUIC_STR_SIZE(&str->in_reader) < slice_len) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(data, slice_len));
    gquic_reader_str_read(data, &str->in_reader);
    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_calc_readed_bytes(&slice_len, str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_finish(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!gquic_rbtree_is_nil(str->sorter.root)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CRYPTO_HAS_MORE_DATA_TO_READ);
    }
    str->finished = 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_write(gquic_crypto_stream_t *const str, gquic_writer_str_t *const writer) {
    u_int64_t out_readed_size = 0;
    gquic_str_t concated = { 0, NULL };
    if (str == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_calc_writed_bytes(&out_readed_size, str));
    GQUIC_ASSERT_FAST_RETURN(gquic_str_concat(&concated, &str->out_buf, writer));
    str->out_buf = concated;
    str->out_reader = str->out_buf;
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(&str->out_reader, out_readed_size));
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_writed_size(writer, GQUIC_STR_SIZE(writer)));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_has_data(gquic_crypto_stream_t *const str) {
    if (str == NULL) {
        return 0;
    }

    return GQUIC_STR_SIZE(&str->out_reader) != 0;
}

int gquic_crypto_stream_pop_crypto_frame(gquic_frame_crypto_t **frame_storage, gquic_crypto_stream_t *const str, const u_int64_t max_len) {
    u_int64_t write_size = max_len;
    if (frame_storage == NULL || str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_crypto_alloc(frame_storage));
    (*frame_storage)->off = str->out_off;
    if (write_size > GQUIC_STR_SIZE(&str->out_reader)) {
        write_size = GQUIC_STR_SIZE(&str->out_reader);
    }
    if (((*frame_storage)->data = malloc(write_size)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    (*frame_storage)->len = write_size;
    gquic_str_t tmp = { write_size, (*frame_storage)->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&tmp, &str->out_reader));

    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_calc_writed_bytes(&write_size, str));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_post_handshake_crypto_stream_init(gquic_post_handshake_crypto_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_crypto_stream_init(&str->stream);
    str->framer = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_post_handshake_crypto_ctor(gquic_post_handshake_crypto_stream_t *const str, gquic_framer_t *const framer) {
    if (str == NULL || framer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_crypto_stream_ctor(&str->stream);
    str->framer = framer;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_post_handshake_crypto_write(gquic_post_handshake_crypto_stream_t *const str, gquic_writer_str_t *const writer) {
    gquic_frame_crypto_t *frame = NULL;
    if (str == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_write(&str->stream, writer));
    while (gquic_crypto_stream_has_data(&str->stream)) {
        gquic_crypto_stream_pop_crypto_frame(&frame, &str->stream, 1000);
        gquic_framer_queue_ctrl_frame(str->framer, frame);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_manager_init(gquic_crypto_stream_manager_t *const manager) {
    if (manager == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    manager->handle_msg.cb = NULL;
    manager->handle_msg.self = NULL;
    manager->handshake_stream = NULL;
    manager->initial_stream = NULL;
    manager->one_rtt_stream = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_manager_ctor(gquic_crypto_stream_manager_t *const manager,
                                     void *handle_msg_self,
                                     int (*handle_msg_cb) (void *const, const gquic_str_t *const, const u_int8_t),
                                     gquic_crypto_stream_t *const initial_stream,
                                     gquic_crypto_stream_t *const handshake_stream,
                                     gquic_post_handshake_crypto_stream_t *const one_rtt_stream) {
    if (manager == NULL || handle_msg_self == NULL || handle_msg_cb == NULL || initial_stream == NULL || handshake_stream == NULL || one_rtt_stream == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    manager->handle_msg.cb = handle_msg_cb;
    manager->handle_msg.self = handle_msg_self;
    manager->initial_stream = initial_stream;
    manager->handshake_stream = handshake_stream;
    manager->one_rtt_stream = one_rtt_stream;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_crypto_stream_manager_handle_crypto_frame(int *const changed,
                                                    gquic_crypto_stream_manager_t *const manager,
                                                    gquic_frame_crypto_t *const frame,
                                                    const u_int8_t enc_lv) {
    int ret = 0;
    gquic_crypto_stream_t *str = NULL;
    gquic_str_t data = { 0, NULL };
    if (changed == NULL || manager == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_handle_crypto_frame(str, frame));

    for ( ;; ) {
        gquic_str_init(&data);
        gquic_crypto_stream_get_data(&data, str);
        if (GQUIC_STR_SIZE(&data) == 0) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        if ((ret = GQUIC_CRYPTO_STREAM_MANAGER_HANDLE_MSG(manager, &data, enc_lv)) < 0) {
            return ret;
        }
        else if (ret) {
            *changed = 1;
            GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_finish(str));
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
