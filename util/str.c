#include "util/str.h"
#include <unistd.h>
#include <malloc.h>
#include <string.h>

int gquic_str_init(gquic_str_t *str) {
    if (str == NULL) {
        return -1;
    }
    str->size = 0;
    str->val = NULL;
    return 0;
}

int gquic_str_alloc(gquic_str_t *str, size_t size) {
    if (str == NULL) {
        return -1;
    }
    if (size > 0) {
        str->val = malloc(size);
        if (str->val == NULL) {
            return -1;
        }
        str->size = size;
    }
    return 0;
}

int gquic_str_reset(gquic_str_t *str) {
    if (str == NULL) {
        return -1;
    }

    if (str->val != NULL) {
        free(str->val);
    }
    gquic_str_init(str);
    return 0;
}

int gquic_str_copy(gquic_str_t *str, const gquic_str_t *ref) {
    if (str == NULL) {
        return -1;
    }
    gquic_str_init(str);
    if (GQUIC_STR_SIZE(ref) == 0) {
        return 0;
    }
    if (gquic_str_alloc(str, GQUIC_STR_SIZE(ref)) != 0) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(str), GQUIC_STR_VAL(ref), GQUIC_STR_SIZE(str));
    return 0;
}

int gquic_str_set(gquic_str_t *const str, const char *const val) {
    if (str == NULL || val == NULL) {
        return -1;
    }
    if (gquic_str_alloc(str, strlen(val)) != 0) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(str), val, GQUIC_STR_SIZE(str));
    return 0;
}

int gquic_str_test_echo(const gquic_str_t *const str) {
    if (str == NULL) {
        return -1;
    }
    u_int32_t off = 0;
    size_t i;
    printf("     ");
    for (i = 0; i < 16; i++) {
        printf("%02X ", (u_int8_t) i);
    }
    for (i = 0; i < GQUIC_STR_SIZE(str); i++) {
        if (i % 16 == 0) {
            printf("\n%04X ", off);
            off += 16;
        }
        printf("%02X ", ((unsigned char *) GQUIC_STR_VAL(str))[i]);
    }
    printf("\n");

    return 0;
}

int gquic_str_cmp(const gquic_str_t *const str_a, const gquic_str_t *const str_b) {
    if (str_a == NULL || str_b == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(str_a) != GQUIC_STR_SIZE(str_b)) {
        return GQUIC_STR_SIZE(str_a) - GQUIC_STR_SIZE(str_b);
    }
    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(str_a); i++) {
        int cmpret = (int16_t) ((u_int8_t *) GQUIC_STR_VAL(str_a))[i] - (int16_t) ((u_int8_t *) GQUIC_STR_VAL(str_b))[i];
        if (cmpret != 0) {
            return cmpret;
        }
    }

    return 0;
}

int gquic_str_concat(gquic_str_t *const ret, const gquic_str_t *const a, const gquic_str_t *const b) {
    if (ret == NULL || a == NULL || b == NULL) {
        return -1;
    }
    if (gquic_str_alloc(ret, GQUIC_STR_SIZE(a) + GQUIC_STR_SIZE(b)) != 0) {
        return -2;
    }
    gquic_writer_str_t writer = *ret;
    if (gquic_writer_str_write(&writer, a) != 0) {
        return -3;
    }
    if (gquic_writer_str_write(&writer, b) != 0) {
        return -4;
    }
    return 0;
}

int gquic_reader_str_readed_size(gquic_reader_str_t *const reader, const size_t n) {
    if (reader == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(reader) < n) {
        return -2;
    }
    reader->size -= n;
    reader->val += n;
    return 0;
}

u_int8_t gquic_reader_str_read_byte(gquic_reader_str_t *const reader) {
    u_int8_t ret = 0;
    if (reader == NULL) {
        return 0;
    }
    if (GQUIC_STR_SIZE(reader) < 1) {
        return 0;
    }
    ret = GQUIC_STR_FIRST_BYTE(reader);
    gquic_reader_str_readed_size(reader, 1);
    return ret;
}

int gquic_reader_str_read(gquic_str_t *const out, gquic_reader_str_t *const reader) {
    if (out == NULL || reader == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(out) > GQUIC_STR_SIZE(reader)) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(out), GQUIC_STR_VAL(reader), GQUIC_STR_SIZE(out));
    gquic_reader_str_readed_size(reader, GQUIC_STR_SIZE(out));
    return 0;
}

int gquic_writer_str_writed_size(gquic_writer_str_t *const writer, const size_t n) {
    if (writer == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(writer) < n) {
        return -2;
    }
    writer->size -= n;
    writer->val += n;
    return 0;
}

int gquic_writer_str_write(gquic_writer_str_t *const writer, const gquic_str_t *const buf) {
    if (writer == NULL || buf == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(writer) < GQUIC_STR_SIZE(buf)) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(writer), GQUIC_STR_VAL(buf), GQUIC_STR_SIZE(buf));
    gquic_writer_str_writed_size(writer, GQUIC_STR_SIZE(buf));
    return 0;
}

int gquic_writer_str_write_byte(gquic_writer_str_t *const writer, u_int8_t b) {
    if (writer == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(writer) < 1) {
        return -2;
    }
    gquic_str_t bbuf = { 1, &b };
    return gquic_writer_str_write(writer, &bbuf);
}

int gquic_writer_str_write_padding(gquic_writer_str_t *const writer, u_int8_t padding_cnt, const u_int64_t padding_len) {
    if (writer == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(writer) < padding_len) {
        return -2;
    }
    memset(GQUIC_STR_VAL(writer), padding_cnt, padding_len);
    gquic_writer_str_writed_size(writer, padding_len);
    return 0;
}
