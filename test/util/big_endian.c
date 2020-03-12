#include "unit_test.h"
#include "util/big_endian.h"
#include "exception.h"

GQUIC_UNIT_TEST(writer_1byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_1byte(&writer, 0x78);
    if (GQUIC_STR_VAL(&writer) - (void *) buf != 1) {
        return -1;
    }
    if (buf[0] != 0x78) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_1byte_lack) {
    gquic_writer_str_t writer = { 0, NULL };
    if (gquic_big_endian_writer_1byte(&writer, 0x78) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_2byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_2byte(&writer, 0x7856);
    if (GQUIC_STR_VAL(&writer) - (void *) buf != 2) {
        return -1;
    }
    if (buf[0] != 0x78 || buf[1] != 0x56) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_2byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 1, buf };
    if (gquic_big_endian_writer_2byte(&writer, 0x7856) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_3byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_3byte(&writer, 0x785631);
    if (GQUIC_STR_VAL(&writer) - (void *) buf != 3) {
        return -1;
    }
    if (buf[0] != 0x78
        || buf[1] != 0x56
        || buf[2] != 0x31) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_3byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 2, buf };
    if (gquic_big_endian_writer_3byte(&writer, 0x785631) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_4byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_4byte(&writer, 0x785631ca);
    if (GQUIC_STR_VAL(&writer) - (void *) buf != 4) {
        return -1;
    }
    if (buf[0] != 0x78
        || buf[1] != 0x56
        || buf[2] != 0x31
        || buf[3] != 0xca) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_4byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 3, buf };
    if (gquic_big_endian_writer_4byte(&writer, 0x785631ca) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_8byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_8byte(&writer, 0x785631ca235694db);
    if (GQUIC_STR_VAL(&writer) - (void *) buf != 8) {
        return -1;
    }
    if (buf[0] != 0x78
        || buf[1] != 0x56
        || buf[2] != 0x31
        || buf[3] != 0xca
        || buf[4] != 0x23
        || buf[5] != 0x56
        || buf[6] != 0x94
        || buf[7] != 0xdb) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(writer_8byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 7, buf };
    if (gquic_big_endian_writer_8byte(&writer, 0x785631ca235694db) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_1byte) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 8, buf };
    u_int8_t ret = 0;
    gquic_big_endian_reader_1byte(&ret, &reader);
    if (ret != 0x78) {
        return -1;
    }
    if (GQUIC_STR_VAL(&reader) - (void *) buf != 1) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_1byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 0, buf };
    u_int8_t ret = 0;
    if (gquic_big_endian_reader_1byte(&ret, &reader) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_2byte) {
    u_int8_t buf[8] = { 0x78, 0x56 };
    gquic_reader_str_t reader = { 8, buf };
    u_int16_t ret = 0;
    gquic_big_endian_reader_2byte(&ret, &reader);
    if (ret != 0x7856) {
        return -1;
    }
    if (GQUIC_STR_VAL(&reader) - (void *) buf != 2) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_2byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int16_t ret = 0;
    if (gquic_big_endian_reader_2byte(&ret, &reader) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_3byte) {
    u_int8_t buf[8] = { 0x78, 0x56, 0x23 };
    gquic_reader_str_t reader = { 8, buf };
    u_int32_t ret = 0;
    gquic_big_endian_reader_3byte(&ret, &reader);
    if (ret != 0x785623) {
        return -1;
    }
    if (GQUIC_STR_VAL(&reader) - (void *) buf != 3) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_3byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int32_t ret = 0;
    if (gquic_big_endian_reader_3byte(&ret, &reader) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_4byte) {
    u_int8_t buf[8] = { 0x78, 0x56, 0x23, 0x4a };
    gquic_reader_str_t reader = { 8, buf };
    u_int32_t ret = 0;
    gquic_big_endian_reader_4byte(&ret, &reader);
    if (ret != 0x7856234a) {
        return -1;
    }
    if (GQUIC_STR_VAL(&reader) - (void *) buf != 4) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_4byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int32_t ret = 0;
    if (gquic_big_endian_reader_4byte(&ret, &reader) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_8byte) {
    u_int8_t buf[8] = { 0x78, 0x56, 0x23, 0x4a, 0x56, 0x27, 0xac, 0xef };
    gquic_reader_str_t reader = { 8, buf };
    u_int64_t ret = 0;
    gquic_big_endian_reader_8byte(&ret, &reader);
    if (ret != 0x7856234a5627acef) {
        return -1;
    }
    if (GQUIC_STR_VAL(&reader) - (void *) buf != 8) {
        return -2;
    }
    return 0;
}

GQUIC_UNIT_TEST(reader_8byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int64_t ret = 0;
    if (gquic_big_endian_reader_8byte(&ret, &reader) != GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY) {
        return -1;
    }
    return 0;
}
