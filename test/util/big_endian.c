#include "unit_test.h"
#include "util/big_endian.h"
#include "exception.h"

GQUIC_UNIT_TEST(writer_1byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_1byte(&writer, 0x78);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 1);
    GQUIC_UNIT_TEST_EXPECT(buf[0] == 0x78);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_1byte_lack) {
    gquic_writer_str_t writer = { 0, NULL };
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_writer_1byte(&writer, 0x78) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_2byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_2byte(&writer, 0x7856);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 2);
    GQUIC_UNIT_TEST_EXPECT(buf[0] == 0x78 && buf[1] == 0x56);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_2byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 1, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_writer_2byte(&writer, 0x7856) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_3byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_3byte(&writer, 0x785631);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 3);
    GQUIC_UNIT_TEST_EXPECT(buf[0] == 0x78 && buf[1] == 0x56 && buf[2] == 0x31);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_3byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 2, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_writer_3byte(&writer, 0x785631) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_4byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_4byte(&writer, 0x785631ca);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 4);
    GQUIC_UNIT_TEST_EXPECT(buf[0] == 0x78 && buf[1] == 0x56 && buf[2] == 0x31 && buf[3] == 0xca);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_4byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 3, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_writer_4byte(&writer, 0x785631ca) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_8byte) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 8, buf };
    gquic_big_endian_writer_8byte(&writer, 0x785631ca235694db);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&writer) - (void *) buf == 8);
    GQUIC_UNIT_TEST_EXPECT(buf[0] == 0x78
                           && buf[1] == 0x56
                           && buf[2] == 0x31
                           && buf[3] == 0xca
                           && buf[4] == 0x23
                           && buf[5] == 0x56
                           && buf[6] == 0x94
                           && buf[7] == 0xdb);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(writer_8byte_lack) {
    u_int8_t buf[8] = { 0 };
    gquic_writer_str_t writer = { 7, buf };
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_writer_8byte(&writer, 0x785631ca235694db) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_1byte) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 8, buf };
    u_int8_t ret = 0;
    gquic_big_endian_reader_1byte(&ret, &reader);
    GQUIC_UNIT_TEST_EXPECT(ret == 0x78);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&reader) - (void *) buf == 1);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_1byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 0, buf };
    u_int8_t ret = 0;
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_reader_1byte(&ret, &reader) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_2byte) {
    u_int8_t buf[8] = { 0x78, 0x56 };
    gquic_reader_str_t reader = { 8, buf };
    u_int16_t ret = 0;
    gquic_big_endian_reader_2byte(&ret, &reader);
    GQUIC_UNIT_TEST_EXPECT(ret == 0x7856);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&reader) - (void *) buf == 2);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_2byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int16_t ret = 0;
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_reader_2byte(&ret, &reader) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_3byte) {
    u_int8_t buf[8] = { 0x78, 0x56, 0x23 };
    gquic_reader_str_t reader = { 8, buf };
    u_int32_t ret = 0;
    gquic_big_endian_reader_3byte(&ret, &reader);
    GQUIC_UNIT_TEST_EXPECT(ret == 0x785623);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&reader) - (void *) buf == 3);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_3byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int32_t ret = 0;
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_reader_3byte(&ret, &reader) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_4byte) {
    u_int8_t buf[8] = { 0x78, 0x56, 0x23, 0x4a };
    gquic_reader_str_t reader = { 8, buf };
    u_int32_t ret = 0;
    gquic_big_endian_reader_4byte(&ret, &reader);
    GQUIC_UNIT_TEST_EXPECT(ret == 0x7856234a);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&reader) - (void *) buf == 4);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_4byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int32_t ret = 0;
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_reader_4byte(&ret, &reader) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_8byte) {
    u_int8_t buf[8] = { 0x78, 0x56, 0x23, 0x4a, 0x56, 0x27, 0xac, 0xef };
    gquic_reader_str_t reader = { 8, buf };
    u_int64_t ret = 0;
    gquic_big_endian_reader_8byte(&ret, &reader);
    GQUIC_UNIT_TEST_EXPECT(ret == 0x7856234a5627acef);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_VAL(&reader) - (void *) buf == 8);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(reader_8byte_lack) {
    u_int8_t buf[8] = { 0x78 };
    gquic_reader_str_t reader = { 1, buf };
    u_int64_t ret = 0;
    GQUIC_UNIT_TEST_EXPECT(gquic_big_endian_reader_8byte(&ret, &reader) == GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
