#include "unit_test.h"
#include "util/conn_id.h"
#include "exception.h"

GQUIC_UNIT_TEST(conn_id_gen) {
    gquic_str_t conn_id = { 0, NULL };
    gquic_conn_id_generate(&conn_id, 10);
    GQUIC_UNIT_TEST_EXPECT(GQUIC_STR_SIZE(&conn_id) == 10);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(conn_id_gen_limit_0) {
    gquic_str_t conn_id = { 0, NULL };
    GQUIC_UNIT_TEST_EXPECT(gquic_conn_id_generate(&conn_id, 0) == GQUIC_SUCCESS);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(conn_id_gen_limit_20) {
    gquic_str_t conn_id = { 0, NULL };
    GQUIC_UNIT_TEST_EXPECT(gquic_conn_id_generate(&conn_id, 20) == GQUIC_SUCCESS);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(conn_id_gen_limit_21) {
    gquic_str_t conn_id = { 0, NULL };
    GQUIC_UNIT_TEST_EXPECT(gquic_conn_id_generate(&conn_id, 21) == GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
