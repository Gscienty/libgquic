#ifndef _LIBGQUIC_EXCEPTION_H
#define _LIBGQUIC_EXCEPTION_H

#define GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY   -10000001
#define GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED    -10000002
#define GQUIC_EXCEPTION_ALLOCATION_FAILED       -10000003
#define GQUIC_EXCEPTION_INITIAL_FAILED          -10000004
#define GQUIC_EXCEPTION_CREATE_THREAD_FAILED    -10000005
#define GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED  -10000006
#define GQUIC_EXCEPTION_HMAC_FAILED             -10000007
#define GQUIC_EXCEPTION_NOT_FOUND               -10000008
#define GQUIC_EXCEPTION_RBTREE_CONFLICT         -10000009
#define GQUIC_EXCEPTION_INVALID_TARGET          -10000010
#define GQUIC_EXCEPTION_CLOSED                  -10000011
#define GQUIC_EXCEPTION_TIMEOUT                 -10000012
#define GQUIC_EXCEPTION_EMPTY                   -10000013
#define GQUIC_EXCEPTION_ATTEMPT_FAILED          -10000014
#define GQUIC_EXCEPTION_VARINT_TYPE_UNEXCEPTED  -10000015
#define GQUIC_EXCEPTION_VARINT_SIZE_UNEXCEPTED  -10000016
#define GQUIC_EXCEPTION_FLOW_CTRL_DISALLOW_RECV -10000017
#define GQUIC_EXCEPTION_RECV_INCONSISTENT_FINAL -10000018
#define GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED   -10000019
#define GQUIC_EXCEPTION_DATA_EMPTY              -10000020
#define GQUIC_EXCEPTION_DATA_DUPLICATE          -10000021
#define GQUIC_EXCEPTION_INTERNAL_ERROR          -10000022
#define GQUIC_EXCEPTION_TOO_MANY_GAPS           -10000023
#define GQUIC_EXCEPTION_ENC_LV_FRAME_CONFLICT   -10000024
#define GQUIC_EXCEPTION_INVALID_ENC_LV          -10000025
#define GQUIC_EXCEPTION_INVALID_FRAME           -10000026
#define GQUIC_EXCEPTION_SEALER_UNAVAILABLE      -10000027
#define GQUIC_EXCEPTION_OPENER_UNAVAILABLE      -10000028
#define GQUIC_EXCEPTION_KEY_TIMES_ERROR         -10000029
#define GQUIC_EXCEPTION_KEY_DROPPED             -10000030
#define GQUIC_EXCEPTION_DECRYPTION_FAILED       -10000031
#define GQUIC_EXCEPTION_UPDATE_KEY_QUICKLY      -10000032
#define GQUIC_EXCEPTION_HANDSHAKE_TYPE_UNEXCEPTED               -10000033
#define GQUIC_EXCEPTION_ENC_LV_INCONSISTENT                     -10000034
#define GQUIC_EXCEPTION_ESTABLISH_RECV_EVENT_UNEXCEPTED         -10000035
#define GQUIC_EXCEPTION_KEY_UNAVAILABLE                         -10000036
#define GQUIC_EXCEPTION_UNSUPPORT_CIPHER_SUITE                  -10000037
#define GQUIC_EXCEPTION_SET_ENCRYPT_KEY_ERROR                   -10000038
#define GQUIC_EXCEPTION_SIMPLE_MASK_INCONSISTENT                -10000039
#define GQUIC_EXCEPTION_HEADER_NOT_EXIST                        -10000040
#define GQUIC_EXCEPTION_INVALID_RESERVED_BITS                   -10000041
#define GQUIC_EXCEPTION_GREATE_THAN_HIGHEST_SEQ                 -10000042
#define GQUIC_EXCEPTION_RECV_CONN_ID_CONFLICT                   -10000043
#define GQUIC_EXCEPTION_RECV_STATELESS_TOKEN_CONFLICT           -10000044
#define GQUIC_EXCEPTION_CONN_ID_LIMIT_ERROR                     -10000045
#define GQUIC_EXCEPTION_FIRST_CONN_ID_SEQ_NUMBER_UNEXCEPTED     -10000046
#define GQUIC_EXCEPTION_CONN_CANNOT_USE_DIFF_STATELESS_TOKEN    -10000047
#define GQUIC_EXCEPTION_CONN_UNKNOW                             -10000048
#define GQUIC_EXCEPTION_RECV_HANDLER_DROPPED                    -10000049
#define GQUIC_EXCEPTION_SEND_QUEUE_INVALID_EVENT                -10000050
#define GQUIC_EXCEPTION_RECV_UNSENT_PACKET_ACK                  -10000051
#define GQUIC_EXCEPTION_RECV_SKIPPED_PACKET_ACK                 -10000052
#define GQUIC_EXCEPTION_INVALID_INITIIAL_SENT_HANDLER           -10000053
#define GQUIC_EXCEPTION_CRYPTO_BUFFER_EXCEEDED                  -10000054
#define GQUIC_EXCEPTION_CRYPTO_RECV_DATA_AFTER_CHANGE_ENC_LV    -10000055
#define GQUIC_EXCEPTION_CRYPTO_HAS_MORE_DATA_TO_READ            -10000056
#define GQUIC_EXCEPTION_GREATE_THAN_MAX_STREAM                  -10000057
#define GQUIC_EXCEPTION_DELETE_INCOMING_STREAM_MULTIPLE_TIMES   -10000058
#define GQUIC_EXCEPTION_TOO_MANY_OPEN_STREAMS                   -10000059
#define GQUIC_EXCEPTION_GREATE_THAN_NEXT_STREAM                 -10000060
#define GQUIC_EXCEPTION_EOF                                     -10000061
#define GQUIC_EXCEPTION_DEADLINE                                -10000062
#define GQUIC_EXCEPTION_PEER_ATTEMPTED_OPEN_STREAM              -10000063
#define GQUIC_EXCEPTION_STREAM_LIMIT_ERROR                      -10000064
#define GQUIC_SUCCESS 0

#define GQUIC_ASSERT_CAUSE(exception, expression) (((exception) = (expression)) != GQUIC_SUCCESS)
#define GQUIC_ASSERT(expression) ((expression) != GQUIC_SUCCESS)

#define GQUIC_ASSERT_FAST_RETURN(expression) \
{ \
    int __$exception = GQUIC_SUCCESS; \
    if (GQUIC_ASSERT_CAUSE(__$exception, expression)) { \
        return __$exception; \
    } \
}

#endif
