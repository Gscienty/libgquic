#include "session.h"
#include "frame/meta.h"
#include "coglobal.h"
#include "unit_test.h"
#include "util/malloc.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <openssl/pkcs12.h>

gquic_str_t token = { 5, "token" };
gquic_str_t odci = { 4, "odci" };
gquic_str_t cdci = { 4, "cdci" };
gquic_str_t dci = { 3, "dci" };
gquic_str_t sci = { 3, "sci" };

gquic_str_t server_sci = { 4, "ssci" };

gquic_config_t cfg;
gquic_tls_config_t ser_cfg;
gquic_transport_parameters_t server_params;
gquic_crypto_stream_t initial;
gquic_crypto_stream_t handshake;
gquic_crypto_stream_t onertt;
gquic_handshake_establish_t server_establish;
gquic_crypto_stream_manager_t server_crypto_stream_manager;
gquic_packet_unpacker_t server_unpacker;
gquic_packet_packer_t server_packer;
gquic_rtt_t server_rtt;
gquic_net_addr_t server_addr;
pthread_t thread;
gquic_session_t sess;
gquic_packet_handler_map_t handler_map;

int client_write_times = 0;

static int __server_run(void *const _) {
    (void) _;
    gquic_handshake_establish_run(&server_establish);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int init_write(void *const _, gquic_writer_str_t *const writer) {
    (void) _;
    /*printf("init write\n");*/
    gquic_crypto_stream_write(&initial, writer);

    gquic_packet_long_header_t *hdr = NULL;
    gquic_packet_long_header_alloc(&hdr);
    
    memcpy(hdr->dcid, GQUIC_STR_VAL(&sci), GQUIC_STR_SIZE(&sci));
    hdr->dcid_len = GQUIC_STR_SIZE(&sci);
    memcpy(hdr->scid, GQUIC_STR_VAL(&server_sci), GQUIC_STR_SIZE(&server_sci));
    hdr->scid_len = GQUIC_STR_SIZE(&server_sci);

    hdr->flag = 0xc0 | (0x03 & (2 - 1));
    ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->pn = 11;
    ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->len = 1252;
    ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->token_len = GQUIC_STR_SIZE(&token);
    ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->token = malloc(GQUIC_STR_SIZE(&token));
    memcpy(((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->token, GQUIC_STR_VAL(&token), GQUIC_STR_SIZE(&token));

    gquic_frame_crypto_t *frame = NULL;
    gquic_crypto_stream_pop_crypto_frame(&frame, &initial, 1252);

    ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->len =  2 + 16 + GQUIC_FRAME_SIZE(frame);

    gquic_packet_buffer_t *buffer;
    gquic_packet_buffer_get(&buffer);
    gquic_writer_str_t w = buffer->slice;

    gquic_packet_long_header_serialize(hdr, &w);
    size_t header_size = GQUIC_STR_VAL(&w) - GQUIC_STR_VAL(&buffer->slice);
    GQUIC_FRAME_SERIALIZE(frame, &w);

    const gquic_str_t plain_text = {
        GQUIC_STR_VAL(&w) - GQUIC_STR_VAL(&buffer->slice) - header_size,
        GQUIC_STR_VAL(&buffer->slice) + header_size
    };
    const gquic_str_t addata = { header_size, GQUIC_STR_VAL(&buffer->slice) };
    gquic_str_t tag = { 0, NULL };
    gquic_str_t cipher_text = { 0, NULL };

    int ret = gquic_common_long_header_sealer_seal(&tag, &cipher_text, &server_establish.initial_sealer, 11, &plain_text, &addata);

    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size, GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));
    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&tag), GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text));
    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t header = { 2, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 + 4 };
    u_int8_t first = GQUIC_STR_FIRST_BYTE(&buffer->slice);
    gquic_header_protector_t *hp;
    gquic_common_long_header_sealer_get_header_sealer(&hp, &server_establish.initial_sealer);
    GQUIC_HEADER_PROTECTOR_SET_KEY(hp, &sample);
    GQUIC_HEADER_PROTECTOR_ENCRYPT(&header, &first, hp);
    *(u_int8_t *) GQUIC_STR_VAL(&buffer->slice) = first;

    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t cnt = { GQUIC_STR_VAL(&buffer->writer) - GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_VAL(&buffer->slice) };
    printf("send shello\n");
    /*gquic_str_test_echo(&cnt);*/

    gquic_received_packet_t *rp = malloc(sizeof(gquic_received_packet_t));

    gquic_packet_buffer_get(&rp->buffer);
    memcpy(GQUIC_STR_VAL(&rp->buffer->slice), GQUIC_STR_VAL(&cnt), GQUIC_STR_SIZE(&cnt));
    rp->data = rp->buffer->slice;
    rp->data.size = GQUIC_STR_SIZE(&cnt);
    rp->recv_time = gquic_time_now();
    rp->remote_addr.type = AF_INET;

    ret = gquic_packet_handler_map_handle_packet(&handler_map, rp);
    return 0;
}

static void handshake_packet() {
    static int pn = 12;
    gquic_packet_long_header_t *hdr = NULL;
    gquic_packet_long_header_alloc(&hdr);
    
    memcpy(hdr->dcid, GQUIC_STR_VAL(&sci), GQUIC_STR_SIZE(&sci));
    hdr->dcid_len = GQUIC_STR_SIZE(&sci);
    memcpy(hdr->scid, GQUIC_STR_VAL(&server_sci), GQUIC_STR_SIZE(&server_sci));
    hdr->scid_len = GQUIC_STR_SIZE(&server_sci);

    hdr->flag = 0xc0 | 0x20 | (0x03 & (2 - 1));
    ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->pn = pn++;

    gquic_frame_crypto_t *frame = NULL;
    gquic_crypto_stream_pop_crypto_frame(&frame, &handshake, 1252);

    ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->len = 2 + 16 + GQUIC_FRAME_SIZE(frame);

    gquic_packet_buffer_t *buffer;
    gquic_packet_buffer_get(&buffer);
    gquic_writer_str_t w = buffer->slice;

    gquic_packet_long_header_serialize(hdr, &w);
    size_t header_size = GQUIC_STR_VAL(&w) - GQUIC_STR_VAL(&buffer->slice);
    GQUIC_FRAME_SERIALIZE(frame, &w);

    /*gquic_str_t tmp = { GQUIC_STR_VAL(&w) - GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_VAL(&buffer->slice) };*/
    /*gquic_str_test_echo(&tmp);*/

    const gquic_str_t plain_text = {
        GQUIC_STR_VAL(&w) - GQUIC_STR_VAL(&buffer->slice) - header_size,
        GQUIC_STR_VAL(&buffer->slice) + header_size
    };
    const gquic_str_t addata = { header_size, GQUIC_STR_VAL(&buffer->slice) };
    gquic_str_t tag = { 0, NULL };
    gquic_str_t cipher_text = { 0, NULL };

    int ret = gquic_common_long_header_sealer_seal(&tag, &cipher_text, &server_establish.handshake_sealer, 12, &plain_text, &addata);

    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size, GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));
    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&tag), GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text));
    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t header = { 2, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 + 4 };
    u_int8_t first = GQUIC_STR_FIRST_BYTE(&buffer->slice);
    gquic_header_protector_t *hp;
    gquic_common_long_header_sealer_get_header_sealer(&hp, &server_establish.handshake_sealer);
    GQUIC_HEADER_PROTECTOR_SET_KEY(hp, &sample);
    GQUIC_HEADER_PROTECTOR_ENCRYPT(&header, &first, hp);
    *(u_int8_t *) GQUIC_STR_VAL(&buffer->slice) = first;

    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t cnt = { GQUIC_STR_VAL(&buffer->writer) - GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_VAL(&buffer->slice) };
    printf("\nsend Ex Ca Ver Fn\n");
    /*gquic_str_test_echo(&cnt);*/

    gquic_received_packet_t *rp = malloc(sizeof(gquic_received_packet_t));

    gquic_packet_buffer_get(&rp->buffer);
    memcpy(GQUIC_STR_VAL(&rp->buffer->slice), GQUIC_STR_VAL(&cnt), GQUIC_STR_SIZE(&cnt));
    rp->data = rp->buffer->slice;
    rp->data.size = GQUIC_STR_SIZE(&cnt);
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    rp->recv_time = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
    rp->remote_addr.type = AF_INET;

    /*printf("send\n");*/
    ret = gquic_packet_handler_map_handle_packet(&handler_map, rp);
}

static int handshake_write(void *const _, gquic_writer_str_t *const writer) {
    static int times = 0;
    times++;
    (void) _;
    /*printf("handshake write\n");*/
    /*gquic_str_test_echo(writer);*/
    gquic_crypto_stream_write(&handshake, writer);
    if (times == 4) {
        handshake_packet();
    }
    return 0;
}

static int one_rtt_write(void *const _, gquic_writer_str_t *const writer) {
    (void) _;
    (void) writer;
    printf("one rtt write\n");
    /*gquic_str_test_echo(writer);*/
    return 0;
}

static int get_cert(PKCS12 **const cert_s, const gquic_tls_client_hello_msg_t *const hello) {
    (void) hello;
    FILE *f = fopen("test_certs/ed25519_p12.pem", "r");
    *cert_s = d2i_PKCS12_fp(f, NULL);
    fclose(f);
    return 0;
}


int server_process_client_hello_package(void *const raw) {
    int ret = 0;
    gquic_str_t conn_id = { 0, NULL };
    gquic_handshake_establish_init(&server_establish);
    gquic_transport_parameters_init(&server_params);
    gquic_rtt_init(&server_rtt);
    gquic_net_str_to_addr_v4(&server_addr, "127.0.0.1");
    gquic_packet_header_deserialize_conn_id(&conn_id, raw, 0);
    gquic_crypto_stream_init(&initial);
    gquic_crypto_stream_ctor(&initial);
    gquic_crypto_stream_init(&handshake);
    gquic_crypto_stream_ctor(&handshake);
    gquic_crypto_stream_init(&onertt);
    gquic_crypto_stream_ctor(&onertt);

    gquic_handshake_establish_ctor(&server_establish,
                                   &initial, init_write,
                                   &handshake, handshake_write,
                                   &onertt, one_rtt_write,
                                   NULL, NULL,
                                   &ser_cfg, &conn_id, &server_params, &server_rtt, &server_addr, 0);
    ser_cfg.get_ser_cert = get_cert;
    
    gquic_packet_unpacker_init(&server_unpacker);
    gquic_packet_unpacker_ctor(&server_unpacker, &server_establish);
    gquic_packet_packer_init(&server_packer);

    gquic_coglobal_execute(__server_run, &sess);

    u_int64_t packet_length = 0;
    gquic_packet_header_deserialize_packet_len(&packet_length, raw, 0);

    gquic_unpacked_packet_t packet;
    gquic_unpacked_packet_init(&packet);
    ret = gquic_packet_unpacker_unpack(&packet, &server_unpacker, raw, gquic_time_now());

    gquic_frame_parser_t parser;
    gquic_frame_parser_init(&parser);

    void *frame = NULL;
    gquic_reader_str_t reader = packet.data;
    ret = gquic_frame_parser_next(&frame, &parser, &reader, packet.enc_lv);

    ret = gquic_crypto_stream_handle_crypto_frame(&initial, frame);
    gquic_frame_release(frame);

    gquic_str_t recv_data = { 0, NULL };
    gquic_crypto_stream_get_data(&recv_data, &initial);

    gquic_str_t *tmp_data = NULL;
    GQUIC_MALLOC_STRUCT(&tmp_data, gquic_str_t);
    gquic_str_copy(tmp_data, &recv_data);
    gquic_handshake_establish_handle_msg(&server_establish, tmp_data, packet.enc_lv);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_is_client_wrapper(void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        return 0;
    }
    return sess->is_client;
}

static int gquic_session_destroy_wrapper(void *const sess, const int err) {
    return gquic_session_destroy(sess, 10 * err - 1);
}

static int gquic_session_close_wrapper(void *const sess) {
    return gquic_session_close(sess);
}

static int gquic_session_handle_packet_wrapper(void *const sess, gquic_received_packet_t *const rp) {
    return gquic_session_handle_packet(sess, rp);
}

static void server_process_client_fin(const gquic_str_t *const raw) {
    int ret;
    gquic_str_t conn_id = { 0, NULL };
    gquic_packet_header_deserialize_conn_id(&conn_id, raw, 0);
    u_int64_t packet_length = 0;
    gquic_packet_header_deserialize_packet_len(&packet_length, raw, 0);
    printf("client_fin\n");
    /*gquic_str_test_echo(raw);*/
    
    gquic_unpacked_packet_t packet;
    gquic_unpacked_packet_init(&packet);

    GQUIC_ASSERT(gquic_packet_unpacker_unpack(&packet, &server_unpacker, raw, gquic_time_now()));

    gquic_frame_parser_t parser;
    gquic_frame_parser_init(&parser);

    void *frame = NULL;
    gquic_reader_str_t reader = packet.data;
    /*gquic_str_test_echo(&reader);*/
    ret = gquic_frame_parser_next(&frame, &parser, &reader, packet.enc_lv);
    if (GQUIC_FRAME_META(frame).type == 0x02) {
        printf("ack??\n");
    }

    /*ret = gquic_crypto_stream_handle_crypto_frame(&handshake, frame);*/
    /*gquic_frame_release(frame);*/

    /*gquic_str_t recv_data = { 0, NULL };*/
    /*gquic_crypto_stream_get_data(&recv_data, &handshake);*/

    /*// TODO empty recv_data segmentation fault*/
    /*gquic_handshake_establish_handle_msg(&server_establish, &recv_data, packet.enc_lv);*/
}

int conn_write(void *const _, const gquic_str_t *const raw) {
    (void) _;
    (void) raw;
    gquic_str_t *tmp_raw = NULL;
    client_write_times++;

    printf("conn write time: %ld\n", gquic_time_now());

    switch (client_write_times) {
    case 1:
        GQUIC_MALLOC_STRUCT(&tmp_raw, gquic_str_t);
        gquic_str_copy(tmp_raw, raw);
        printf("recv chello\n");
        /*gquic_str_test_echo(tmp_raw);*/
        // Client Hello Package
        gquic_coglobal_execute(server_process_client_hello_package, tmp_raw);
        break;
    case 2:
        printf("recv ack\n");
        /*server_process_client_fin(raw);*/
        break;
    /*default:*/
        /*printf("write times %d\n", client_write_times);*/
    }

    return 0;
}

int gquic_client_sess_run_co(void *const sess) {
    GQUIC_ASSERT_FAST_RETURN(gquic_session_run(sess));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(session_client) {
    printf("START server_est\n");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bind(fd, (struct sockaddr *) &addr, sizeof(addr));

    int flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);

    int ret = 0;
    gquic_net_conn_t conn;
    gquic_net_conn_init(&conn);
    conn.write.self = conn_write;
    conn.write.cb = conn_write;

    gquic_config_init(&cfg);

    cfg.insecure_skiy_verify = 1;
    cfg.handshake_timeout = 2 * 1000 * 1000;

    gquic_packet_handler_map_init(&handler_map);
    gquic_str_t tmp_token = { 0, NULL };
    gquic_str_copy(&tmp_token, &token);
    gquic_packet_handler_map_ctor(&handler_map, fd, 10, &tmp_token);

    gquic_session_init(&sess);
    ret = gquic_session_ctor(&sess,
                             &conn,
                             &handler_map,
                             &odci,
                             &cdci,
                             &dci,
                             &sci,
                             &token,
                             &cfg,
                             10,
                             1);
    gquic_packet_handler_t *abs_sess = malloc(sizeof(gquic_packet_handler_t));
    abs_sess->is_client.cb = gquic_session_is_client_wrapper;
    abs_sess->is_client.self = &sess;
    abs_sess->destroy.cb = gquic_session_destroy_wrapper;
    abs_sess->destroy.self = &sess;
    abs_sess->closer.closer.cb = gquic_session_close_wrapper;
    abs_sess->closer.closer.self = &sess;
    abs_sess->handle_packet.cb = gquic_session_handle_packet_wrapper;
    abs_sess->handle_packet.self = &sess;

    gquic_str_t ignore = { 0, NULL };
    gquic_packet_handler_map_add(&ignore, &handler_map, &sci, abs_sess);

    gquic_coglobal_thread_init(0);

    gquic_coglobal_execute(gquic_client_sess_run_co, &sess);

    int i = 0;
    for (i = 0; i < 50; i++) {
        gquic_coglobal_schedule();
    }

    return 0;
}
