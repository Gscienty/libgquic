#include "session.h"
#include "frame/meta.h"
#include "util/malloc.h"
#include "coglobal.h"
#include "unit_test.h"
#include <pthread.h>
#include <stdio.h>
#include <openssl/pkcs12.h>
#include <fcntl.h>

gquic_str_t token = { 5, "token" };
gquic_str_t odci = { 4, "odci" };
gquic_str_t cdci = { 4, "cdci" };
gquic_str_t dci = { 3, "dci" };
gquic_str_t sci = { 3, "sci" };

gquic_str_t client_sci = { 4, "ssci" };

gquic_config_t cfg;
gquic_tls_config_t cli_cfg;
gquic_session_t sess;
gquic_packet_handler_map_t handler_map;

gquic_net_addr_t client_addr;
gquic_transport_parameters_t client_params;
gquic_crypto_stream_t initial;
gquic_crypto_stream_t handshake;
gquic_crypto_stream_t onertt;
gquic_packet_unpacker_t unpacker;
gquic_packet_packer_t packer;
gquic_rtt_t client_rtt;
gquic_handshake_establish_t client_establish;
pthread_t thread;

int handle_shello(void *const raw) {
    u_int64_t now = gquic_time_now();
    gquic_unpacked_packet_t packet;
    gquic_packet_unpacker_init(&unpacker);
    gquic_packet_unpacker_ctor(&unpacker, &client_establish);
    int ret = gquic_packet_unpacker_unpack(&packet, &unpacker, raw, now);

    gquic_frame_parser_t parser;
    gquic_frame_parser_init(&parser);

    void *frame = NULL;
    gquic_reader_str_t reader = packet.data;
    ret = gquic_frame_parser_next(&frame, &parser, &reader, packet.enc_lv);
    gquic_frame_release(frame);
    ret = gquic_frame_parser_next(&frame, &parser, &reader, packet.enc_lv);

    ret = gquic_crypto_stream_handle_crypto_frame(&initial, frame);

    gquic_str_t *recv_data = NULL;
    GQUIC_MALLOC_STRUCT(&recv_data, gquic_str_t);
    gquic_str_init(recv_data);
    gquic_crypto_stream_get_data(recv_data, &initial);
    
    gquic_handshake_establish_handle_msg(&client_establish, recv_data, packet.enc_lv);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int handle_handshake(void *const raw) {
    while (client_establish.read_enc_level != GQUIC_ENC_LV_HANDSHAKE) {
        gquic_coglobal_yield();
    }

    u_int64_t now = gquic_time_now();
    gquic_unpacked_packet_t packet;
    gquic_packet_unpacker_init(&unpacker);
    gquic_packet_unpacker_ctor(&unpacker, &client_establish);
    int ret = gquic_packet_unpacker_unpack(&packet, &unpacker, raw, now);

    gquic_frame_parser_t parser;
    gquic_frame_parser_init(&parser);

    void *frame = NULL;
    gquic_reader_str_t reader = packet.data;
    while (GQUIC_STR_SIZE(&reader) != 0) {
        gquic_frame_parser_next(&frame, &parser, &reader, packet.enc_lv);
        if (frame == NULL) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        if (GQUIC_FRAME_META(frame).type == 0x06) {
            ret = gquic_crypto_stream_handle_crypto_frame(&handshake, frame);
        }
    }

    gquic_str_t *recv_data = NULL;
    GQUIC_MALLOC_STRUCT(&recv_data, gquic_str_t);
    gquic_str_init(recv_data);
    GQUIC_ASSERT(gquic_crypto_stream_get_data(recv_data, &handshake));
    gquic_str_test_echo(recv_data);
    gquic_handshake_establish_handle_msg(&client_establish, recv_data, packet.enc_lv);

    GQUIC_MALLOC_STRUCT(&recv_data, gquic_str_t);
    gquic_str_init(recv_data);
    GQUIC_ASSERT(gquic_crypto_stream_get_data(recv_data, &handshake));
    gquic_str_test_echo(recv_data);
    gquic_handshake_establish_handle_msg(&client_establish, recv_data, packet.enc_lv);

    GQUIC_MALLOC_STRUCT(&recv_data, gquic_str_t);
    gquic_str_init(recv_data);
    GQUIC_ASSERT(gquic_crypto_stream_get_data(recv_data, &handshake));
    gquic_str_test_echo(recv_data);
    gquic_handshake_establish_handle_msg(&client_establish, recv_data, packet.enc_lv);

    GQUIC_MALLOC_STRUCT(&recv_data, gquic_str_t);
    gquic_str_init(recv_data);
    GQUIC_ASSERT(gquic_crypto_stream_get_data(recv_data, &handshake));
    gquic_str_test_echo(recv_data);
    gquic_handshake_establish_handle_msg(&client_establish, recv_data, packet.enc_lv);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int conn_write(void *const _, const gquic_str_t *const raw) {
    gquic_str_t *tmp = NULL;
    (void) _;
    static int times = 0;
    times++;

    switch (times) {
    case 1: // shello
        GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
        gquic_str_init(tmp);
        gquic_str_copy(tmp, raw);

        gquic_coglobal_execute(handle_shello, tmp);
        break;
    default:
        if (!client_establish.handshake_done) {
            GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
            gquic_str_init(tmp);
            gquic_str_copy(tmp, raw);

            gquic_coglobal_execute(handle_handshake, tmp);
        }
    }
    return 0;
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

static int __client_run(void *const _) {
    (void) _;
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_run(&client_establish));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int init_write(void *const _, gquic_writer_str_t *const writer) {
    (void) _;
    printf("init write\n");
    gquic_crypto_stream_write(&initial, writer);

    gquic_packet_long_header_t *hdr;
    gquic_packet_long_header_alloc(&hdr);
    memcpy(hdr->dcid, GQUIC_STR_VAL(&sci), GQUIC_STR_SIZE(&sci));
    hdr->dcid_len = GQUIC_STR_SIZE(&sci);
    memcpy(hdr->scid, GQUIC_STR_VAL(&client_sci), GQUIC_STR_SIZE(&client_sci));
    hdr->scid_len = GQUIC_STR_SIZE(&client_sci);

    hdr->flag = 0xc0 | (0x03 & (2 - 1));
    ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->pn = 10;
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
    /*gquic_str_test_echo(&plain_text);*/
    const gquic_str_t addata = { header_size, GQUIC_STR_VAL(&buffer->slice) };
    gquic_str_t tag = { 0, NULL };
    gquic_str_t cipher_text = { 0, NULL };

    int ret = gquic_common_long_header_sealer_seal(&tag, &cipher_text, &client_establish.initial_sealer, 10, &plain_text, &addata);

    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size, GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));
    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&tag), GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text));
    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t header = { 2, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 + 4 };
    u_int8_t first = GQUIC_STR_FIRST_BYTE(&buffer->slice);
    gquic_header_protector_t *hp;
    gquic_common_long_header_sealer_get_header_sealer(&hp, &client_establish.initial_sealer);
    GQUIC_HEADER_PROTECTOR_SET_KEY(hp, &sample);
    GQUIC_HEADER_PROTECTOR_ENCRYPT(&header, &first, hp);
    *(u_int8_t *) GQUIC_STR_VAL(&buffer->slice) = first;

    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t cnt = { GQUIC_STR_VAL(&buffer->writer) - GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_VAL(&buffer->slice) };

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

    printf("send chello\n");
    ret = gquic_packet_handler_map_handle_packet(&handler_map, rp);
    return 0;
}

static int __handshake_write_thread(void *const _) {
    (void) _;
    gquic_packet_long_header_t *hdr;
    gquic_packet_long_header_alloc(&hdr);
    memcpy(hdr->dcid, GQUIC_STR_VAL(&sci), GQUIC_STR_SIZE(&sci));
    hdr->dcid_len = GQUIC_STR_SIZE(&sci);
    memcpy(hdr->scid, GQUIC_STR_VAL(&dci), GQUIC_STR_SIZE(&dci));
    hdr->scid_len = GQUIC_STR_SIZE(&dci);

    hdr->flag = 0xc0 | 0x20 | (0x03 & (2 - 1));
    ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->pn = 0;

    gquic_frame_crypto_t *frame = NULL;
    gquic_crypto_stream_pop_crypto_frame(&frame, &handshake, 1252);

    ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(hdr))->len =  2 + 16 + GQUIC_FRAME_SIZE(frame);

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

    int ret = gquic_common_long_header_sealer_seal(&tag, &cipher_text, &client_establish.handshake_sealer, 0, &plain_text, &addata);

    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size, GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));
    memcpy(GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&tag), GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text));
    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t header = { 2, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 };
    gquic_str_t sample = { 16, GQUIC_STR_VAL(&buffer->slice) + header_size - 2 + 4 };
    u_int8_t first = GQUIC_STR_FIRST_BYTE(&buffer->slice);
    gquic_header_protector_t *hp;
    gquic_common_long_header_sealer_get_header_sealer(&hp, &client_establish.handshake_sealer);
    GQUIC_HEADER_PROTECTOR_SET_KEY(hp, &sample);
    GQUIC_HEADER_PROTECTOR_ENCRYPT(&header, &first, hp);
    *(u_int8_t *) GQUIC_STR_VAL(&buffer->slice) = first;

    buffer->writer.size = GQUIC_STR_SIZE(&buffer->slice) - header_size - GQUIC_STR_SIZE(&cipher_text) - GQUIC_STR_SIZE(&tag);
    buffer->writer.val = GQUIC_STR_VAL(&buffer->slice) + header_size + GQUIC_STR_SIZE(&cipher_text) + GQUIC_STR_SIZE(&tag);

    gquic_str_t cnt = { GQUIC_STR_VAL(&buffer->writer) - GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_VAL(&buffer->slice) };

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

    printf("send cfin\n");
    ret = gquic_packet_handler_map_handle_packet(&handler_map, rp);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int handshake_write(void *const _, gquic_writer_str_t *const writer) {
    (void) _;
    gquic_str_test_echo(writer);
    gquic_crypto_stream_write(&handshake, writer);
    gquic_coglobal_execute(__handshake_write_thread, writer);
    return 0;
}

static int onertt_write(void *const _, gquic_writer_str_t *const writer) {
    (void) _;
    gquic_str_test_echo(writer);
    return 0;
}

int send_chello() {
    gquic_handshake_establish_init(&client_establish);
    gquic_transport_parameters_init(&client_params);
    gquic_rtt_init(&client_rtt);
    gquic_net_str_to_addr_v4(&client_addr, "127.0.0.1");
    gquic_crypto_stream_init(&initial);
    gquic_crypto_stream_init(&handshake);
    gquic_crypto_stream_init(&onertt);
    gquic_crypto_stream_ctor(&initial);
    gquic_crypto_stream_ctor(&handshake);
    gquic_crypto_stream_ctor(&onertt);

    gquic_handshake_establish_ctor(&client_establish,
                                   &initial, init_write,
                                   &handshake, handshake_write,
                                   &onertt, onertt_write,
                                   NULL, NULL,
                                   &cli_cfg, &cdci, &client_params, &client_rtt, &client_addr, 1);

    gquic_coglobal_execute(__client_run, send_chello);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int get_cert(PKCS12 **const cert_s, const gquic_tls_client_hello_msg_t *const hello) {
    (void) hello;
    FILE *f = fopen("test_certs/ed25519_p12.pem", "r");
    *cert_s = d2i_PKCS12_fp(f, NULL);
    fclose(f);
    return 0;
}

int server_session_run_co(void *const sess) {
    GQUIC_ASSERT_FAST_RETURN(gquic_session_run(sess));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(session_server) {
    gquic_coglobal_thread_init(0);

    printf("START client_est\n");
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
    cfg.get_ser_cert = get_cert;
    cfg.handshake_timeout = 2 * 1000 * 1000;

    gquic_tls_config_init(&cli_cfg);
    cli_cfg.insecure_skiy_verify = 1;

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
                             0);

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

    send_chello();

    gquic_coglobal_execute(server_session_run_co, &sess);

    int i = 0;
    for (i = 0; i < 150; i++) {
        gquic_coglobal_schedule();
    }

    return 0;
}
