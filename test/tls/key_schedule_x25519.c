#include "tls/key_schedule.h"

int main() {
    gquic_tls_ecdhe_params_t alice_param;
    gquic_tls_ecdhe_params_t bob_param;
    gquic_tls_ecdhe_params_generate(&alice_param, GQUIC_TLS_CURVE_X25519);
    gquic_tls_ecdhe_params_generate(&bob_param, GQUIC_TLS_CURVE_X25519);

    gquic_str_t alice_public_key;
    gquic_str_t bob_public_key;
    gquic_str_init(&alice_public_key);
    gquic_str_init(&bob_public_key);
    GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&bob_param, &bob_public_key);
    GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&alice_param, &alice_public_key);

    gquic_str_t alice_shared_key;
    gquic_str_t bob_shared_key;
    gquic_str_init(&alice_shared_key);
    gquic_str_init(&bob_shared_key);
    GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&alice_param, &alice_shared_key, &bob_public_key);
    GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&bob_param, &bob_shared_key, &alice_public_key);

    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(&alice_shared_key); i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&alice_shared_key))[i]);
    printf("\n");
    for (i = 0; i < GQUIC_STR_SIZE(&bob_shared_key); i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&bob_shared_key))[i]);
    printf("\n");

    return 0;
}
