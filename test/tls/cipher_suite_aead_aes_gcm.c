#include "tls/cipher_suite.h"
#include "../tls/cipher_suite.c"

int main() {
    gquic_tls_aead_t aead;

    gquic_str_t plain;
    gquic_str_t addata;
    gquic_str_t cipher;
    gquic_str_t tag;
    gquic_str_t key;
    gquic_str_t iv;

    gquic_str_alloc(&key, 32);
    gquic_str_alloc(&iv, 12);
    uint8_t gcm_key[] = {
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
        0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
        0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
    };
    int i = 0; for (i = 0; i < 32; i++) ((unsigned char *) GQUIC_STR_VAL(&key))[i] = gcm_key[i];
    unsigned char gcm_iv[] = {
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
    };
    for (i = 0; i < 12; i++) ((unsigned char *) GQUIC_STR_VAL(&iv))[i] = gcm_iv[i];

    aead_aes_gcm_init(&aead, &key, &iv);


    uint8_t gcm_pt[] = {
        0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
        0xcc, 0x2b, 0xf2, 0xa5
    };
    uint8_t gcm_aad[] = {
        0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
        0x7f, 0xec, 0x78, 0xde
    };
    gquic_str_alloc(&plain, sizeof(gcm_pt));
    gquic_str_alloc(&addata, sizeof(gcm_aad));
    for (i = 0; i < (int) sizeof(gcm_pt); i++) ((unsigned char *) GQUIC_STR_VAL(&plain))[i] = gcm_pt[i];
    for (i = 0; i < (int) sizeof(gcm_aad); i++) ((unsigned char *) GQUIC_STR_VAL(&addata))[i] = gcm_aad[i];

    GQUIC_TLS_AEAD_SEAL(&tag, &cipher, &aead, &plain, &addata);

    BIO_dump_fp(stdout, GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));

    /*BIO_dump_fp(stdout, GQUIC_STR_VAL(&cipher), GQUIC_STR_SIZE(&cipher));*/

    gquic_str_t decrypt_plain;
    int ret = GQUIC_TLS_AEAD_OPEN(&decrypt_plain, &aead, &tag, &cipher, &addata);
    printf("%d\n", ret);

    BIO_dump_fp(stdout, GQUIC_STR_VAL(&decrypt_plain), GQUIC_STR_SIZE(&decrypt_plain));
    return 0;
}
