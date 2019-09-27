#include <openssl/sha.h>
#include <string.h>
#include "tls/config.h"

int gquic_tls_ticket_key_deserialize(gquic_tls_ticket_key_t *ticket_key, const void *buf, const size_t size) {
    if (ticket_key == NULL || buf == NULL) {
        return -1;
    }
    if (size != 32) {
        return -2;
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, buf, size);
    SHA256_Final(hash, &sha);
    memcpy(ticket_key->name, hash, 16);
    memcpy(ticket_key->aes_key, hash + 16, 16);
    memcpy(ticket_key->hmac_key, hash + 32, 16);
    return 0;
}
