#include "util/big_endian.h"

int gquic_big_endian_transfer(void *out, const void *in, const size_t size) {
    if (out == NULL) {
        return -1;
    }
    if (in == NULL) {
        return -2;
    }
    size_t i = 0;
    for (i = 0; i < size; i++) {
        ((unsigned char *) out)[size - i - 1] = ((unsigned char *) in)[i];
    }
    return 0;
}
