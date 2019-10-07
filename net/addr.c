#include "net/addr.h"
#include <unistd.h>
#include <string.h>

int gquic_net_addr_to_str(const gquic_net_addr_t *const addr, gquic_str_t *const ret) {
    if (addr == NULL || ret == NULL) {
        return -1;
    }
    switch (addr->type) {
    case AF_INET:
        if (gquic_str_alloc(ret, INET_ADDRSTRLEN) != 0) {
            return -3;
        }
        if (inet_ntop(AF_INET, &addr->addr.v4.sin_addr, GQUIC_STR_VAL(ret), GQUIC_STR_SIZE(ret)) == NULL) {
            return -4;
        }
        break;
    case AF_INET6:
        if (gquic_str_alloc(ret, INET6_ADDRSTRLEN) != 0) {
            return -3;
        }
        if (inet_ntop(AF_INET6, &addr->addr.v6.sin6_addr, GQUIC_STR_VAL(ret), GQUIC_STR_SIZE(ret)) == NULL) {
            return -4;
        }
        break;
    case AF_UNIX:
        if (gquic_str_alloc(ret, sizeof(addr->addr.un.sun_path)) != 0) {
            return -3;
        }
        memcpy(GQUIC_STR_VAL(ret), addr->addr.un.sun_path, sizeof(addr->addr.un.sun_path));
        break;
    default:
        return -5;
    }
    
    GQUIC_STR_SIZE(ret) = strlen(GQUIC_STR_VAL(ret));
    if (GQUIC_STR_SIZE(ret) == 0) {
        gquic_str_reset(ret);
        return -6;
    }
    return 0;
}

int gquic_net_str_to_addr_v4(gquic_net_addr_t *const addr, const char *const ip) {
    if (addr == NULL || ip == NULL) {
        return -1;
    }

    addr->type = AF_INET;
    inet_aton(ip, &addr->addr.v4.sin_addr);
    return 0;
}
