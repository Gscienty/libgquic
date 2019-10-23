#include "tls/client_sess_state.h"
#include "util/rbtree.h"
#include "util/list.h"

typedef struct gquic_tls_lru_sess_cache_s gquic_tls_lru_sess_cache_t;
struct gquic_tls_lru_sess_cache_s {
    gquic_rbtree_t *m;
    gquic_list_t q;
};
