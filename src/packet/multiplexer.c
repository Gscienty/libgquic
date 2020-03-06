#include "packet/multiplexer.h"
#include "util/rbtree.h"
#include <semaphore.h>

typedef struct gquic_multiplexer_s gquic_multiplexer_t;
struct gquic_multiplexer_s {
    sem_t mtx;
    gquic_rbtree_t *conns;
};
static void gquic_init_multiplexer();

static int __inited = 0;
static gquic_multiplexer_t __ins;

static void gquic_init_multiplexer() {
    if (__inited == 0) {
        sem_init(&__ins.mtx, 0, 1);
        gquic_rbtree_root_init(&__ins.conns);
        __inited = 1;
    }
}

int gquic_multiplexer_add_conn(gquic_packet_handler_map_t **const handler_storage,
                               const int conn_fd,
                               const int conn_id_len,
                               const gquic_str_t *const stateless_reset_token) {
    int ret = 0;
    gquic_rbtree_t *rbt = NULL;
    if (handler_storage == NULL) {
        return -1;
    }
    gquic_init_multiplexer();

    sem_wait(&__ins.mtx);
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, __ins.conns, &conn_fd, sizeof(int)) != 0) {
        if (gquic_rbtree_alloc(&rbt, sizeof(int), sizeof(gquic_packet_handler_map_t)) != 0) {
            ret = -2;
            goto finished;
        }
        *(int *) GQUIC_RBTREE_KEY(rbt) = conn_fd;
        gquic_packet_handler_map_init(GQUIC_RBTREE_VALUE(rbt));
        gquic_packet_handler_map_ctor(GQUIC_RBTREE_VALUE(rbt), conn_fd, conn_id_len, stateless_reset_token);
        gquic_rbtree_insert(&__ins.conns, rbt);
    }
    if (((gquic_packet_handler_map_t *) GQUIC_RBTREE_VALUE(rbt))->conn_id_len != conn_id_len) {
        ret = -3;
        goto finished;
    }
    if (GQUIC_STR_SIZE(stateless_reset_token) != 0
        && gquic_str_cmp(stateless_reset_token, &((gquic_packet_handler_map_t *) GQUIC_RBTREE_VALUE(rbt))->stateless_reset_key) != 0) {
        ret = -4;
        goto finished;
    }
    *handler_storage = GQUIC_RBTREE_VALUE(rbt);

finished:
    sem_post(&__ins.mtx);
    return ret;
}

int gquic_multiplexer_remove_conn(const int conn_fd) {
    int ret = 0;
    gquic_rbtree_t *rbt = NULL;
    gquic_init_multiplexer();
    sem_wait(&__ins.mtx);
    
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, __ins.conns, &conn_fd, sizeof(int)) != 0) {
        ret = -1;
        goto finished;
    }
    gquic_rbtree_remove(&__ins.conns, &rbt);
    gquic_packet_handler_map_dtor(GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_release(rbt, NULL);

finished:
    sem_post(&__ins.mtx);
    return ret;
}
