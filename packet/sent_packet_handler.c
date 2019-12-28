#include "packet/sent_packet_handler.h"

int gquic_packet_sent_mem_init(gquic_packet_sent_mem_t *const mem) {
    if (mem == NULL) {
        return -1;
    }

    gquic_list_head_init(&mem->list);
    gquic_rbtree_root_init(&mem->root);

    return 0;
}

int gquic_packet_sent_mem_dtor(gquic_packet_sent_mem_t *const mem) {
    gquic_rbtree_t *del = NULL;
    if (mem == NULL) {
        return -1;
    }

    while (!gquic_rbtree_is_nil(mem->root)) {
        del = mem->root;
        gquic_rbtree_remove(&mem->root, &del);
        gquic_rbtree_release(del, NULL);
    }
    while (!gquic_list_head_empty(&mem->list)) {
        gquic_packet_dtor(GQUIC_LIST_FIRST(&mem->list));
        gquic_list_release(GQUIC_LIST_FIRST(&mem->list));
    }
    return 0;
}

int gquic_packet_sent_mem_sent_packet(gquic_packet_sent_mem_t *const mem, const gquic_packet_t *const packet) {
    const gquic_packet_t **packet_storage = NULL;
    gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (mem == NULL || packet == NULL) {
        return -1;
    }
    if ((packet_storage = gquic_list_alloc(sizeof(gquic_packet_t *))) == NULL) {
        return -2;
    }
    if (gquic_rbtree_alloc(&packet_storage_rb_node, sizeof(u_int64_t), sizeof(gquic_packet_t ***)) != 0) {
        return -3;
    }
    *packet_storage = packet;
    *(const gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node) = packet_storage;
    *(u_int64_t *) GQUIC_RBTREE_KEY(packet_storage_rb_node) = packet->pn;

    gquic_list_insert_before(&mem->list, packet_storage);
    gquic_rbtree_insert(&mem->root, packet_storage_rb_node);

    return 0;
}

int gquic_packet_sent_mem_get_packet(const gquic_packet_t **const packet, gquic_packet_sent_mem_t *const mem, const u_int64_t pn) {
    const gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (packet == NULL || mem == NULL) {
        return -1;
    }
    *packet = NULL;
    if (gquic_rbtree_find(&packet_storage_rb_node, mem->root, &pn, sizeof(u_int64_t)) != 0) {
        return -2;
    }
    *packet = **(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node);
    return 0;
}

int gquic_packet_sent_mem_remove(gquic_packet_sent_mem_t *const mem, const u_int64_t pn, int (*release_packet_func) (gquic_packet_t *const)) {
    gquic_packet_t *packet = NULL;
    gquic_rbtree_t *packet_storage_rb_node = NULL;
    if (mem == NULL) {
        return -1;
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &packet_storage_rb_node, mem->root, &pn, sizeof(u_int64_t)) != 0) {
        return -2;
    }
    packet = **(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node);

    gquic_rbtree_remove(&mem->root, &packet_storage_rb_node);
    gquic_list_release(*(gquic_packet_t ***) GQUIC_RBTREE_VALUE(packet_storage_rb_node));
    gquic_rbtree_release(packet_storage_rb_node, NULL);

    if (packet != NULL && release_packet_func != NULL) {
        if (release_packet_func(packet) != 0) {
            return -3;
        }
    }
    return 0;
}
