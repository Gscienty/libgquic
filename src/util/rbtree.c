#include "util/rbtree.h"
#include "exception.h"
#include <unistd.h>
#include <malloc.h>

static int gquic_rbtree_left_rotate(gquic_rbtree_t **, gquic_rbtree_t *);
static int gquic_rbtree_right_rotate(gquic_rbtree_t **, gquic_rbtree_t *);
static int gquic_rbtree_key_cmp(const void *a_key, const size_t a_len, const gquic_rbtree_t *b);
static int gquic_rbtree_insert_fixup(gquic_rbtree_t **, gquic_rbtree_t *);
static gquic_rbtree_t *gquic_rbtree_successor(gquic_rbtree_t *);
static gquic_rbtree_t *gquic_rbtree_minimum(gquic_rbtree_t *node);
static inline int gquic_rbtree_replace(gquic_rbtree_t **const, gquic_rbtree_t *const, gquic_rbtree_t *const);
static inline int gquic_rbtree_sibling(gquic_rbtree_t **const, const gquic_rbtree_t *const);
static inline int gquic_rbtree_delete_case1(gquic_rbtree_t **const, gquic_rbtree_t *const);
static inline int gquic_rbtree_delete_case2(gquic_rbtree_t **const, gquic_rbtree_t *const);
static inline int gquic_rbtree_delete_case3(gquic_rbtree_t **const, gquic_rbtree_t *const);
static inline int gquic_rbtree_delete_case4(gquic_rbtree_t **const, gquic_rbtree_t *const);
static inline int gquic_rbtree_delete_case5(gquic_rbtree_t **const, gquic_rbtree_t *const);
static inline int gquic_rbtree_delete_case6(gquic_rbtree_t **const, gquic_rbtree_t *const);
static inline int gquic_rbtree_assign(gquic_rbtree_t **const, gquic_rbtree_t *const, gquic_rbtree_t *const);

static gquic_rbtree_t nil = {
    GQUIC_RBTREE_COLOR_BLACK,
    &nil,
    &nil,
    &nil,
    0
};

int gquic_rbtree_root_init(gquic_rbtree_t **const root) {
    if (root == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *root = &nil;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_rbtree_alloc(gquic_rbtree_t **const rb, const size_t key_len, const size_t val_len) {
    gquic_rbtree_t *ret = NULL;
    if (rb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((ret = malloc(sizeof(gquic_rbtree_t) + key_len + val_len)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    ret->color = GQUIC_RBTREE_COLOR_RED;
    ret->left = &nil;
    ret->parent = &nil;
    ret->right = &nil;
    ret->key_len = key_len;
    if (rb != NULL) {
        *rb = ret;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_rbtree_release(gquic_rbtree_t *const rb, int (*release_val)(void *const)) {
    int exception = GQUIC_SUCCESS;
    if (rb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (release_val != NULL && GQUIC_ASSERT_CAUSE(exception, release_val(GQUIC_RBTREE_VALUE(rb)))) {
        return exception;
    }
    free(rb);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_rbtree_insert(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    int cmpret;
    gquic_rbtree_t *parent = &nil;
    gquic_rbtree_t **in = root;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    while (*in != &nil) {
        parent = *in;
        cmpret = gquic_rbtree_key_cmp(GQUIC_RBTREE_KEY(node), node->key_len, parent);
        if (cmpret == 0) {
            return GQUIC_EXCEPTION_RBTREE_CONFLICT;
        }
        if (cmpret < 0) {
            in = &parent->left;
        }
        else {
            in = &parent->right;
        }
    }
    node->parent = parent;
    *in = node;

    return gquic_rbtree_insert_fixup(root, node);
}

int gquic_rbtree_insert_cmp(gquic_rbtree_t **const root, gquic_rbtree_t *const node, int (*key_cmp) (void *const, void *const)) {
    int cmpret;
    gquic_rbtree_t *parent = &nil;
    gquic_rbtree_t **in = root;
    if (root == NULL || node == NULL || key_cmp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    while (*in != &nil) {
        parent = *in;
        cmpret = key_cmp(GQUIC_RBTREE_KEY(node), GQUIC_RBTREE_KEY(parent));
        if (cmpret == 0) {
            return GQUIC_EXCEPTION_RBTREE_CONFLICT;
        }
        if (cmpret < 0) {
            in = &parent->left;
        }
        else {
            in = &parent->right;
        }
    }
    node->parent = parent;
    *in = node;

    return gquic_rbtree_insert_fixup(root, node);
}

int gquic_rbtree_remove(gquic_rbtree_t **const root, gquic_rbtree_t **const node_p) {
    if (root == NULL || node_p == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_rbtree_t *node = *node_p;
    if (node->left != &nil && node->right != &nil) {
        gquic_rbtree_t *next = gquic_rbtree_minimum(node->right);
        gquic_rbtree_t tmp;
        gquic_rbtree_assign(root, &tmp, next);
        gquic_rbtree_assign(root, next, node);
        gquic_rbtree_assign(root, node, &tmp);
    }
    gquic_rbtree_t *child = node->left == &nil ? node->right : node->left;
    if (node->color == GQUIC_RBTREE_COLOR_BLACK) {
        node->color = child->color;
        gquic_rbtree_delete_case1(root, node);
    }
    gquic_rbtree_replace(root, node, child);
    if (node->parent == &nil && child != &nil) {
        child->color = GQUIC_RBTREE_COLOR_BLACK;
    }
    *node_p = node;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_rbtree_is_nil(gquic_rbtree_t *const node) {
    return node == &nil;
}

int gquic_rbtree_find(const gquic_rbtree_t **const ret, const gquic_rbtree_t *const root, const void *key, const size_t key_len) {
    int cmpret;
    if (ret == NULL || root == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *ret = root;
    while (*ret != &nil) {
        cmpret = gquic_rbtree_key_cmp(key, key_len, *ret);
        if (cmpret == 0) {
            return GQUIC_SUCCESS;
        }
        if (cmpret < 0) {
            *ret = (*ret)->left;
        }
        else {
            *ret = (*ret)->right;
        }
    }

    return GQUIC_EXCEPTION_NOT_FOUND;
}

int gquic_rbtree_find_cmp(const gquic_rbtree_t **const ret, const gquic_rbtree_t *const root, void *key, int (key_cmp) (void *const, void *const)) {
    int cmpret;
    if (ret == NULL || root == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *ret = root;
    while (*ret != &nil) {
        cmpret = key_cmp(key, GQUIC_RBTREE_KEY(*ret));
        if (cmpret == 0) {
            return GQUIC_SUCCESS;
        }
        if (cmpret < 0) {
            *ret = (*ret)->left;
        }
        else {
            *ret = (*ret)->right;
        }
    }

    return GQUIC_EXCEPTION_NOT_FOUND;
}

static int gquic_rbtree_left_rotate(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *child;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    child = node->right;
    node->right = child->left;
    if (child->left != &nil) {
        child->left->parent = node;
    }
    child->parent = node->parent;
    if (node->parent == &nil) {
        *root = child;
    }
    else if (node == node->parent->left) {
        node->parent->left = child;
    }
    else {
        node->parent->right = child;
    }
    child->left = node;
    node->parent = child;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_rbtree_right_rotate(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *child;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    child = node->left;
    node->left = child->right;
    if (child->right != &nil) {
        child->right->parent = node;
    }
    child->parent = node->parent;
    if (node->parent == &nil) {
        *root = child;
    }
    else {
        if (node == node->parent->left) {
            node->parent->left = child;
        }
        else {
            node->parent->right = child;
        }
    }
    child->right = node;
    node->parent = child;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_rbtree_key_cmp(const void *a_key, const size_t a_len, const gquic_rbtree_t *b) {
    void *b_key;
    if (a_len == b->key_len) {
        b_key = GQUIC_RBTREE_KEY(b);
        size_t itr;
        for (itr = 0; itr < a_len; itr++) {
            if (((unsigned char *) a_key)[itr] < ((unsigned char *) b_key)[itr]) {
                return -1;
            }
            else if (((unsigned char *) a_key)[itr] > ((unsigned char *) b_key)[itr]) {
                return 1;
            }
        }
        return 0;
    }
    
    if (a_len < b->key_len) {
        return -1;
    }
    else {
        return 1;
    }
}

static int gquic_rbtree_insert_fixup(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *uncle;
    while (node->parent->color == GQUIC_RBTREE_COLOR_RED) {
        if (node->parent == node->parent->parent->left) {
            uncle = node->parent->parent->right;
            if (uncle->color == GQUIC_RBTREE_COLOR_RED) {
                uncle->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->parent->color = GQUIC_RBTREE_COLOR_RED;
                node = node->parent->parent;
            }
            else {
                if (node == node->parent->right) {
                    node = node->parent;
                    gquic_rbtree_left_rotate(root, node);
                }
                node->parent->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->parent->color = GQUIC_RBTREE_COLOR_RED;
                gquic_rbtree_right_rotate(root, node->parent->parent);
            }
        }
        else {
            uncle = node->parent->parent->left;
            if (uncle->color == GQUIC_RBTREE_COLOR_RED) {
                uncle->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->parent->color = GQUIC_RBTREE_COLOR_RED;
                node = node->parent->parent;
            }
            else {
                if (node == node->parent->left) {
                    node = node->parent;
                    gquic_rbtree_right_rotate(root, node);
                }
                node->parent->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->parent->color = GQUIC_RBTREE_COLOR_RED;
                gquic_rbtree_left_rotate(root, node->parent->parent);;
            }
        }
    }
    (*root)->color = GQUIC_RBTREE_COLOR_BLACK;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_rbtree_t *gquic_rbtree_successor(gquic_rbtree_t *node) {
    if (node == &nil) {
        return &nil;
    }
    if (node->right != &nil) {
        return gquic_rbtree_minimum(node->right);    
    }
    gquic_rbtree_t *ret = node->parent;
    while (ret != &nil && node == ret->right) {
        node = ret;
        ret = node->parent;
    }

    return ret;
}

static gquic_rbtree_t *gquic_rbtree_minimum(gquic_rbtree_t *node) {
    if (node == &nil) {
        return &nil;
    }
    while (node->left != &nil) {
        node = node->left;
    }

    return node;
}

static inline int gquic_rbtree_replace(gquic_rbtree_t **const root, gquic_rbtree_t *const old_n, gquic_rbtree_t *const new_n) {
    if (root == NULL || old_n == NULL || new_n == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (old_n == *root) {
        *root = new_n;
    }
    else {
        if (old_n == old_n->parent->left) {
            old_n->parent->left = new_n;
        }
        else {
            old_n->parent->right = new_n;
        }
    }
    if (new_n != &nil) {
        new_n->parent = old_n->parent;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_sibling(gquic_rbtree_t **const ret, const gquic_rbtree_t *const node) {
    if (ret == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (node->parent->left == node) {
        *ret = node->parent->right;
    }
    else {
        *ret = node->parent->left;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_delete_case1(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (node->parent != &nil) {
        gquic_rbtree_delete_case2(root, node);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_delete_case2(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    gquic_rbtree_t *sibling = &nil;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_rbtree_sibling(&sibling, node);
    if (sibling->color == GQUIC_RBTREE_COLOR_RED) {
        node->parent->color = GQUIC_RBTREE_COLOR_RED;
        sibling->color = GQUIC_RBTREE_COLOR_BLACK;
        if (node == node->parent->left) {
            gquic_rbtree_left_rotate(root, node->parent);
        }
        else {
            gquic_rbtree_right_rotate(root, node->parent);
        }
    }
    gquic_rbtree_delete_case3(root, node);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
static inline int gquic_rbtree_delete_case3(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    gquic_rbtree_t *sibling = &nil;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_rbtree_sibling(&sibling, node);
    if (node->parent->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->left->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->right->color == GQUIC_RBTREE_COLOR_BLACK) {
        sibling->color = GQUIC_RBTREE_COLOR_RED;
        gquic_rbtree_delete_case1(root, node->parent);
    }
    else {
        gquic_rbtree_delete_case4(root, node);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_delete_case4(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    gquic_rbtree_t *sibling = &nil;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_rbtree_sibling(&sibling, node);
    if (node->parent->color == GQUIC_RBTREE_COLOR_RED &&
        sibling->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->left->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->right->color == GQUIC_RBTREE_COLOR_BLACK) {
        sibling->color = GQUIC_RBTREE_COLOR_RED;
        node->parent->color = GQUIC_RBTREE_COLOR_BLACK;
    }
    else {
        gquic_rbtree_delete_case5(root, node);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_delete_case5(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    gquic_rbtree_t *sibling = &nil;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_rbtree_sibling(&sibling, node);
    if (node->parent->left == node &&
        sibling->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->left->color == GQUIC_RBTREE_COLOR_RED &&
        sibling->right->color == GQUIC_RBTREE_COLOR_BLACK) {
        sibling->color = GQUIC_RBTREE_COLOR_RED;
        sibling->left->color = GQUIC_RBTREE_COLOR_BLACK;
        gquic_rbtree_right_rotate(root, sibling);
    }
    else if (node->parent->right == node &&
        sibling->color == GQUIC_RBTREE_COLOR_BLACK &&
        sibling->right->color == GQUIC_RBTREE_COLOR_RED &&
        sibling->left->color == GQUIC_RBTREE_COLOR_BLACK) {
        sibling->color = GQUIC_RBTREE_COLOR_RED;
        sibling->right->color = GQUIC_RBTREE_COLOR_BLACK;
        gquic_rbtree_left_rotate(root, sibling);
    }
    gquic_rbtree_delete_case6(root, node);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_delete_case6(gquic_rbtree_t **const root, gquic_rbtree_t *const node) {
    gquic_rbtree_t *sibling = &nil;
    if (root == NULL || node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_rbtree_sibling(&sibling, node);
    sibling->color = node->parent->color;
    node->parent->color = GQUIC_RBTREE_COLOR_BLACK;
    if (node == node->parent->left) {
        sibling->right->color = GQUIC_RBTREE_COLOR_BLACK;
        gquic_rbtree_left_rotate(root, node->parent);
    }
    else {
        sibling->left->color = GQUIC_RBTREE_COLOR_BLACK;
        gquic_rbtree_right_rotate(root, node->parent);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_rbtree_assign(gquic_rbtree_t **const root, gquic_rbtree_t *const target, gquic_rbtree_t *const ref) {
    if (root == NULL || target == NULL || ref == NULL || target == &nil || ref == &nil) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    target->color = ref->color;
    target->left = ref->left;
    target->right = ref->right;
    target->parent = ref->parent;

    if (ref->parent == &nil) {
        *root = target;
    }
    else {
        if (ref->parent->left == ref) {
            ref->parent->left = target;
        }
        else {
            ref->parent->right = target;
        }
    }
    if (ref->left != &nil) {
        ref->left->parent = target;
    }
    if (ref->right != &nil) {
        ref->right->parent = target;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
