#include "util/rbtree.h"
#include <unistd.h>
#include <malloc.h>

static int gquic_rbtree_left_rotate(gquic_rbtree_t **, gquic_rbtree_t *);
static int gquic_rbtree_right_rotate(gquic_rbtree_t **, gquic_rbtree_t *);
static int gquic_rbtree_key_cmp(const void *a_key, const size_t a_len, const gquic_rbtree_t *b);
static int gquic_rbtree_insert_fixup(gquic_rbtree_t **, gquic_rbtree_t *);
static gquic_rbtree_t *gquic_rbtree_successor(gquic_rbtree_t *);
static int gquic_rbtree_remove_fixup(gquic_rbtree_t **, gquic_rbtree_t *);
static gquic_rbtree_t *gquic_rbtree_minimum(gquic_rbtree_t *node);

static gquic_rbtree_t nil = {
    GQUIC_RBTREE_COLOR_BLACK,
    &nil,
    &nil,
    &nil,
    0
};

int gquic_rbtree_root_init(gquic_rbtree_t **root) {
    if (root == NULL) {
        return -1;
    }
    *root = &nil;
    return 0;
}

gquic_rbtree_t *gquic_rbtree_alloc(const size_t key_len, const size_t val_len) {
    gquic_rbtree_t *ret = malloc(sizeof(gquic_rbtree_t) + key_len + val_len);
    if (ret == NULL) {
        return NULL;
    }
    ret->color = GQUIC_RBTREE_COLOR_RED;
    ret->left = &nil;
    ret->parent = &nil;
    ret->right = &nil;
    ret->key_len = key_len;
    return ret;
}

int gquic_rbtree_insert(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    int cmpret;
    gquic_rbtree_t *parent = &nil;
    gquic_rbtree_t **in = root;

    while (*in != &nil) {
        parent = *in;
        cmpret = gquic_rbtree_key_cmp(GQUIC_RBTREE_KEY(node), node->key_len, parent);
        if (cmpret == 0) {
            return -1;
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

gquic_rbtree_t *gquic_rbtree_remove(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *del;
    if (node->left == &nil || node->right == &nil) {
        del = node;
    }
    else {
        del = gquic_rbtree_successor(node);
    }
    gquic_rbtree_t *ref;
    if (del->left != &nil) {
        ref = del->left;
    }
    else {
        ref = del->right;
    }
    ref->parent = del->parent;
    if (del->parent == &nil) {
        *root = ref;
    }
    else if (del == del->parent->left) {
        del->parent->left = ref;
    }
    else {
        del->parent->right = ref;
    }
    if (node != del) {
        gquic_rbtree_t cp = { del->color, del->left, del->right, del->parent, del->key_len };

        del->color = node->color;
        del->left = node->left;
        del->right = node->left;
        del->parent = node->parent;
        del->key_len = node->key_len;

        node->color = cp.color;
        node->left = cp.left;
        node->right = cp.right;
        node->parent = cp.parent;
        node->key_len = cp.key_len;

        if (node->left != &nil) {
            node->left->parent = node;
        }
        if (node->right != &nil) {
            node->right->parent = node;
        }
        if (node->parent == &nil) {
            *root = node;
        }
        else if (node->parent->left == del) {
            node->parent->left = node;
        }
        else if (node->parent->right == del) {
            node->parent->right = node;
        }

        del = node;
    }
    if (del->color == GQUIC_RBTREE_COLOR_BLACK) {
        gquic_rbtree_remove_fixup(root, ref);
    }

    return del;
}

int gquic_rbtree_is_nil(gquic_rbtree_t *node) {
    return node == &nil;
}

static int gquic_rbtree_left_rotate(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *child;
    if (root == NULL || node == NULL) {
        return -1;
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
    return 0;
}

static int gquic_rbtree_right_rotate(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *child;
    if (root == NULL || node == NULL) {
        return -1;
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
    return 0;
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
    return 0;
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

static int gquic_rbtree_remove_fixup(gquic_rbtree_t **root, gquic_rbtree_t *node) {
    gquic_rbtree_t *ref;
    if (root == NULL || node == NULL) {
        return -1;
    }

    while (node != *root && node->color == GQUIC_RBTREE_COLOR_BLACK) {
        if (node == node->parent->left) {
            ref = node->parent->right;
            if (ref->color == GQUIC_RBTREE_COLOR_RED) {
                ref->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->color = GQUIC_RBTREE_COLOR_RED;
                gquic_rbtree_left_rotate(root, node->parent);
                ref = node->parent->right;
            }
            if (ref->left->color == GQUIC_RBTREE_COLOR_BLACK && ref->right->color == GQUIC_RBTREE_COLOR_BLACK) {
                ref->color = GQUIC_RBTREE_COLOR_RED;
                node = node->parent;
            }
            else {
                if (ref->right->color == GQUIC_RBTREE_COLOR_BLACK) {
                    ref->color = GQUIC_RBTREE_COLOR_RED;
                    ref->left->color = GQUIC_RBTREE_COLOR_BLACK;
                    gquic_rbtree_right_rotate(root, ref);
                    ref = node->parent->right;
                }
                ref->color = ref->parent->color;
                ref->parent->color = GQUIC_RBTREE_COLOR_BLACK;
                ref->right->color = GQUIC_RBTREE_COLOR_BLACK;
                gquic_rbtree_left_rotate(root, node->parent);
                break;
            }
        }
        else {
            ref = node->parent->left;
            if (ref->color == GQUIC_RBTREE_COLOR_RED) {
                ref->color = GQUIC_RBTREE_COLOR_BLACK;
                node->parent->color = GQUIC_RBTREE_COLOR_RED;
                gquic_rbtree_right_rotate(root, node->parent);
                ref = node->parent->left;
            }
            if (ref->left->color == GQUIC_RBTREE_COLOR_BLACK && ref->right->color == GQUIC_RBTREE_COLOR_BLACK) {
                ref->color = GQUIC_RBTREE_COLOR_RED;
                node = node->parent;
            }
            else {
                if (ref->left->color == GQUIC_RBTREE_COLOR_BLACK) {
                    ref->color = GQUIC_RBTREE_COLOR_RED;
                    ref->right->color = GQUIC_RBTREE_COLOR_BLACK;
                    gquic_rbtree_left_rotate(root, ref);
                    ref = node->parent->left;
                }
                ref->color = ref->parent->color;
                ref->parent->color = GQUIC_RBTREE_COLOR_BLACK;
                ref->left->color = GQUIC_RBTREE_COLOR_BLACK;
                gquic_rbtree_right_rotate(root, node->parent);
                break;
            }
        }
    }
    node->color = GQUIC_RBTREE_COLOR_BLACK;
    return 0;
}
