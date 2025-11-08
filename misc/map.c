#include <string.h>
#include <stdio.h>
#include "map.h"

// Internal helper functions
static map_node_t* __map_create_node(map_t* map, const void* key, void* value);
static void __map_free_node(map_t* map, map_node_t* node);
static void __map_rotate_left(map_t* map, map_node_t* x);
static void __map_rotate_right(map_t* map, map_node_t* x);
static void __map_insert_fixup(map_t* map, map_node_t* z);
static void __map_transplant(map_t* map, map_node_t* u, map_node_t* v);
static void __map_delete_fixup(map_t* map, map_node_t* x);
static map_node_t* __map_minimum(map_t* map, map_node_t* node);
static map_node_t* __map_maximum(map_t* map, map_node_t* node);
static map_node_t* __map_successor(map_t* map, map_node_t* node);
static map_node_t* __map_predecessor(map_t* map, map_node_t* node);
static void __map_clear_recursive(map_t* map, map_node_t* node);

// Create a new map with comparison function
map_t* map_create(map_compare_fn compare) {
    return map_create_ex(compare, NULL, NULL, NULL, NULL);
}

// Create a new map with extended options
map_t* map_create_ex(map_compare_fn compare,
                     map_copy_fn key_copy, map_free_fn key_free,
                     map_copy_fn value_copy, map_free_fn value_free) {
    if (compare == NULL)
        return NULL;

    map_t* map = malloc(sizeof(map_t));
    if (map == NULL)
        return NULL;

    // Create sentinel nil node
    map->nil = malloc(sizeof(map_node_t));
    if (map->nil == NULL) {
        free(map);
        return NULL;
    }

    map->nil->color = MAP_BLACK;
    map->nil->parent = NULL;
    map->nil->left = NULL;
    map->nil->right = NULL;
    map->nil->key = NULL;
    map->nil->value = NULL;

    map->root = map->nil;
    map->size = 0;
    map->compare = compare;
    map->key_copy = key_copy;
    map->key_free = key_free;
    map->value_copy = value_copy;
    map->value_free = value_free;

    return map;
}

// Clear all nodes from the map
void map_clear(map_t* map) {
    if (map == NULL)
        return;

    __map_clear_recursive(map, map->root);
    map->root = map->nil;
    map->size = 0;
}

// Free the map and all its nodes
void map_free(map_t* map) {
    if (map == NULL)
        return;

    map_clear(map);
    free(map->nil);
    free(map);
}

// Insert a key-value pair (fails if key exists)
int map_insert(map_t* map, const void* key, void* value) {
    if (map == NULL)
        return -1;

    // Check if key already exists
    if (map_find_node(map, key) != map->nil)
        return 0; // Key already exists

    map_node_t* z = __map_create_node(map, key, value);
    if (z == NULL)
        return -1;

    map_node_t* y = map->nil;
    map_node_t* x = map->root;

    while (x != map->nil) {
        y = x;
        int cmp = map->compare(z->key, x->key);
        if (cmp < 0)
            x = x->left;
        else
            x = x->right;
    }

    z->parent = y;
    if (y == map->nil)
        map->root = z;
    else if (map->compare(z->key, y->key) < 0)
        y->left = z;
    else
        y->right = z;

    z->left = map->nil;
    z->right = map->nil;
    z->color = MAP_RED;

    __map_insert_fixup(map, z);
    map->size++;

    return 1;
}

// Insert or update a key-value pair
int map_insert_or_assign(map_t* map, void* key, void* value) {
    if (map == NULL)
        return -1;

    // Check if key already exists
    map_node_t* existing = map_find_node(map, key);
    if (existing != map->nil) {
        // Update existing value
        if (map->value_free != NULL)
            map->value_free(existing->value);

        if (map->value_copy != NULL)
            existing->value = map->value_copy(value);
        else
            existing->value = value;

        return 2; // Updated existing
    }

    // Insert new node
    return map_insert(map, key, value);
}

// Find value by key
void* map_find(map_t* map, const void* key) {
    if (map == NULL)
        return NULL;
    map_node_t* node = map_find_node(map, key);
    if (node == map->nil)
        return NULL;
    return node->value;
}

// Find node by key
map_node_t* map_find_node(map_t* map, const void* key) {
    if (map == NULL)
        return NULL;

    map_node_t* current = map->root;
    while (current != map->nil) {
        int cmp = map->compare(key, current->key);
        if (cmp == 0)
            return current;
        else if (cmp < 0)
            current = current->left;
        else
            current = current->right;
    }

    return map->nil;
}

// Erase a node by key
int map_erase(map_t* map, const void* key) {
    if (map == NULL)
        return 0;

    map_node_t* z = map_find_node(map, key);
    if (z == map->nil)
        return 0; // Not found

    map_node_t* y = z;
    map_node_t* x;
    map_color_t y_original_color = y->color;

    if (z->left == map->nil) {
        x = z->right;
        __map_transplant(map, z, z->right);
    } else if (z->right == map->nil) {
        x = z->left;
        __map_transplant(map, z, z->left);
    } else {
        y = __map_minimum(map, z->right);
        y_original_color = y->color;
        x = y->right;

        if (y->parent == z) {
            x->parent = y;
        } else {
            __map_transplant(map, y, y->right);
            y->right = z->right;
            y->right->parent = y;
        }

        __map_transplant(map, z, y);
        y->left = z->left;
        y->left->parent = y;
        y->color = z->color;
    }

    __map_free_node(map, z);
    map->size--;

    if (y_original_color == MAP_BLACK)
        __map_delete_fixup(map, x);

    return 1;
}

// Check if key exists
int map_contains(map_t* map, const void* key) {
    if (map == NULL)
        return 0;
    return map_find_node(map, key) != map->nil;
}

// Get map size
size_t map_size(const map_t* map) {
    if (map == NULL)
        return 0;
    return map->size;
}

// Check if map is empty
int map_empty(const map_t* map) {
    return map_size(map) == 0;
}

// Iterator operations
map_iterator_t map_begin(map_t* map) {
    map_iterator_t it;
    it.map = map;
    if (map == NULL || map->root == map->nil) {
        it.node = NULL;
    } else {
        it.node = __map_minimum(map, map->root);
    }
    return it;
}

map_iterator_t map_end(map_t* map) {
    map_iterator_t it;
    it.map = map;
    it.node = map ? map->nil : NULL;
    return it;
}

map_iterator_t map_next(map_iterator_t it) {
    if (it.map == NULL || it.node == NULL || it.node == it.map->nil) {
        it.node = NULL;
        return it;
    }
    it.node = __map_successor(it.map, it.node);
    return it;
}

map_iterator_t map_prev(map_iterator_t it) {
    if (it.map == NULL || it.node == NULL) {
        return it;
    }
    if (it.node == it.map->nil) {
        // Move to maximum
        it.node = __map_maximum(it.map, it.map->root);
    } else {
        it.node = __map_predecessor(it.map, it.node);
    }
    return it;
}

int map_iterator_valid(map_iterator_t it) {
    return it.map != NULL && it.node != NULL &&
           it.node != it.map->nil;
}

void* map_iterator_key(map_iterator_t it) {
    if (!map_iterator_valid(it))
        return NULL;
    return it.node->key;
}

void* map_iterator_value(map_iterator_t it) {
    if (!map_iterator_valid(it))
        return NULL;
    return it.node->value;
}

// Comparison functions
int map_compare_int(const void* a, const void* b) {
    intptr_t ia = (intptr_t)a;
    intptr_t ib = (intptr_t)b;
    if (ia < ib) return -1;
    if (ia > ib) return 1;
    return 0;
}

int map_compare_string(const void* a, const void* b) {
    return strcmp((const char*)a, (const char*)b);
}

int map_compare_ptr(const void* a, const void* b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

void* map_copy_string(const void *a) {
    return strdup((const char*)a);
}

// Internal helper functions

static map_node_t* __map_create_node(map_t* map, const void* key, void* value) {
    map_node_t* node = malloc(sizeof(map_node_t));
    if (node == NULL)
        return NULL;

    if (map->key_copy != NULL)
        node->key = map->key_copy(key);
    else
        node->key = (void*)key;

    if (map->value_copy != NULL)
        node->value = map->value_copy(value);
    else
        node->value = value;

    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;
    node->color = MAP_RED;

    return node;
}

static void __map_free_node(map_t* map, map_node_t* node) {
    if (node == NULL)
        return;

    if (map->key_free != NULL)
        map->key_free(node->key);

    if (map->value_free != NULL)
        map->value_free(node->value);

    free(node);
}

static void __map_rotate_left(map_t* map, map_node_t* x) {
    map_node_t* y = x->right;
    x->right = y->left;

    if (y->left != map->nil)
        y->left->parent = x;

    y->parent = x->parent;

    if (x->parent == map->nil)
        map->root = y;
    else if (x == x->parent->left)
        x->parent->left = y;
    else
        x->parent->right = y;

    y->left = x;
    x->parent = y;
}

static void __map_rotate_right(map_t* map, map_node_t* x) {
    map_node_t* y = x->left;
    x->left = y->right;

    if (y->right != map->nil)
        y->right->parent = x;

    y->parent = x->parent;

    if (x->parent == map->nil)
        map->root = y;
    else if (x == x->parent->right)
        x->parent->right = y;
    else
        x->parent->left = y;

    y->right = x;
    x->parent = y;
}

static void __map_insert_fixup(map_t* map, map_node_t* z) {
    while (z->parent->color == MAP_RED) {
        if (z->parent == z->parent->parent->left) {
            map_node_t* y = z->parent->parent->right;
            if (y->color == MAP_RED) {
                z->parent->color = MAP_BLACK;
                y->color = MAP_BLACK;
                z->parent->parent->color = MAP_RED;
                z = z->parent->parent;
            } else {
                if (z == z->parent->right) {
                    z = z->parent;
                    __map_rotate_left(map, z);
                }
                z->parent->color = MAP_BLACK;
                z->parent->parent->color = MAP_RED;
                __map_rotate_right(map, z->parent->parent);
            }
        } else {
            map_node_t* y = z->parent->parent->left;
            if (y->color == MAP_RED) {
                z->parent->color = MAP_BLACK;
                y->color = MAP_BLACK;
                z->parent->parent->color = MAP_RED;
                z = z->parent->parent;
            } else {
                if (z == z->parent->left) {
                    z = z->parent;
                    __map_rotate_right(map, z);
                }
                z->parent->color = MAP_BLACK;
                z->parent->parent->color = MAP_RED;
                __map_rotate_left(map, z->parent->parent);
            }
        }
    }
    map->root->color = MAP_BLACK;
}

static void __map_transplant(map_t* map, map_node_t* u, map_node_t* v) {
    if (u->parent == map->nil)
        map->root = v;
    else if (u == u->parent->left)
        u->parent->left = v;
    else
        u->parent->right = v;
    v->parent = u->parent;
}

static void __map_delete_fixup(map_t* map, map_node_t* x) {
    while (x != map->root && x->color == MAP_BLACK) {
        if (x == x->parent->left) {
            map_node_t* w = x->parent->right;
            if (w->color == MAP_RED) {
                w->color = MAP_BLACK;
                x->parent->color = MAP_RED;
                __map_rotate_left(map, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == MAP_BLACK && w->right->color == MAP_BLACK) {
                w->color = MAP_RED;
                x = x->parent;
            } else {
                if (w->right->color == MAP_BLACK) {
                    w->left->color = MAP_BLACK;
                    w->color = MAP_RED;
                    __map_rotate_right(map, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = MAP_BLACK;
                w->right->color = MAP_BLACK;
                __map_rotate_left(map, x->parent);
                x = map->root;
            }
        } else {
            map_node_t* w = x->parent->left;
            if (w->color == MAP_RED) {
                w->color = MAP_BLACK;
                x->parent->color = MAP_RED;
                __map_rotate_right(map, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == MAP_BLACK && w->left->color == MAP_BLACK) {
                w->color = MAP_RED;
                x = x->parent;
            } else {
                if (w->left->color == MAP_BLACK) {
                    w->right->color = MAP_BLACK;
                    w->color = MAP_RED;
                    __map_rotate_left(map, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = MAP_BLACK;
                w->left->color = MAP_BLACK;
                __map_rotate_right(map, x->parent);
                x = map->root;
            }
        }
    }
    x->color = MAP_BLACK;
}

static map_node_t* __map_minimum(map_t* map, map_node_t* node) {
    while (node->left != map->nil)
        node = node->left;
    return node;
}

static map_node_t* __map_maximum(map_t* map, map_node_t* node) {
    while (node->right != map->nil)
        node = node->right;
    return node;
}

static map_node_t* __map_successor(map_t* map, map_node_t* node) {
    if (node->right != map->nil)
        return __map_minimum(map, node->right);

    map_node_t* y = node->parent;
    while (y != map->nil && node == y->right) {
        node = y;
        y = y->parent;
    }
    return y;
}

static map_node_t* __map_predecessor(map_t* map, map_node_t* node) {
    if (node->left != map->nil)
        return __map_maximum(map, node->left);

    map_node_t* y = node->parent;
    while (y != map->nil && node == y->left) {
        node = y;
        y = y->parent;
    }
    return y;
}

static void __map_clear_recursive(map_t* map, map_node_t* node) {
    if (node == map->nil)
        return;

    __map_clear_recursive(map, node->left);
    __map_clear_recursive(map, node->right);
    __map_free_node(map, node);
}
