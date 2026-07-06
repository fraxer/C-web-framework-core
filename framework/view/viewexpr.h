#ifndef __VIEWEXPR__
#define __VIEWEXPR__

#include <stddef.h>

#include "json.h"

#define VIEWEXPR_MAX_DEPTH 32

typedef enum viewexpr_valuetype {
    VIEWEXPR_NULL = 0,
    VIEWEXPR_BOOL,
    VIEWEXPR_NUMBER,
    VIEWEXPR_STRING,
    VIEWEXPR_TOKEN
} viewexpr_valuetype_e;

typedef struct viewexpr_value {
    viewexpr_valuetype_e type;
    int boolean;
    long double number;
    const char* string;         // borrowed: json document, AST literal or loop key
    const json_token_t* token;  // JSON_OBJECT or JSON_ARRAY
} viewexpr_value_t;

typedef enum viewexpr_nodetype {
    VIEWEXPR_NODE_LITERAL = 0,
    VIEWEXPR_NODE_VARIABLE,
    VIEWEXPR_NODE_UNARY,
    VIEWEXPR_NODE_BINARY
} viewexpr_nodetype_e;

typedef enum viewexpr_op {
    VIEWEXPR_OP_NONE = 0,
    VIEWEXPR_OP_NOT,
    VIEWEXPR_OP_NEG,
    VIEWEXPR_OP_OR,
    VIEWEXPR_OP_AND,
    VIEWEXPR_OP_EQ,
    VIEWEXPR_OP_NE,
    VIEWEXPR_OP_LT,
    VIEWEXPR_OP_LE,
    VIEWEXPR_OP_GT,
    VIEWEXPR_OP_GE,
    VIEWEXPR_OP_ADD,
    VIEWEXPR_OP_SUB,
    VIEWEXPR_OP_MUL,
    VIEWEXPR_OP_DIV,
    VIEWEXPR_OP_MOD
} viewexpr_op_e;

typedef struct viewexpr_segment {
    char* name;                    // .name segment; NULL for an [index] segment
    struct viewexpr_node* index;   // [index] segment; NULL for a .name segment
    struct viewexpr_segment* next;
} viewexpr_segment_t;

typedef struct viewexpr_node {
    viewexpr_nodetype_e type;
    viewexpr_op_e op;           // unary and binary nodes
    viewexpr_value_t literal;   // literal nodes; literal.string is owned by the node
    viewexpr_segment_t* path;   // variable nodes
    struct viewexpr_node* left; // unary operand and binary left operand
    struct viewexpr_node* right;
} viewexpr_node_t;

// Resolves the leading identifier of a variable path to a value.
typedef struct viewexpr_scope {
    viewexpr_value_t (*resolve)(const struct viewexpr_scope* scope, const char* name);
    void* data;
} viewexpr_scope_t;

viewexpr_node_t* viewexpr_parse(const char* expression, size_t length);
void viewexpr_node_free(viewexpr_node_t* node);

viewexpr_value_t viewexpr_eval(const viewexpr_node_t* node, const viewexpr_scope_t* scope);
viewexpr_value_t viewexpr_value_from_token(const json_token_t* token);
int viewexpr_value_istrue(const viewexpr_value_t* value);
size_t viewexpr_number_format(long double value, char* buffer, size_t buffer_size);

#endif
