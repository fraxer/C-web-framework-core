#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "numlocale.h"
#include "viewexpr.h"
#include "viewmodifier.h"

#define VIEWEXPR_NUMBER_MAX_LENGTH 64

typedef enum viewexpr_tokentype {
    VIEWEXPR_T_ERROR = 0,
    VIEWEXPR_T_END,
    VIEWEXPR_T_NUMBER,
    VIEWEXPR_T_STRING,
    VIEWEXPR_T_IDENT,
    VIEWEXPR_T_TRUE,
    VIEWEXPR_T_FALSE,
    VIEWEXPR_T_NULL,
    VIEWEXPR_T_OR,
    VIEWEXPR_T_AND,
    VIEWEXPR_T_EQ,
    VIEWEXPR_T_NE,
    VIEWEXPR_T_LT,
    VIEWEXPR_T_LE,
    VIEWEXPR_T_GT,
    VIEWEXPR_T_GE,
    VIEWEXPR_T_PLUS,
    VIEWEXPR_T_MINUS,
    VIEWEXPR_T_STAR,
    VIEWEXPR_T_SLASH,
    VIEWEXPR_T_PERCENT,
    VIEWEXPR_T_NOT,
    VIEWEXPR_T_LPAREN,
    VIEWEXPR_T_RPAREN,
    VIEWEXPR_T_LBRACKET,
    VIEWEXPR_T_RBRACKET,
    VIEWEXPR_T_DOT,
    VIEWEXPR_T_PIPE,
    VIEWEXPR_T_COMMA
} viewexpr_tokentype_e;

typedef struct viewexpr_lextoken {
    viewexpr_tokentype_e type;
    const char* start;  // identifier slice in the source expression
    size_t length;
    long double number;
    char* string;       // owned decoded string literal
} viewexpr_lextoken_t;

typedef struct viewexpr_lexer {
    const char* pos;
    const char* end;
    viewexpr_lextoken_t token;
} viewexpr_lexer_t;

typedef struct viewexpr_parser {
    viewexpr_lexer_t lexer;
    size_t nodes; // operands and modifiers parsed so far
} viewexpr_parser_t;

static void __viewexpr_lexer_next(viewexpr_lexer_t* lexer);
static viewexpr_node_t* __viewexpr_parse_or(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_and(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_equality(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_relational(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_additive(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_multiplicative(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_unary(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_postfix(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_primary(viewexpr_parser_t* parser, int depth);
static viewexpr_node_t* __viewexpr_parse_variable(viewexpr_parser_t* parser, int depth);
static int __viewexpr_parse_segments(viewexpr_parser_t* parser, viewexpr_segment_t** head, viewexpr_segment_t** last, int depth);
static viewexpr_value_t __viewexpr_eval_node(const viewexpr_node_t* node, const viewexpr_scope_t* scope);
static size_t __viewexpr_number_format(long double value, char* buffer, size_t buffer_size);

static int __viewexpr_isspace(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v';
}

static int __viewexpr_isdigit(char ch) {
    return ch >= '0' && ch <= '9';
}

static int __viewexpr_ident_start(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}

static int __viewexpr_ident_char(char ch) {
    return __viewexpr_ident_start(ch) || __viewexpr_isdigit(ch);
}

/**
 * Reads the next token from the expression into lexer->token.
 * On lexical errors the token type is VIEWEXPR_T_ERROR.
 *
 * @param lexer The expression lexer.
 * @return void
 */
void __viewexpr_lexer_next(viewexpr_lexer_t* lexer) {
    if (lexer->token.string != NULL) {
        free(lexer->token.string);
        lexer->token.string = NULL;
    }

    lexer->token.type = VIEWEXPR_T_ERROR;
    lexer->token.start = NULL;
    lexer->token.length = 0;
    lexer->token.number = 0;

    while (lexer->pos < lexer->end && __viewexpr_isspace(*lexer->pos))
        lexer->pos++;

    if (lexer->pos >= lexer->end) {
        lexer->token.type = VIEWEXPR_T_END;
        return;
    }

    const char ch = *lexer->pos;

    if (__viewexpr_ident_start(ch)) {
        const char* start = lexer->pos;
        while (lexer->pos < lexer->end && __viewexpr_ident_char(*lexer->pos))
            lexer->pos++;

        const size_t length = (size_t)(lexer->pos - start);
        lexer->token.start = start;
        lexer->token.length = length;

        if (length == 4 && strncmp(start, "true", 4) == 0)
            lexer->token.type = VIEWEXPR_T_TRUE;
        else if (length == 5 && strncmp(start, "false", 5) == 0)
            lexer->token.type = VIEWEXPR_T_FALSE;
        else if (length == 4 && strncmp(start, "null", 4) == 0)
            lexer->token.type = VIEWEXPR_T_NULL;
        else
            lexer->token.type = VIEWEXPR_T_IDENT;

        return;
    }

    if (__viewexpr_isdigit(ch)) {
        const char* start = lexer->pos;

        while (lexer->pos < lexer->end && __viewexpr_isdigit(*lexer->pos))
            lexer->pos++;

        if (lexer->pos < lexer->end && *lexer->pos == '.') {
            lexer->pos++;
            if (lexer->pos >= lexer->end || !__viewexpr_isdigit(*lexer->pos)) {
                log_error("__viewexpr_lexer_next: digit expected after decimal point\n");
                return;
            }
            while (lexer->pos < lexer->end && __viewexpr_isdigit(*lexer->pos))
                lexer->pos++;
        }

        if (lexer->pos < lexer->end && (*lexer->pos == 'e' || *lexer->pos == 'E')) {
            lexer->pos++;
            if (lexer->pos < lexer->end && (*lexer->pos == '+' || *lexer->pos == '-'))
                lexer->pos++;
            if (lexer->pos >= lexer->end || !__viewexpr_isdigit(*lexer->pos)) {
                log_error("__viewexpr_lexer_next: digit expected in exponent\n");
                return;
            }
            while (lexer->pos < lexer->end && __viewexpr_isdigit(*lexer->pos))
                lexer->pos++;
        }

        // "1x" is a malformed number, not a number followed by an identifier
        if (lexer->pos < lexer->end && __viewexpr_ident_char(*lexer->pos)) {
            log_error("__viewexpr_lexer_next: malformed number\n");
            return;
        }

        const size_t length = (size_t)(lexer->pos - start);
        if (length >= VIEWEXPR_NUMBER_MAX_LENGTH) {
            log_error("__viewexpr_lexer_next: number literal is too long\n");
            return;
        }

        char buffer[VIEWEXPR_NUMBER_MAX_LENGTH];
        memcpy(buffer, start, length);
        buffer[length] = 0;

        const locale_t previous = uselocale(numeric_locale());
        lexer->token.number = strtold(buffer, NULL);
        uselocale(previous);
        lexer->token.type = VIEWEXPR_T_NUMBER;

        return;
    }

    if (ch == '\'' || ch == '"') {
        const char quote = ch;
        lexer->pos++;

        // the decoded string can only shrink relative to the source
        char* string = malloc((size_t)(lexer->end - lexer->pos) + 1);
        if (string == NULL) {
            log_error("__viewexpr_lexer_next: malloc failed\n");
            return;
        }

        size_t length = 0;
        while (lexer->pos < lexer->end && *lexer->pos != quote) {
            char decoded = *lexer->pos++;
            if (decoded == '\\' && lexer->pos < lexer->end) {
                decoded = *lexer->pos++;
                if (decoded == 'n') decoded = '\n';
                else if (decoded == 't') decoded = '\t';
                else if (decoded == 'r') decoded = '\r';
                // \\ \' \" and anything else decode to the char itself
            }

            string[length++] = decoded;
        }

        if (lexer->pos >= lexer->end) {
            log_error("__viewexpr_lexer_next: unterminated string literal\n");
            free(string);
            return;
        }

        lexer->pos++; // closing quote
        string[length] = 0;

        lexer->token.string = string;
        lexer->token.length = length;
        lexer->token.type = VIEWEXPR_T_STRING;

        return;
    }

    lexer->pos++;

    const char next = lexer->pos < lexer->end ? *lexer->pos : 0;

    switch (ch)
    {
    case '(': lexer->token.type = VIEWEXPR_T_LPAREN; return;
    case ')': lexer->token.type = VIEWEXPR_T_RPAREN; return;
    case '[': lexer->token.type = VIEWEXPR_T_LBRACKET; return;
    case ']': lexer->token.type = VIEWEXPR_T_RBRACKET; return;
    case '.': lexer->token.type = VIEWEXPR_T_DOT; return;
    case ',': lexer->token.type = VIEWEXPR_T_COMMA; return;
    case '+': lexer->token.type = VIEWEXPR_T_PLUS; return;
    case '-': lexer->token.type = VIEWEXPR_T_MINUS; return;
    case '*': lexer->token.type = VIEWEXPR_T_STAR; return;
    case '/': lexer->token.type = VIEWEXPR_T_SLASH; return;
    case '%': lexer->token.type = VIEWEXPR_T_PERCENT; return;
    case '!':
        if (next == '=') {
            lexer->pos++;
            lexer->token.type = VIEWEXPR_T_NE;
        }
        else
            lexer->token.type = VIEWEXPR_T_NOT;
        return;
    case '=':
        if (next == '=') {
            lexer->pos++;
            lexer->token.type = VIEWEXPR_T_EQ;
            return;
        }
        log_error("__viewexpr_lexer_next: '=' is not an operator, use '=='\n");
        return;
    case '<':
        if (next == '=') {
            lexer->pos++;
            lexer->token.type = VIEWEXPR_T_LE;
        }
        else
            lexer->token.type = VIEWEXPR_T_LT;
        return;
    case '>':
        if (next == '=') {
            lexer->pos++;
            lexer->token.type = VIEWEXPR_T_GE;
        }
        else
            lexer->token.type = VIEWEXPR_T_GT;
        return;
    case '&':
        if (next == '&') {
            lexer->pos++;
            lexer->token.type = VIEWEXPR_T_AND;
            return;
        }
        log_error("__viewexpr_lexer_next: '&' is not an operator, use '&&'\n");
        return;
    case '|':
        if (next == '|') {
            lexer->pos++;
            lexer->token.type = VIEWEXPR_T_OR;
        }
        else
            lexer->token.type = VIEWEXPR_T_PIPE;
        return;
    default:
        log_error("__viewexpr_lexer_next: unexpected character in expression\n");
        return;
    }
}

/**
 * Creates an expression AST node.
 *
 * @param type The node type.
 * @param op The node operator (VIEWEXPR_OP_NONE for literals and variables).
 * @return The created node, or NULL if memory allocation failed.
 */
static viewexpr_node_t* __viewexpr_node_create(viewexpr_nodetype_e type, viewexpr_op_e op) {
    viewexpr_node_t* node = malloc(sizeof * node);
    if (node == NULL) {
        log_error("__viewexpr_node_create: malloc failed\n");
        return NULL;
    }

    node->type = type;
    node->op = op;
    node->literal.type = VIEWEXPR_NULL;
    node->literal.boolean = 0;
    node->literal.number = 0;
    node->literal.string = NULL;
    node->literal.length = 0;
    node->literal.token = NULL;
    node->path = NULL;
    node->left = NULL;
    node->right = NULL;
    node->modifier = NULL;
    node->argc = 0;
    for (size_t i = 0; i < VIEWEXPR_MAX_ARGS; i++)
        node->args[i] = NULL;

    return node;
}

/**
 * Wraps two operands into a binary node.
 * On any failure both operands are freed.
 *
 * @param op The binary operator.
 * @param left The left operand.
 * @param right The right operand (may be NULL to signal a failed parse).
 * @return The binary node, or NULL on failure.
 */
static viewexpr_node_t* __viewexpr_binary_wrap(viewexpr_op_e op, viewexpr_node_t* left, viewexpr_node_t* right) {
    if (right == NULL) {
        viewexpr_node_free(left);
        return NULL;
    }

    viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_BINARY, op);
    if (node == NULL) {
        viewexpr_node_free(left);
        viewexpr_node_free(right);
        return NULL;
    }

    node->left = left;
    node->right = right;

    return node;
}

/**
 * Frees a variable path segment list.
 *
 * @param segment The first segment of the list.
 * @return void
 */
static void __viewexpr_segments_free(viewexpr_segment_t* segment) {
    while (segment != NULL) {
        viewexpr_segment_t* next = segment->next;
        free(segment->name);
        viewexpr_node_free(segment->index);
        free(segment);
        segment = next;
    }
}

/**
 * Frees an expression AST.
 *
 * @param node The AST root.
 * @return void
 */
void viewexpr_node_free(viewexpr_node_t* node) {
    if (node == NULL) return;

    if (node->literal.type == VIEWEXPR_STRING)
        free((char*)node->literal.string);

    __viewexpr_segments_free(node->path);
    viewexpr_node_free(node->left);
    viewexpr_node_free(node->right);

    for (size_t i = 0; i < node->argc; i++)
        viewexpr_node_free(node->args[i]);

    free(node);
}

/**
 * Creates a variable path segment.
 *
 * @param name The field name slice, or NULL for an index segment.
 * @param length The field name length.
 * @param index The index expression, or NULL for a name segment.
 * @return The created segment, or NULL if memory allocation failed.
 */
static viewexpr_segment_t* __viewexpr_segment_create(const char* name, size_t length, viewexpr_node_t* index) {
    viewexpr_segment_t* segment = malloc(sizeof * segment);
    if (segment == NULL) {
        log_error("__viewexpr_segment_create: malloc failed\n");
        return NULL;
    }

    segment->name = NULL;
    segment->index = index;
    segment->next = NULL;

    if (name != NULL) {
        segment->name = malloc(length + 1);
        if (segment->name == NULL) {
            log_error("__viewexpr_segment_create: malloc failed\n");
            free(segment);
            return NULL;
        }

        memcpy(segment->name, name, length);
        segment->name[length] = 0;
    }

    return segment;
}

/*
 * Recursive descent grammar:
 *
 *   expression     := or
 *   or             := and ( '||' and )*
 *   and            := equality ( '&&' equality )*
 *   equality       := relational ( ( '==' | '!=' ) relational )*
 *   relational     := additive ( ( '<' | '<=' | '>' | '>=' ) additive )*
 *   additive       := multiplicative ( ( '+' | '-' ) multiplicative )*
 *   multiplicative := unary ( ( '*' | '/' | '%' ) unary )*
 *   unary          := ( '!' | '-' ) unary | postfix
 *   postfix        := primary ( '|' modifier | '.' IDENT | '[' expression ']' )*
 *   modifier       := IDENT [ '(' [ expression ( ',' expression )* ] ')' ]
 *   primary        := literal | variable | '(' expression ')'
 *   variable       := IDENT ( '.' IDENT | '[' expression ']' )*
 */

viewexpr_node_t* __viewexpr_parse_or(viewexpr_parser_t* parser, int depth) {
    if (depth > VIEWEXPR_MAX_DEPTH) {
        log_error("__viewexpr_parse_or: expression is too deep\n");
        return NULL;
    }

    viewexpr_node_t* left = __viewexpr_parse_and(parser, depth);

    while (left != NULL && parser->lexer.token.type == VIEWEXPR_T_OR) {
        __viewexpr_lexer_next(&parser->lexer);
        left = __viewexpr_binary_wrap(VIEWEXPR_OP_OR, left, __viewexpr_parse_and(parser, depth));
    }

    return left;
}

viewexpr_node_t* __viewexpr_parse_and(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* left = __viewexpr_parse_equality(parser, depth);

    while (left != NULL && parser->lexer.token.type == VIEWEXPR_T_AND) {
        __viewexpr_lexer_next(&parser->lexer);
        left = __viewexpr_binary_wrap(VIEWEXPR_OP_AND, left, __viewexpr_parse_equality(parser, depth));
    }

    return left;
}

viewexpr_node_t* __viewexpr_parse_equality(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* left = __viewexpr_parse_relational(parser, depth);

    while (left != NULL) {
        viewexpr_op_e op;
        switch (parser->lexer.token.type)
        {
        case VIEWEXPR_T_EQ: op = VIEWEXPR_OP_EQ; break;
        case VIEWEXPR_T_NE: op = VIEWEXPR_OP_NE; break;
        default: return left;
        }

        __viewexpr_lexer_next(&parser->lexer);
        left = __viewexpr_binary_wrap(op, left, __viewexpr_parse_relational(parser, depth));
    }

    return left;
}

viewexpr_node_t* __viewexpr_parse_relational(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* left = __viewexpr_parse_additive(parser, depth);

    while (left != NULL) {
        viewexpr_op_e op;
        switch (parser->lexer.token.type)
        {
        case VIEWEXPR_T_LT: op = VIEWEXPR_OP_LT; break;
        case VIEWEXPR_T_LE: op = VIEWEXPR_OP_LE; break;
        case VIEWEXPR_T_GT: op = VIEWEXPR_OP_GT; break;
        case VIEWEXPR_T_GE: op = VIEWEXPR_OP_GE; break;
        default: return left;
        }

        __viewexpr_lexer_next(&parser->lexer);
        left = __viewexpr_binary_wrap(op, left, __viewexpr_parse_additive(parser, depth));
    }

    return left;
}

viewexpr_node_t* __viewexpr_parse_additive(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* left = __viewexpr_parse_multiplicative(parser, depth);

    while (left != NULL) {
        viewexpr_op_e op;
        switch (parser->lexer.token.type)
        {
        case VIEWEXPR_T_PLUS: op = VIEWEXPR_OP_ADD; break;
        case VIEWEXPR_T_MINUS: op = VIEWEXPR_OP_SUB; break;
        default: return left;
        }

        __viewexpr_lexer_next(&parser->lexer);
        left = __viewexpr_binary_wrap(op, left, __viewexpr_parse_multiplicative(parser, depth));
    }

    return left;
}

viewexpr_node_t* __viewexpr_parse_multiplicative(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* left = __viewexpr_parse_unary(parser, depth);

    while (left != NULL) {
        viewexpr_op_e op;
        switch (parser->lexer.token.type)
        {
        case VIEWEXPR_T_STAR: op = VIEWEXPR_OP_MUL; break;
        case VIEWEXPR_T_SLASH: op = VIEWEXPR_OP_DIV; break;
        case VIEWEXPR_T_PERCENT: op = VIEWEXPR_OP_MOD; break;
        default: return left;
        }

        __viewexpr_lexer_next(&parser->lexer);
        left = __viewexpr_binary_wrap(op, left, __viewexpr_parse_unary(parser, depth));
    }

    return left;
}

/**
 * Counts one more operand or modifier against VIEWEXPR_MAX_NODES. Depth
 * alone does not bound a flat chain (a + a + ..., a | lower | lower ...),
 * and every later pass over the tree recurses through it.
 *
 * @param parser The parser.
 * @return 1 if the expression is still within the limit, 0 otherwise.
 */
static int __viewexpr_count_node(viewexpr_parser_t* parser) {
    if (++parser->nodes <= VIEWEXPR_MAX_NODES) return 1;

    log_error("__viewexpr_count_node: expression has too many operands\n");
    return 0;
}

viewexpr_node_t* __viewexpr_parse_unary(viewexpr_parser_t* parser, int depth) {
    if (depth > VIEWEXPR_MAX_DEPTH) {
        log_error("__viewexpr_parse_unary: expression is too deep\n");
        return NULL;
    }

    if (!__viewexpr_count_node(parser)) return NULL;

    const viewexpr_tokentype_e type = parser->lexer.token.type;
    if (type != VIEWEXPR_T_NOT && type != VIEWEXPR_T_MINUS)
        return __viewexpr_parse_postfix(parser, depth);

    __viewexpr_lexer_next(&parser->lexer);

    viewexpr_node_t* operand = __viewexpr_parse_unary(parser, depth + 1);
    if (operand == NULL) return NULL;

    viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_UNARY,
        type == VIEWEXPR_T_NOT ? VIEWEXPR_OP_NOT : VIEWEXPR_OP_NEG);
    if (node == NULL) {
        viewexpr_node_free(operand);
        return NULL;
    }

    node->left = operand;

    return node;
}

/**
 * Parses the arguments of a modifier after its '(' into the node.
 *
 * @param parser The parser, positioned after '('.
 * @param node The modifier node.
 * @param depth The current depth.
 * @return 1 on success (')' consumed), 0 otherwise.
 */
static int __viewexpr_parse_modifier_args(viewexpr_parser_t* parser, viewexpr_node_t* node, int depth) {
    if (parser->lexer.token.type == VIEWEXPR_T_RPAREN) {
        __viewexpr_lexer_next(&parser->lexer);
        return 1;
    }

    for (;;) {
        if (node->argc >= VIEWEXPR_MAX_ARGS) {
            log_error("__viewexpr_parse_modifier_args: too many arguments\n");
            return 0;
        }

        viewexpr_node_t* arg = __viewexpr_parse_or(parser, depth + 1);
        if (arg == NULL) return 0;

        node->args[node->argc++] = arg;

        if (parser->lexer.token.type == VIEWEXPR_T_COMMA) {
            __viewexpr_lexer_next(&parser->lexer);
            continue;
        }

        if (parser->lexer.token.type != VIEWEXPR_T_RPAREN) {
            log_error("__viewexpr_parse_modifier_args: ')' expected\n");
            return 0;
        }

        __viewexpr_lexer_next(&parser->lexer);
        return 1;
    }
}

/**
 * Wraps an operand into a path node with the segments that follow it:
 * `(expr).field`, `x | first.name`.
 *
 * @param parser The parser, at '.' or '['.
 * @param operand The operand (freed on failure).
 * @param depth The current depth.
 * @return The path node, or NULL on failure.
 */
static viewexpr_node_t* __viewexpr_parse_path(viewexpr_parser_t* parser, viewexpr_node_t* operand, int depth) {
    viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_PATH, VIEWEXPR_OP_NONE);
    if (node == NULL) {
        viewexpr_node_free(operand);
        return NULL;
    }

    node->left = operand;

    viewexpr_segment_t* last = NULL;
    if (!__viewexpr_parse_segments(parser, &node->path, &last, depth)) {
        viewexpr_node_free(node);
        return NULL;
    }

    return node;
}

viewexpr_node_t* __viewexpr_parse_postfix(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* operand = __viewexpr_parse_primary(parser, depth);

    for (;;) {
        if (operand == NULL) return NULL;

        const viewexpr_tokentype_e type = parser->lexer.token.type;
        if (type == VIEWEXPR_T_DOT || type == VIEWEXPR_T_LBRACKET) {
            operand = __viewexpr_parse_path(parser, operand, depth);
            continue;
        }

        if (type != VIEWEXPR_T_PIPE) break;

        if (!__viewexpr_count_node(parser)) {
            viewexpr_node_free(operand);
            return NULL;
        }

        __viewexpr_lexer_next(&parser->lexer);

        if (parser->lexer.token.type != VIEWEXPR_T_IDENT) {
            log_error("__viewexpr_parse_postfix: modifier name expected after '|'\n");
            viewexpr_node_free(operand);
            return NULL;
        }

        const viewmodifier_t* modifier = viewmodifier_find(parser->lexer.token.start, parser->lexer.token.length);
        if (modifier == NULL) {
            log_error("__viewexpr_parse_postfix: unknown modifier '%.*s'\n",
                (int)parser->lexer.token.length, parser->lexer.token.start);
            viewexpr_node_free(operand);
            return NULL;
        }

        viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_MODIFIER, VIEWEXPR_OP_NONE);
        if (node == NULL) {
            viewexpr_node_free(operand);
            return NULL;
        }

        node->modifier = modifier;
        node->left = operand;
        operand = node;

        __viewexpr_lexer_next(&parser->lexer);

        if (parser->lexer.token.type == VIEWEXPR_T_LPAREN) {
            __viewexpr_lexer_next(&parser->lexer);

            if (!__viewexpr_parse_modifier_args(parser, node, depth)) {
                viewexpr_node_free(node);
                return NULL;
            }
        }

        if (node->argc < modifier->min_args || node->argc > modifier->max_args) {
            log_error("__viewexpr_parse_postfix: modifier '%s' takes %u to %u arguments\n",
                modifier->name, (unsigned)modifier->min_args, (unsigned)modifier->max_args);
            viewexpr_node_free(node);
            return NULL;
        }
    }

    return operand;
}

viewexpr_node_t* __viewexpr_parse_primary(viewexpr_parser_t* parser, int depth) {
    viewexpr_lextoken_t* token = &parser->lexer.token;

    switch (token->type)
    {
    case VIEWEXPR_T_NUMBER:
    {
        viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_LITERAL, VIEWEXPR_OP_NONE);
        if (node == NULL) return NULL;

        node->literal.type = VIEWEXPR_NUMBER;
        node->literal.number = token->number;

        __viewexpr_lexer_next(&parser->lexer);

        return node;
    }
    case VIEWEXPR_T_STRING:
    {
        viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_LITERAL, VIEWEXPR_OP_NONE);
        if (node == NULL) return NULL;

        node->literal.type = VIEWEXPR_STRING;
        node->literal.string = token->string;
        node->literal.length = token->length;
        token->string = NULL; // ownership moved to the node

        __viewexpr_lexer_next(&parser->lexer);

        return node;
    }
    case VIEWEXPR_T_TRUE:
    case VIEWEXPR_T_FALSE:
    {
        viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_LITERAL, VIEWEXPR_OP_NONE);
        if (node == NULL) return NULL;

        node->literal.type = VIEWEXPR_BOOL;
        node->literal.boolean = token->type == VIEWEXPR_T_TRUE;

        __viewexpr_lexer_next(&parser->lexer);

        return node;
    }
    case VIEWEXPR_T_NULL:
    {
        viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_LITERAL, VIEWEXPR_OP_NONE);
        if (node == NULL) return NULL;

        __viewexpr_lexer_next(&parser->lexer);

        return node;
    }
    case VIEWEXPR_T_IDENT:
        return __viewexpr_parse_variable(parser, depth);
    case VIEWEXPR_T_LPAREN:
    {
        __viewexpr_lexer_next(&parser->lexer);

        viewexpr_node_t* node = __viewexpr_parse_or(parser, depth + 1);
        if (node == NULL) return NULL;

        if (parser->lexer.token.type != VIEWEXPR_T_RPAREN) {
            log_error("__viewexpr_parse_primary: ')' expected\n");
            viewexpr_node_free(node);
            return NULL;
        }

        __viewexpr_lexer_next(&parser->lexer);

        return node;
    }
    default:
        log_error("__viewexpr_parse_primary: operand expected\n");
        return NULL;
    }
}

/**
 * Parses `.name` and `[index]` segments while they follow, appending them to
 * the list whose last element is *last (*head when the list is empty).
 *
 * @param parser The parser.
 * @param head The list head.
 * @param last The last element, updated as segments are appended.
 * @param depth The current depth.
 * @return 1 on success, 0 on a malformed segment (the list stays owned by the caller).
 */
static int __viewexpr_parse_segments(viewexpr_parser_t* parser, viewexpr_segment_t** head, viewexpr_segment_t** last, int depth) {
    for (;;) {
        viewexpr_segment_t* segment = NULL;

        if (parser->lexer.token.type == VIEWEXPR_T_DOT) {
            __viewexpr_lexer_next(&parser->lexer);

            if (parser->lexer.token.type != VIEWEXPR_T_IDENT) {
                log_error("__viewexpr_parse_segments: field name expected after '.'\n");
                return 0;
            }

            segment = __viewexpr_segment_create(parser->lexer.token.start, parser->lexer.token.length, NULL);
            if (segment == NULL) return 0;

            __viewexpr_lexer_next(&parser->lexer);
        }
        else if (parser->lexer.token.type == VIEWEXPR_T_LBRACKET) {
            __viewexpr_lexer_next(&parser->lexer);

            viewexpr_node_t* index = __viewexpr_parse_or(parser, depth + 1);
            if (index == NULL) return 0;

            if (parser->lexer.token.type != VIEWEXPR_T_RBRACKET) {
                log_error("__viewexpr_parse_segments: ']' expected\n");
                viewexpr_node_free(index);
                return 0;
            }

            __viewexpr_lexer_next(&parser->lexer);

            segment = __viewexpr_segment_create(NULL, 0, index);
            if (segment == NULL) {
                viewexpr_node_free(index);
                return 0;
            }
        }
        else
            return 1;

        if (*last == NULL) *head = segment;
        else (*last)->next = segment;
        *last = segment;
    }
}

viewexpr_node_t* __viewexpr_parse_variable(viewexpr_parser_t* parser, int depth) {
    viewexpr_node_t* node = __viewexpr_node_create(VIEWEXPR_NODE_VARIABLE, VIEWEXPR_OP_NONE);
    if (node == NULL) return NULL;

    viewexpr_segment_t* last = __viewexpr_segment_create(parser->lexer.token.start, parser->lexer.token.length, NULL);
    if (last == NULL) {
        viewexpr_node_free(node);
        return NULL;
    }

    node->path = last;

    __viewexpr_lexer_next(&parser->lexer);

    if (!__viewexpr_parse_segments(parser, &node->path, &last, depth)) {
        viewexpr_node_free(node);
        return NULL;
    }

    return node;
}

/**
 * Checks where output modifiers (raw, nl2br) stand: they decide how the whole
 * {{ }} tag is written, so only the root of an output expression may be one.
 *
 * @param node The node to check.
 * @param is_root Non-zero for the root of the expression.
 * @param allow_output Non-zero for a {{ }} tag expression.
 * @return 1 if the tree is valid, 0 otherwise.
 */
static int __viewexpr_check_output(const viewexpr_node_t* node, int is_root, int allow_output) {
    if (node == NULL) return 1;

    if (node->type == VIEWEXPR_NODE_MODIFIER && node->modifier->kind != VIEWMOD_VALUE) {
        if (!is_root || !allow_output) {
            log_error("__viewexpr_check_output: '%s' is allowed only last at the root of a {{ }} tag\n",
                node->modifier->name);
            return 0;
        }
    }

    if (!__viewexpr_check_output(node->left, 0, allow_output)) return 0;
    if (!__viewexpr_check_output(node->right, 0, allow_output)) return 0;

    for (size_t i = 0; i < node->argc; i++)
        if (!__viewexpr_check_output(node->args[i], 0, allow_output)) return 0;

    for (const viewexpr_segment_t* segment = node->path; segment != NULL; segment = segment->next)
        if (!__viewexpr_check_output(segment->index, 0, allow_output)) return 0;

    return 1;
}

/**
 * Parses an expression into an AST using recursive descent.
 *
 * @param expression The expression text (does not need to be NUL-terminated).
 * @param length The expression length in bytes.
 * @param allow_output Non-zero to allow raw/nl2br at the root.
 * @return The AST root, or NULL if the expression is empty or malformed.
 */
static viewexpr_node_t* __viewexpr_parse_entry(const char* expression, size_t length, int allow_output) {
    if (expression == NULL || length == 0) return NULL;

    viewexpr_parser_t parser;
    parser.lexer.pos = expression;
    parser.lexer.end = expression + length;
    parser.lexer.token.type = VIEWEXPR_T_END;
    parser.lexer.token.start = NULL;
    parser.lexer.token.length = 0;
    parser.lexer.token.number = 0;
    parser.lexer.token.string = NULL;
    parser.nodes = 0;

    __viewexpr_lexer_next(&parser.lexer);

    viewexpr_node_t* node = __viewexpr_parse_or(&parser, 0);
    if (node != NULL && parser.lexer.token.type != VIEWEXPR_T_END) {
        log_error("viewexpr_parse: unexpected token after expression\n");
        viewexpr_node_free(node);
        node = NULL;
    }

    // a string literal left in the lexer on a failed parse
    free(parser.lexer.token.string);

    if (node != NULL && !__viewexpr_check_output(node, 1, allow_output)) {
        viewexpr_node_free(node);
        node = NULL;
    }

    return node;
}

/**
 * Parses a condition or loop expression: output modifiers (raw, nl2br) are
 * refused anywhere in it.
 *
 * @param expression The expression text (does not need to be NUL-terminated).
 * @param length The expression length in bytes.
 * @return The AST root, or NULL if the expression is empty or malformed.
 */
viewexpr_node_t* viewexpr_parse(const char* expression, size_t length) {
    return __viewexpr_parse_entry(expression, length, 0);
}

/**
 * Parses the expression of a {{ }} tag: an output modifier (raw, nl2br) is
 * allowed as its root.
 *
 * @param expression The expression text (does not need to be NUL-terminated).
 * @param length The expression length in bytes.
 * @return The AST root, or NULL if the expression is empty or malformed.
 */
viewexpr_node_t* viewexpr_parse_output(const char* expression, size_t length) {
    return __viewexpr_parse_entry(expression, length, 1);
}

static viewexpr_value_t __viewexpr_null_value(void) {
    viewexpr_value_t value;
    value.type = VIEWEXPR_NULL;
    value.boolean = 0;
    value.number = 0;
    value.string = NULL;
    value.length = 0;
    value.token = NULL;
    return value;
}

static viewexpr_value_t __viewexpr_bool_value(int boolean) {
    viewexpr_value_t value = __viewexpr_null_value();
    value.type = VIEWEXPR_BOOL;
    value.boolean = boolean != 0;
    return value;
}

static viewexpr_value_t __viewexpr_number_value(long double number) {
    viewexpr_value_t value = __viewexpr_null_value();
    value.type = VIEWEXPR_NUMBER;
    value.number = number;
    return value;
}

/**
 * Converts a json token to an expression value.
 *
 * @param token The json token (may be NULL).
 * @return The converted value; NULL tokens convert to a null value.
 */
viewexpr_value_t viewexpr_value_from_token(const json_token_t* token) {
    viewexpr_value_t value = __viewexpr_null_value();
    if (token == NULL) return value;

    switch (token->type)
    {
    case JSON_STRING:
        value.type = VIEWEXPR_STRING;
        value.string = json_string(token);
        value.length = json_string_size(token);
        value.token = token;
        break;
    case JSON_NUMBER:
        value.type = VIEWEXPR_NUMBER;
        value.number = json_ldouble(token);
        break;
    case JSON_BOOL:
        value.type = VIEWEXPR_BOOL;
        value.boolean = json_bool(token);
        break;
    case JSON_OBJECT:
    case JSON_ARRAY:
        value.type = VIEWEXPR_TOKEN;
        value.token = token;
        break;
    default:
        break;
    }

    return value;
}

/**
 * Returns the truthiness of a value: false for null, zero, an empty string
 * and an empty object or array.
 *
 * @param value The value.
 * @return 1 if the value is truthy, 0 otherwise.
 */
int viewexpr_value_istrue(const viewexpr_value_t* value) {
    if (value == NULL) return 0;

    switch (value->type)
    {
    case VIEWEXPR_BOOL:
        return value->boolean != 0;
    case VIEWEXPR_NUMBER:
        return !isnan(value->number) && value->number != 0;
    case VIEWEXPR_STRING:
        return value->string != NULL && value->length > 0;
    case VIEWEXPR_TOKEN:
        return value->token != NULL && value->token->size > 0;
    default:
        return 0;
    }
}

/**
 * Orders two strings byte by byte over their lengths (NUL bytes included);
 * a proper prefix is less than the longer string.
 *
 * @return Negative, zero or positive, as memcmp.
 */
static int __viewexpr_string_compare(const viewexpr_value_t* left, const viewexpr_value_t* right) {
    const size_t common = left->length < right->length ? left->length : right->length;

    const int order = common > 0 ? memcmp(left->string, right->string, common) : 0;
    if (order != 0) return order;

    return left->length < right->length ? -1 : left->length > right->length ? 1 : 0;
}

/**
 * Looks a key up in an object by its bytes, NUL bytes included
 * (json_object_get() compares C strings).
 *
 * @return The value token, or NULL.
 */
static const json_token_t* __viewexpr_object_get(const json_token_t* object, const char* key, size_t length) {
    for (json_it_t it = json_init_it(object); !json_end_it(&it); it = json_next_it(&it)) {
        const char* name = json_string(it.key);
        if (name != NULL && json_string_size(it.key) == length && memcmp(name, key, length) == 0)
            return json_it_value(&it);
    }

    return NULL;
}

static int __viewexpr_value_equal(const viewexpr_value_t* left, const viewexpr_value_t* right) {
    if (left->type != right->type) return 0;

    switch (left->type)
    {
    case VIEWEXPR_NULL:
        return 1;
    case VIEWEXPR_BOOL:
        return (left->boolean != 0) == (right->boolean != 0);
    case VIEWEXPR_NUMBER:
        return left->number == right->number;
    case VIEWEXPR_STRING:
        return left->string != NULL && right->string != NULL && __viewexpr_string_compare(left, right) == 0;
    case VIEWEXPR_TOKEN:
        return left->token == right->token;
    default:
        return 0;
    }
}

/**
 * Walks `.name` / `[index]` segments from a value through JSON tokens.
 *
 * @param value The starting value.
 * @param segment The first segment to apply.
 * @param scope The scope for index expressions.
 * @return The value at the end of the path, or null when a step does not exist.
 */
static viewexpr_value_t __viewexpr_walk_segments(viewexpr_value_t value, const viewexpr_segment_t* segment, const viewexpr_scope_t* scope) {
    for (; segment != NULL; segment = segment->next) {
        if (value.type != VIEWEXPR_TOKEN || value.token == NULL)
            return __viewexpr_null_value();

        const json_token_t* token = NULL;

        if (segment->name != NULL) {
            if (value.token->type != JSON_OBJECT)
                return __viewexpr_null_value();

            token = json_object_get(value.token, segment->name);
        }
        else {
            const viewexpr_value_t index = __viewexpr_eval_node(segment->index, scope);

            if (value.token->type == JSON_ARRAY) {
                if (index.type != VIEWEXPR_NUMBER)
                    return __viewexpr_null_value();

                const long double number = index.number;
                if (isnan(number) || isinf(number) || number < 0 || number > (long double)INT_MAX)
                    return __viewexpr_null_value();

                const int position = (int)number;
                if ((long double)position != number)
                    return __viewexpr_null_value();

                token = json_array_get(value.token, position);
            }
            else if (value.token->type == JSON_OBJECT) {
                if (index.type != VIEWEXPR_STRING || index.string == NULL)
                    return __viewexpr_null_value();

                token = __viewexpr_object_get(value.token, index.string, index.length);
            }
        }

        if (token == NULL)
            return __viewexpr_null_value();

        value = viewexpr_value_from_token(token);
    }

    return value;
}

static viewexpr_value_t __viewexpr_eval_variable(const viewexpr_node_t* node, const viewexpr_scope_t* scope) {
    if (scope == NULL || scope->resolve == NULL) return __viewexpr_null_value();

    const viewexpr_segment_t* segment = node->path;
    if (segment == NULL || segment->name == NULL) return __viewexpr_null_value();

    return __viewexpr_walk_segments(scope->resolve(scope, segment->name), segment->next, scope);
}

static viewexpr_value_t __viewexpr_eval_binary(const viewexpr_node_t* node, const viewexpr_scope_t* scope) {
    if (node->op == VIEWEXPR_OP_AND || node->op == VIEWEXPR_OP_OR) {
        const viewexpr_value_t left = __viewexpr_eval_node(node->left, scope);
        const int left_true = viewexpr_value_istrue(&left);

        if (node->op == VIEWEXPR_OP_AND && !left_true) return __viewexpr_bool_value(0);
        if (node->op == VIEWEXPR_OP_OR && left_true) return __viewexpr_bool_value(1);

        const viewexpr_value_t right = __viewexpr_eval_node(node->right, scope);

        return __viewexpr_bool_value(viewexpr_value_istrue(&right));
    }

    const viewexpr_value_t left = __viewexpr_eval_node(node->left, scope);
    const viewexpr_value_t right = __viewexpr_eval_node(node->right, scope);

    switch (node->op)
    {
    case VIEWEXPR_OP_EQ:
        return __viewexpr_bool_value(__viewexpr_value_equal(&left, &right));
    case VIEWEXPR_OP_NE:
        return __viewexpr_bool_value(!__viewexpr_value_equal(&left, &right));
    case VIEWEXPR_OP_LT:
    case VIEWEXPR_OP_LE:
    case VIEWEXPR_OP_GT:
    case VIEWEXPR_OP_GE:
    {
        // numbers compare numerically, strings lexicographically;
        // mixed and unordered types are never in order
        int comparable = 0;
        int less = 0;
        int equal = 0;

        if (left.type == VIEWEXPR_NUMBER && right.type == VIEWEXPR_NUMBER) {
            comparable = !isnan(left.number) && !isnan(right.number);
            less = left.number < right.number;
            equal = left.number == right.number;
        }
        else if (left.type == VIEWEXPR_STRING && right.type == VIEWEXPR_STRING
            && left.string != NULL && right.string != NULL) {
            const int order = __viewexpr_string_compare(&left, &right);
            comparable = 1;
            less = order < 0;
            equal = order == 0;
        }

        if (!comparable) return __viewexpr_bool_value(0);

        switch (node->op)
        {
        case VIEWEXPR_OP_LT: return __viewexpr_bool_value(less);
        case VIEWEXPR_OP_LE: return __viewexpr_bool_value(less || equal);
        case VIEWEXPR_OP_GT: return __viewexpr_bool_value(!less && !equal);
        default: return __viewexpr_bool_value(!less);
        }
    }
    case VIEWEXPR_OP_ADD:
    case VIEWEXPR_OP_SUB:
    case VIEWEXPR_OP_MUL:
    case VIEWEXPR_OP_DIV:
    case VIEWEXPR_OP_MOD:
    {
        if (left.type != VIEWEXPR_NUMBER || right.type != VIEWEXPR_NUMBER)
            return __viewexpr_null_value();

        switch (node->op)
        {
        case VIEWEXPR_OP_ADD: return __viewexpr_number_value(left.number + right.number);
        case VIEWEXPR_OP_SUB: return __viewexpr_number_value(left.number - right.number);
        case VIEWEXPR_OP_MUL: return __viewexpr_number_value(left.number * right.number);
        case VIEWEXPR_OP_DIV:
            if (right.number == 0) return __viewexpr_null_value();
            return __viewexpr_number_value(left.number / right.number);
        default:
            if (right.number == 0) return __viewexpr_null_value();
            return __viewexpr_number_value(fmodl(left.number, right.number));
        }
    }
    default:
        return __viewexpr_null_value();
    }
}

/**
 * Evaluates a modifier node. Kept out of __viewexpr_eval_node so the argument
 * array does not enlarge every frame of the recursion.
 *
 * @param node The modifier node.
 * @param scope The variable scope (may be NULL).
 * @return The modifier result.
 */
static viewexpr_value_t __viewexpr_eval_modifier(const viewexpr_node_t* node, const viewexpr_scope_t* scope) {
    const viewexpr_value_t operand = __viewexpr_eval_node(node->left, scope);

    // raw and nl2br change how the tag is written, not the value
    if (node->modifier->kind != VIEWMOD_VALUE)
        return operand;

    viewexpr_value_t args[VIEWEXPR_MAX_ARGS];
    for (size_t i = 0; i < node->argc; i++)
        args[i] = __viewexpr_eval_node(node->args[i], scope);

    return node->modifier->apply(scope != NULL ? scope->arena : NULL, &operand, args, node->argc);
}

viewexpr_value_t __viewexpr_eval_node(const viewexpr_node_t* node, const viewexpr_scope_t* scope) {
    if (node == NULL) return __viewexpr_null_value();

    switch (node->type)
    {
    case VIEWEXPR_NODE_LITERAL:
        return node->literal;
    case VIEWEXPR_NODE_VARIABLE:
        return __viewexpr_eval_variable(node, scope);
    case VIEWEXPR_NODE_UNARY:
    {
        const viewexpr_value_t operand = __viewexpr_eval_node(node->left, scope);

        if (node->op == VIEWEXPR_OP_NOT)
            return __viewexpr_bool_value(!viewexpr_value_istrue(&operand));

        if (operand.type != VIEWEXPR_NUMBER)
            return __viewexpr_null_value();

        return __viewexpr_number_value(-operand.number);
    }
    case VIEWEXPR_NODE_BINARY:
        return __viewexpr_eval_binary(node, scope);
    case VIEWEXPR_NODE_MODIFIER:
        return __viewexpr_eval_modifier(node, scope);
    case VIEWEXPR_NODE_PATH:
        return __viewexpr_walk_segments(__viewexpr_eval_node(node->left, scope), node->path, scope);
    default:
        return __viewexpr_null_value();
    }
}

/**
 * Evaluates an expression AST.
 *
 * @param node The AST root (may be NULL).
 * @param scope The variable scope (may be NULL, variables evaluate to null).
 * @return The expression value.
 */
viewexpr_value_t viewexpr_eval(const viewexpr_node_t* node, const viewexpr_scope_t* scope) {
    return __viewexpr_eval_node(node, scope);
}

/**
 * Formats a number the way templates should show it: integral values without
 * a fractional part, other values with the shortest representation that
 * parses back to the same number. Always with a decimal point.
 *
 * @param value The number to format.
 * @param buffer The output buffer.
 * @param buffer_size The output buffer size.
 * @return The number of characters written, 0 on failure (buffer is empty).
 */
size_t viewexpr_number_format(long double value, char* buffer, size_t buffer_size) {
    const locale_t previous = uselocale(numeric_locale());
    const size_t written = __viewexpr_number_format(value, buffer, buffer_size);
    uselocale(previous);

    return written;
}

static size_t __viewexpr_number_format(long double value, char* buffer, size_t buffer_size) {
    if (buffer == NULL || buffer_size == 0) return 0;

    buffer[0] = 0;

    if (isnan(value) || isinf(value)) return 0;

    if (value >= -(long double)LLONG_MAX && value <= (long double)LLONG_MAX) {
        const long long integer = (long long)value;
        if ((long double)integer == value) {
            const int written = snprintf(buffer, buffer_size, "%lld", integer);
            if (written < 0 || (size_t)written >= buffer_size) {
                buffer[0] = 0;
                return 0;
            }

            return (size_t)written;
        }
    }

    int written = 0;
    for (int precision = 1; precision <= 17; precision++) {
        written = snprintf(buffer, buffer_size, "%.*Lg", precision, value);
        if (written < 0 || (size_t)written >= buffer_size) {
            buffer[0] = 0;
            return 0;
        }

        if (strtold(buffer, NULL) == value)
            return (size_t)written;
    }

    // no exact round-trip, the 17-digit form is already in the buffer
    return (size_t)written;
}
