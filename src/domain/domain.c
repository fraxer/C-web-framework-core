#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "domain.h"
#include "idn_utils.h"

typedef struct domain_parser {
    char* template;
    char* prepared_template;
    size_t pos;
    size_t prepared_pos;
    int brackets_count;
} domain_parser_t;

int domain_estimate_length(const char*);

void domain_parser_alloc(domain_parser_t*, domain_t*);

void domain_parser_insert_symbol(domain_parser_t* parser);

void domain_parser_insert_custom_symbol(domain_parser_t* parser, char ch);

/* Whether the template means only itself. Everything PCRE treats as a
 * metacharacter disqualifies it, with one exception: '.' is escaped by
 * domain_parse, so a dotted name stays literal -- which is what makes the
 * shortcut worth having, since every real domain has dots and nothing else. */
static int __template_is_literal(const char* template) {
    for (const char* p = template; *p != 0; p++) {
        switch (*p) {
        case '^': case '$': case '*': case '+': case '?':
        case '(': case ')': case '[': case ']':
        case '{': case '}': case '|': case '\\':
            return 0;
        default:
            break;
        }
    }

    return 1;
}

/* Capture groups a domain pattern may have. A vhost template captures nothing
 * the caller reads -- only the yes/no answer is used -- so this is sized to hold
 * pcre_exec's own bookkeeping with room to spare. */
#define DOMAIN_PCRE_VECTOR_SIZE 120

/* ASCII case folding, deliberately not tolower(): the templates are punycode by
 * the time they get here, so only ASCII letters can differ in case, and a locale
 * that folds anything else would make vhost selection depend on the environment
 * the server was started in. */
static inline char __fold(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

int domain_matches(const domain_t* domain, const char* host, size_t length) {
    if (domain == NULL || host == NULL) return 0;

    if (domain->is_literal) {
        if (length != domain->ascii_length) return 0;

        for (size_t i = 0; i < length; i++)
            if (__fold(host[i]) != __fold(domain->ascii_template[i])) return 0;

        return 1;
    }

    pcre2_match_data* match_data = pcre2_match_data_create(DOMAIN_PCRE_VECTOR_SIZE / 3, NULL);
    if (match_data == NULL) return 0;

    int rc = pcre2_match(domain->pcre_template, (PCRE2_SPTR)host, length, 0, 0, match_data, NULL);
    pcre2_match_data_free(match_data);

    return rc > 0;
}

domain_t* domain_create(const char* value) {
    domain_t* result = NULL;
    domain_t* domain = domain_alloc(value);
    if (domain == NULL) goto failed;

    if (domain_parse(domain) == -1) goto failed;

    domain->is_literal = __template_is_literal(domain->ascii_template);
    domain->ascii_length = strlen(domain->ascii_template);

    /* PCRE_CASELESS: a host is case-insensitive (RFC 9110 §4.2.3), and
     * `Host: EXAMPLE.COM` used to miss the vhost `example.com` outright -- the
     * pattern was compiled case-sensitive and the literal comparison matched it.
     * Both halves fold now, and they must keep folding the same way: a shortcut
     * that disagrees with the pattern is how a request lands on the wrong
     * server. */
    int error_code = 0;
    PCRE2_SIZE error_offset = 0;
    domain->pcre_template = pcre2_compile((PCRE2_SPTR)domain->prepared_template, PCRE2_ZERO_TERMINATED,
                                          PCRE2_CASELESS, &error_code, &error_offset, NULL);
    if (domain->pcre_template == NULL) {
        /* Get error message */
        PCRE2_UCHAR error_buffer[256];
        pcre2_get_error_message(error_code, error_buffer, sizeof(error_buffer));
        domain->pcre_error = (char*)strdup((char*)error_buffer);
        domain->pcre_erroffset = (int)error_offset;
        goto failed;
    }

    result = domain;

    failed:

    if (result == NULL)
        domains_free(domain);

    return result;
}

void domains_free(domain_t* domain) {
    while (domain != NULL) {
        domain_t* next = domain->next;

        if (domain->template != NULL)
            free(domain->template);

        if (domain->ascii_template != NULL)
            free(domain->ascii_template);

        if (domain->prepared_template != NULL)
            free(domain->prepared_template);

        if (domain->pcre_template != NULL)
            pcre2_code_free(domain->pcre_template);
        free((void*)domain->pcre_error);  /* strdup'd in pcre2_compile error path */

        free(domain);

        domain = next;
    }
}

domain_t* domain_alloc(const char* value) {
    if (value == NULL) return NULL;

    domain_t* result = NULL;
    domain_t* domain = malloc(sizeof * domain);
    if (domain == NULL) return NULL;

    domain->is_literal = 0;
    domain->ascii_length = 0;
    domain->template = NULL;
    domain->ascii_template = NULL;
    domain->prepared_template = NULL;
    domain->pcre_template = NULL;
    domain->pcre_error = NULL;
    domain->pcre_erroffset = 0;
    domain->next = NULL;

    domain->template = malloc(strlen(value) + 1);
    if (domain->template == NULL) goto failed;

    strcpy(domain->template, value);

    // Convert to ASCII/Punycode
    domain->ascii_template = idn_to_ascii(value);
    if (domain->ascii_template == NULL) goto failed;

    // Use ASCII version for PCRE length calculation
    int pcre_length = domain_estimate_length(domain->ascii_template);
    if (pcre_length == -1) goto failed;

    domain->prepared_template = malloc(pcre_length + 1);
    if (domain->prepared_template == NULL) goto failed;

    result = domain;

    failed:

    if (result == NULL) {
        free(domain->prepared_template);
        free(domain->ascii_template);
        free(domain->template);
        free(domain);
    }

    return result;
}

int domain_parse(domain_t* domain) {
    domain_parser_t parser;

    domain_parser_alloc(&parser, domain);

    const size_t length = strlen(domain->ascii_template);
    if (length == 0) {
        log_error("Domain error: Empty domain template\n");
        return -1;
    }

    const int need_start_anchor = domain->ascii_template[0] != '^';
    const int need_end_anchor = domain->ascii_template[length - 1] != '$';

    if (need_start_anchor)
        parser.prepared_pos = 1;

    for (; parser.pos < length; parser.pos++) {
        switch (domain->ascii_template[parser.pos]) {
        case '(':
        case '[':
            parser.brackets_count++;
            domain_parser_insert_symbol(&parser);
            break;
        case ')':
        case ']':
            if (parser.brackets_count == 0) return -1;
            parser.brackets_count--;
            domain_parser_insert_symbol(&parser);
            break;
        case '*':
            if (parser.brackets_count > 0) {
                domain_parser_insert_symbol(&parser);
                break;
            }

            if (parser.pos == 0 || parser.pos == length - 1) {
                domain_parser_insert_custom_symbol(&parser, '.');
                domain_parser_insert_symbol(&parser);
            }
            else {
                log_error("Domain error: Asterisk must be in start or end of the string\n");
                return -1;
            }
            break;
        case '.':
            if (parser.brackets_count > 0) {
                domain_parser_insert_symbol(&parser);
                break;
            }

            domain_parser_insert_custom_symbol(&parser, '\\');
            domain_parser_insert_symbol(&parser);
            break;
        default:
            domain_parser_insert_symbol(&parser);
        }
    }

    if (parser.brackets_count != 0) return -1;

    if (need_start_anchor)
        domain->prepared_template[0] = '^';

    if (need_end_anchor)
        domain_parser_insert_custom_symbol(&parser, '$');

    domain_parser_insert_custom_symbol(&parser, 0);

    return 0;
}

int domain_estimate_length(const char* domain) {
    const int length = strlen(domain);
    if (length == 0) {
        log_error("Domain error: Empty domain template\n");
        return -1;
    }

    int pcre_length = 0;
    int brackets_count = 0;

    for (int pos = 0; pos < length; pos++) {
        switch (domain[pos]) {
        case '(':
        case '[':
            brackets_count++;
            pcre_length++;
            break;
        case ')':
        case ']':
            if (brackets_count == 0) return -1;
            brackets_count--;
            pcre_length++;
            break;
        case '*':
            if (brackets_count > 0) {
                pcre_length++;
                break;
            }

            if (pos == 0 || pos == length - 1) {
                pcre_length += 2;
            }
            else {
                log_error("Domain error: Asterisk must be in start or end of the string\n");
                return -1;
            }
            break;
        case '.':
            if (brackets_count > 0) {
                pcre_length++;
                break;
            }

            pcre_length += 2;
            break;
        default:
            pcre_length++;
        }
    }

    if (brackets_count != 0) return -1;

    if (domain[0] != '^') pcre_length++;
    if (domain[length - 1] != '$') pcre_length++;

    return pcre_length;
}

void domain_parser_alloc(domain_parser_t* parser, domain_t* domain) {
    parser->template = domain->ascii_template;
    parser->prepared_template = domain->prepared_template;
    parser->pos = 0;
    parser->prepared_pos = 0;
    parser->brackets_count = 0;
}

void domain_parser_insert_symbol(domain_parser_t* parser) {
    domain_parser_insert_custom_symbol(parser, parser->template[parser->pos]);
}

void domain_parser_insert_custom_symbol(domain_parser_t* parser, char ch) {
    parser->prepared_template[parser->prepared_pos] = ch;
    parser->prepared_pos++;
}

int domain_count(domain_t* domain) {
    domain_t* current = domain;

    int count = 0;

    while (current) {
        count++;
        current = current->next;
    }

    return count;
}