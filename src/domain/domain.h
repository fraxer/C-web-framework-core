#ifndef __DOMAIN__
#define __DOMAIN__

#include <pcre2.h>

typedef struct domain {
    int pcre_erroffset;
    /* The template carries nothing PCRE reads as more than itself, so matching
     * it is a string comparison and the compiled pattern is only kept for the
     * paths that have not been converted. Almost every configured domain is
     * like this -- "example.com", "www.example.com" -- and running a regex for
     * them showed up as the top line of the worker profile (5.4%, all in
     * libpcre) on a server with a handful of routes. */
    int is_literal;
    char* template;
    char* ascii_template;
    /* Length of ascii_template, so the literal comparison does not strlen() the
     * same constant on every request. */
    size_t ascii_length;
    char* prepared_template;
    const char* pcre_error;
    pcre2_code* pcre_template;
    struct domain* next;
} domain_t;

domain_t* domain_create(const char*);

domain_t* domain_alloc(const char*);

void domains_free(domain_t*);

int domain_parse(domain_t*);

/* Does this domain accept `host` (already ASCII/punycode, `length` bytes)?
 * Literal templates are compared byte for byte, the rest go through PCRE. The
 * comparison is case-sensitive, exactly as the compiled pattern is -- this is a
 * shortcut, not a change of behaviour. */
int domain_matches(const domain_t* domain, const char* host, size_t length);

int domain_count(domain_t*);

#endif
