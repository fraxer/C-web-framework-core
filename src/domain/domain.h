#ifndef __DOMAIN__
#define __DOMAIN__

#include <stddef.h>

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

/* The name a Host field or :authority asks for, as domain_matches compares it:
 * the port off (only digits make one, RFC 9110 §7.2), the brackets off an IPv6
 * literal, one trailing dot off -- "example.com." names the same host as
 * "example.com" -- and the rest in ASCII/punycode. `*out` is a new string for
 * the caller to free on DOMAIN_HOST_OK.
 *
 * DOMAIN_HOST_BAD for what cannot be a Host: empty, DOMAIN_MAX_HOST bytes or
 * more, a control byte, space or DEL anywhere, a port with anything but
 * digits, an unclosed or trailed IPv6 literal, two trailing dots.
 * DOMAIN_HOST_UNKNOWN for a name IDN cannot convert: well formed, but no
 * virtual host can have it. */
#define DOMAIN_MAX_HOST 256

typedef enum {
    DOMAIN_HOST_OK = 0,
    DOMAIN_HOST_BAD,
    DOMAIN_HOST_UNKNOWN
} domain_host_e;

domain_host_e domain_host_normalize(const char* host, size_t length, char** out);

#endif
