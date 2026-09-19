#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "utf8.h"

#include "cstr_internal.h"
#include "validation.h"

#define MAX_EMAIL_LENGTH 254
#define MAX_LOCAL_PART_LENGTH 64
#define MAX_DOMAIN_LENGTH 255

/* E.164 limits: a number shorter than seven digits does not exist even under a
 * short numbering plan, and one longer than fifteen does not exist at all. */
#define MIN_PHONE_DIGITS 7
#define MAX_PHONE_DIGITS 15

#define MAX_PORT 65535

static int is_local_part_char(char c);
static int is_domain_char(char c);
static int is_valid_tld(const char* domain);
static int validate_local_part(const char* local_part);
static int validate_domain(const char* domain);
static int starts_with_lower(const char* value, const char* prefix);

int validate_utf8(const char* value) {
    if (value == NULL) return 0;

    for (const unsigned char* p = (const unsigned char*)value; *p;) {
        uint32_t codepoint;
        const size_t size = utf8_decode(p, &codepoint);

        if (size == 0) return 0;

        p += size;
    }

    return 1;
}

int validate_not_empty(const char* value) {
    return value != NULL && *value != 0;
}

int validate_length(const char* value, size_t min_length, size_t max_length) {
    if (value == NULL) return 0;

    const size_t length = utf8_strlen(value);

    if (length < min_length) return 0;
    if (max_length > 0 && length > max_length) return 0;

    return 1;
}

int validate_no_control(const char* value) {
    if (value == NULL) return 0;

    for (const unsigned char* p = (const unsigned char*)value; *p;) {
        uint32_t codepoint;
        const size_t size = utf8_decode(p, &codepoint);

        if (size == 0) return 0;
        if (cstr_is_control_codepoint(codepoint)) return 0;

        p += size;
    }

    return 1;
}

int validate_charset(const char* value, validate_char_fn allowed) {
    if (value == NULL || allowed == NULL) return 0;

    for (const unsigned char* p = (const unsigned char*)value; *p;) {
        uint32_t codepoint;
        const size_t size = utf8_decode(p, &codepoint);

        if (size == 0) return 0;
        if (!allowed(codepoint)) return 0;

        p += size;
    }

    return 1;
}

int validate_char_letter(uint32_t codepoint) {
    return utf8_is_alpha(codepoint) != 0;
}

int validate_char_digit(uint32_t codepoint) {
    return codepoint >= '0' && codepoint <= '9';
}

int validate_char_letter_or_digit(uint32_t codepoint) {
    return validate_char_letter(codepoint) || validate_char_digit(codepoint);
}

int validate_char_name(uint32_t codepoint) {
    if (validate_char_letter(codepoint)) return 1;

    switch (codepoint) {
    case ' ':
    case '-':
    case '.':
    case '\'':
    case 0x2010:    /* HYPHEN */
    case 0x2011:    /* NON-BREAKING HYPHEN */
    case 0x2013:    /* EN DASH -- often used to spell a double surname */
    case 0x2019:    /* RIGHT SINGLE QUOTATION MARK -- the typographic apostrophe */
        return 1;
    default:
        return 0;
    }
}

int validate_char_phone(uint32_t codepoint) {
    if (validate_char_digit(codepoint)) return 1;

    switch (codepoint) {
    case '+': case ' ': case '(': case ')': case '-': case '.':
        return 1;
    default:
        return 0;
    }
}

int validate_char_ascii_printable(uint32_t codepoint) {
    return codepoint >= 0x20 && codepoint < 0x7F;
}

int validate_phone(const char* value) {
    if (value == NULL || *value == 0) return 0;

    const char* p = value;

    /* A plus is allowed only as the leading character: "8+800" is not a
     * number. */
    if (*p == '+') p++;

    size_t digits = 0;

    for (; *p; p++) {
        if (*p >= '0' && *p <= '9') {
            digits++;
            continue;
        }

        if (strchr(" ()-.", *p) == NULL) return 0;
    }

    return digits >= MIN_PHONE_DIGITS && digits <= MAX_PHONE_DIGITS;
}

/**
 * @brief Characters allowed in the local part of an address (RFC 5322).
 */
int is_local_part_char(char c) {
    return (isalnum((unsigned char)c) ||
            c == '.' || c == '!' || c == '#' ||
            c == '$' || c == '%' || c == '&' ||
            c == '\'' || c == '*' || c == '+' ||
            c == '-' || c == '/' || c == '=' ||
            c == '?' || c == '^' || c == '_' ||
            c == '`' || c == '{' || c == '|' ||
            c == '}' || c == '~');
}

/**
 * @brief Characters allowed in the domain part of an address (RFC 1035).
 */
int is_domain_char(char c) {
    return (isalnum((unsigned char)c) || c == '-' || c == '.');
}

/**
 * @brief A top-level domain: at least two characters, letters only.
 */
int is_valid_tld(const char* domain) {
    const char* dot = strrchr(domain, '.');
    if (dot == NULL) return 0;

    const char* tld = dot + 1;

    if (strlen(tld) < 2) return 0;

    while (*tld) {
        if (!isalpha((unsigned char)*tld)) return 0;
        tld++;
    }

    return 1;
}

/**
 * @brief The local part: non-empty, within the limit, no dot at either edge
 * and no two dots in a row.
 */
int validate_local_part(const char* local_part) {
    const size_t length = strlen(local_part);
    if (length == 0 || length > MAX_LOCAL_PART_LENGTH) return 0;

    if (local_part[0] == '.' || local_part[length - 1] == '.') return 0;

    char prev = 0;
    for (size_t i = 0; i < length; i++) {
        const char current = local_part[i];

        if (current == '.' && prev == '.') return 0;
        if (!is_local_part_char(current)) return 0;

        prev = current;
    }

    return 1;
}

/**
 * @brief The domain: non-empty, within the limit, no hyphen or dot at either
 * edge, no two special characters in a row, at least one dot and a valid TLD.
 */
int validate_domain(const char* domain) {
    const size_t length = strlen(domain);
    if (length == 0 || length > MAX_DOMAIN_LENGTH) return 0;

    if (domain[0] == '-' || domain[0] == '.' ||
        domain[length - 1] == '-' || domain[length - 1] == '.') return 0;

    char prev = 0;
    int has_dot = 0;
    for (size_t i = 0; i < length; i++) {
        const char ch = domain[i];

        if (ch == '.') has_dot = 1;

        if ((ch == '.' || ch == '-') && (prev == '.' || prev == '-')) return 0;
        if (!is_domain_char(ch)) return 0;

        prev = ch;
    }

    if (!has_dot) return 0;

    return is_valid_tld(domain);
}

int validate_email(const char* email) {
    if (email == NULL || *email == 0) return 0;

    const size_t length = strlen(email);
    if (length > MAX_EMAIL_LENGTH) return 0;

    const char* at_pos = strchr(email, '@');
    if (at_pos == NULL) return 0;

    /* Exactly one at sign. */
    if (strchr(at_pos + 1, '@') != NULL) return 0;

    char local_part[MAX_LOCAL_PART_LENGTH + 1] = {0};
    char domain[MAX_DOMAIN_LENGTH + 1] = {0};

    const size_t local_part_length = (size_t)(at_pos - email);
    const size_t domain_length = length - local_part_length - 1;

    if (local_part_length >= sizeof(local_part) ||
        domain_length >= sizeof(domain)) return 0;

    memcpy(local_part, email, local_part_length);
    memcpy(domain, at_pos + 1, domain_length);

    if (!validate_local_part(local_part)) return 0;

    return validate_domain(domain);
}

int validate_url(const char* value) {
    if (value == NULL) return 0;

    const char* host = NULL;

    if (strncmp(value, "http://", 7) == 0) host = value + 7;
    else if (strncmp(value, "https://", 8) == 0) host = value + 8;
    else return 0;

    /* Neither a user name nor a password belongs in a link that came from a
     * form: "https://sberbank.ru@evil.example/" shows the user one thing and
     * leads somewhere else. */
    const size_t authority_length = strcspn(host, "/?#");
    if (memchr(host, '@', authority_length) != NULL) return 0;

    const size_t host_length = strcspn(host, ":/?#");
    if (host_length == 0 || host_length > MAX_DOMAIN_LENGTH) return 0;

    char domain[MAX_DOMAIN_LENGTH + 1] = {0};
    memcpy(domain, host, host_length);

    if (!validate_domain(domain)) return 0;

    const char* rest = host + host_length;

    if (*rest == ':') {
        rest++;

        const size_t port_length = strcspn(rest, "/?#");
        if (port_length == 0 || port_length > 5) return 0;

        long port = 0;
        for (size_t i = 0; i < port_length; i++) {
            if (!isdigit((unsigned char)rest[i])) return 0;
            port = port * 10 + (rest[i] - '0');
        }

        if (port < 1 || port > MAX_PORT) return 0;

        rest += port_length;
    }

    /* Path, query and fragment: printable ASCII without spaces. Cyrillic in a
     * link has to arrive percent-encoded already. */
    for (; *rest; rest++)
        if (!validate_char_ascii_printable((unsigned char)*rest) || *rest == ' ') return 0;

    return 1;
}

/**
 * @brief Whether the string starts with the prefix, ignoring case (the prefix
 * is ASCII).
 */
int starts_with_lower(const char* value, const char* prefix) {
    for (; *prefix; value++, prefix++) {
        if (*value == 0) return 0;
        if (tolower((unsigned char)*value) != *prefix) return 0;
    }

    return 1;
}

size_t count_links(const char* value) {
    if (value == NULL) return 0;

    /* Lower case only: starts_with_lower folds the input to it. */
    static const char* const markers[] = { "http://", "https://", "www." };

    size_t count = 0;

    for (const char* p = value; *p;) {
        int matched = 0;

        for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]) && !matched; i++)
            matched = starts_with_lower(p, markers[i]);

        if (!matched) {
            p++;
            continue;
        }

        count++;

        /* A link runs to the nearest whitespace: otherwise "https://www.x"
         * would count twice, once for the scheme and once for the "www.". */
        while (*p && !isspace((unsigned char)*p)) p++;
    }

    return count;
}
