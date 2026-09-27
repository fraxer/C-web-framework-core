#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "log.h"
#include "dkim.h"
#include "dkimcanonparser.h"
#include "dkimheaderparser.h"
#include "base64.h"

int __dkim_relaxed_header_canon(dkim_t* dkim);
char* __dkim_relaxed_body_canon(const char *body);
char* __dkim_wrap(char *str, size_t len);
EVP_PKEY* __dkim_rsa_read_pem(const char* buffer);
char* __dkim_header_list_create(dkim_t* dkim, int* header_list_length);
int __dkim_header_count(mail_header_t* header);
int __dkim_header_keys_length(mail_header_t* header);
char* __dkim_base64_encode_sha1(const char* body, int* canon_body_length);
/* Signs `data` with RSA-SHA1 (sha1 is applied once, internally) and returns
 * the base64-encoded signature. Feeding a precomputed digest here would hash
 * it a second time and produce a signature no RFC 4871 verifier accepts. */
char* __dkim_sign_create(const unsigned char* data, int data_length, const char* private_key, int* sign64_length);
char* __dkim_make_headers_string(dkim_t* dkim, int* headers_string_length);
char* __dkim_add_sign_to_dkim(const char* dkim, size_t dkim_length, const char* sign, size_t sign_length);

/* The "relaxed" Header Canonicalization Algorithm */
int __dkim_relaxed_header_canon(dkim_t* dkim) {
    int result = 0;
    dkimheaderparser_t* parser = dkimheaderparser_alloc();
    if (parser == NULL) return 0;

    dkimheaderparser_init(parser);

    /* Copy all headers */
    /* Convert all header field names (not the header field values) to
       lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC". */
    /* Convert all sequences of one or more WSP characters to a single SP
       character. WSP characters here include those before and after a
       line folding boundary. */
    mail_header_t* header = dkim->header;
    while (header) {
        for (size_t e = 0; e < header->key_length; ++e)
            header->key[e] = (char)tolower((unsigned char)header->key[e]);

        dkimheaderparser_set_buffer(parser, header->value, header->value_length);
        if (!dkimheaderparser_run(parser))
            goto failed;

        char* new_body = dkimheaderparser_get_content(parser);
        if (new_body == NULL)
            goto failed;

        free(header->value);
        header->value = new_body;
        header->value_length = dkimheaderparser_get_content_length(parser);

        header = header->next;
    }

    result = 1;

    failed:

    dkimheaderparser_free(parser);

    return result;
}

/* One header value, relaxed (RFC 6376 §3.4.2); NULL on allocation failure. */
static char* __dkim_relaxed_value(const char* value, size_t length, size_t* out_length) {
    dkimheaderparser_t* parser = dkimheaderparser_alloc();
    if (parser == NULL) return NULL;

    dkimheaderparser_init(parser);
    dkimheaderparser_set_buffer(parser, value, length);
    char* result = dkimheaderparser_run(parser) ? dkimheaderparser_get_content(parser) : NULL;
    *out_length = result != NULL ? dkimheaderparser_get_content_length(parser) : 0;

    dkimheaderparser_free(parser);

    return result;
}

/* "relaxed" body canonicalization */
char* __dkim_relaxed_body_canon(const char *body) {
    dkimcanonparser_t* parser = dkimcanonparser_alloc();
    if (parser == NULL) return NULL;

    dkimcanonparser_init(parser);
    dkimcanonparser_set_buffer(parser, body, strlen(body));
    const int success = dkimcanonparser_run(parser);
    char* new_body = success ? dkimcanonparser_get_content(parser) : NULL;

    dkimcanonparser_free(parser);

    return new_body;
}

/* Where a tag value may be folded when its line runs long (RFC 6376 §3.5):
 * base64 values (b=, bh=) anywhere, h= only after a colon, the rest never --
 * a fold is whitespace to a verifier, and inside a domain or a field name it
 * would change the value. */
typedef enum {
    DKIM_WRAP_NEVER = 0,
    DKIM_WRAP_ANYWHERE,
    DKIM_WRAP_AFTER_COLON
} dkim_wrap_rule_e;

static dkim_wrap_rule_e __dkim_wrap_rule(const char* name, size_t length) {
    while (length > 0 && (*name == ' ' || *name == '\t')) { name++; length--; }
    while (length > 0 && (name[length - 1] == ' ' || name[length - 1] == '\t')) length--;

    if ((length == 1 && name[0] == 'b') || (length == 2 && name[0] == 'b' && name[1] == 'h'))
        return DKIM_WRAP_ANYWHERE;
    if (length == 1 && name[0] == 'h')
        return DKIM_WRAP_AFTER_COLON;

    return DKIM_WRAP_NEVER;
}

/* Folds a tag list: after every space, and past 75 characters on a line where
 * the tag allows it. Decisions depend only on what precedes them, so folding a
 * prefix gives the same folds as folding the whole -- dkim_create_sign relies
 * on that to sign the field with an empty b= as it is later sent. */
char* __dkim_wrap(char* str, size_t len) {
    char* tmp = malloc(len * 4 + 1);
    if (tmp == NULL)
        return NULL;

    size_t tmp_len = 0;
    size_t lcount = 0;
    size_t tag_start = 0;
    int in_name = 1;
    dkim_wrap_rule_e rule = DKIM_WRAP_NEVER;

    for (size_t i = 0; i < len; ++i) {
        const char c = str[i];
        tmp[tmp_len++] = c;
        ++lcount;

        if (c == ';') {
            in_name = 1;
            tag_start = i + 1;
            rule = DKIM_WRAP_NEVER;
        }
        else if (c == '=' && in_name) {
            in_name = 0;
            rule = __dkim_wrap_rule(str + tag_start, i - tag_start);
        }

        const int long_line = lcount >= 75 && !in_name &&
            (rule == DKIM_WRAP_ANYWHERE || (rule == DKIM_WRAP_AFTER_COLON && c == ':'));

        if ((c == ' ' || long_line) && i + 1 < len) {
            tmp[tmp_len++] = '\r';
            tmp[tmp_len++] = '\n';
            tmp[tmp_len++] = '\t';
            lcount = 0;
        }
    }

    tmp[tmp_len] = 0;

    return tmp;
}

EVP_PKEY* __dkim_rsa_read_pem(const char* buffer) {
    BIO* mem = BIO_new_mem_buf(buffer, strlen(buffer));
    if (mem == NULL) return NULL;

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    BIO_free(mem);

    return pkey;
} 

/* h1:h2:h3 */
char* __dkim_header_list_create(dkim_t* dkim, int* header_list_length) {
    const int count = __dkim_header_count(dkim->header);
    const int keys_length = __dkim_header_keys_length(dkim->header);

    /* With zero headers the naive "keys + count - 1" underflows to -1; guard
     * it so we never hand a wrapped size_t to malloc. */
    *header_list_length = count > 0 ? keys_length + count - 1 : 0;

    char* header_list = malloc(sizeof(char) * ((*header_list_length) + 1));
    if (header_list == NULL) {
        *header_list_length = 0;
        return NULL;
    }

    int pos = 0;
    mail_header_t* header = dkim->header;
    while (header) {
        if (pos != 0)
            pos += sprintf(header_list + pos, ":");

        pos += sprintf(header_list + pos, "%s", header->key);

        header = header->next;
    }

    /* Always terminate: the loop body never runs when there are no headers. */
    header_list[pos] = '\0';

    return header_list;
}

int __dkim_header_count(mail_header_t* header) {
    int count = 0;
    while (header) {
        count++;
        header = header->next;
    }

    return count;
}

int __dkim_header_keys_length(mail_header_t* header) {
    int length = 0;
    while (header) {
        length += header->key_length;
        header = header->next;
    }

    return length;
}

char* __dkim_base64_encode_sha1(const char* body, int* canon_body_length) {
    char* canon_body = __dkim_relaxed_body_canon(body);
    if (canon_body == NULL) return NULL;

    *canon_body_length = strlen(canon_body);

    unsigned char uhash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)canon_body, *canon_body_length, uhash);
    free(canon_body);

    char* base64string = malloc(base64_encode_len(SHA_DIGEST_LENGTH));
    if (base64string == NULL)
        return NULL;

    if (!base64_encode(base64string, (const char*)uhash, SHA_DIGEST_LENGTH)) {
        *canon_body_length = 0;
        free(base64string);
        return NULL;
    }

    return base64string;
}

char* __dkim_sign_create(const unsigned char* data, int data_length, const char* private_key, int* sign64_length) {
    *sign64_length = 0;

    EVP_PKEY* pkey = __dkim_rsa_read_pem(private_key);
    if (pkey == NULL) {
        log_error("DKIM error loading rsa key\n");
        return NULL;
    }

    char* result = NULL;
    char* base64sign = NULL;
    unsigned char* sign = NULL;
    size_t sign_length = 0;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto failed;

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha1(), NULL, pkey) != 1) {
        log_error("DKIM error rsa sign init: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto failed;
    }

    if (EVP_DigestSignUpdate(md_ctx, data, (size_t)data_length) != 1) {
        log_error("DKIM error rsa sign update: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto failed;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, &sign_length) != 1) {
        log_error("DKIM error rsa sign final (get length): %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto failed;
    }

    sign = malloc(sign_length);
    if (sign == NULL)
        goto failed;

    if (EVP_DigestSignFinal(md_ctx, sign, &sign_length) != 1) {
        log_error("DKIM error rsa sign: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto failed;
    }

    base64sign = malloc(base64_encode_len(sign_length));
    if (base64sign == NULL)
        goto failed;

    *sign64_length = base64_encode(base64sign, (char*)sign, sign_length);
    if (*sign64_length == 0) {
        free(base64sign);
        goto failed;
    }

    result = base64sign;

    failed:

    if (md_ctx != NULL)
        EVP_MD_CTX_free(md_ctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (sign != NULL)
        free(sign);

    return result;
}

/* The field to sign in the place of `header`. h= lists a name once per
 * instance, and a verifier takes the instances of a repeated name from the
 * bottom up (RFC 6376 §5.4.2): the k-th of n instances, counted from the top,
 * is signed in the place of the k-th from the bottom. The lengths are the
 * same either way, so the buffer sized over the list still fits. */
static const mail_header_t* __dkim_bottom_up_instance(const mail_header_t* first, const mail_header_t* header) {
    size_t above = 0;
    size_t total = 0;
    for (const mail_header_t* h = first; h != NULL; h = h->next) {
        if (strcasecmp(h->key, header->key) != 0) continue;
        if (h == header) above = total;
        total++;
    }

    const size_t want = total - 1 - above;
    size_t seen = 0;
    for (const mail_header_t* h = first; h != NULL; h = h->next) {
        if (strcasecmp(h->key, header->key) != 0) continue;
        if (seen++ == want) return h;
    }

    return header;
}

char* __dkim_make_headers_string(dkim_t* dkim, int* headers_string_length) {
    *headers_string_length = 0;

    mail_header_t* header = dkim->header;
    while (header) {
        *headers_string_length += header->key_length + header->value_length;
        *headers_string_length += header->next != NULL ? 3 : 1;

        header = header->next;
    }

    char* string = malloc(*headers_string_length + 1);
    if (string == NULL) {
        *headers_string_length = 0;
        return NULL;
    }

    size_t offset = 0;
    header = dkim->header;
    while (header) {
        const mail_header_t* instance = __dkim_bottom_up_instance(dkim->header, header);
        const char* template = header->next != NULL ? "%s:%s\r\n" : "%s:%s";
        /* Cap by the remaining space from `offset`, not the whole buffer. */
        offset += snprintf(string + offset, (size_t)(*headers_string_length) + 1 - offset, template, instance->key, instance->value);

        header = header->next;
    }

    return string;
}

char* __dkim_add_sign_to_dkim(const char* dkim, size_t dkim_length, const char* sign, size_t sign_length) {
    const size_t extra_dkim_length = dkim_length + sign_length;
    char* extra_dkim = malloc(extra_dkim_length + 1);
    if (extra_dkim == NULL)
        return NULL;

    memcpy(extra_dkim, dkim, dkim_length);
    memcpy(extra_dkim + dkim_length, sign, sign_length + 1);

    char* wrap_dkim = __dkim_wrap(extra_dkim, extra_dkim_length);

    free(extra_dkim);

    return wrap_dkim;
}

dkim_t* dkim_create() {
    dkim_t* dkim = malloc(sizeof * dkim);
    if (dkim == NULL) return NULL;

    dkim->private_key = NULL;
    dkim->domain = NULL;
    dkim->selector = NULL;
    dkim->timestamp = 0;
    dkim->header = NULL;
    dkim->last_header = NULL;

    return dkim;
}

/* A field name is RFC 5322 ftext -- printable US-ASCII except the colon --
 * that h= can hold: no ';', which ends a tag (RFC 6376 §3.2). */
static int __dkim_header_name_valid(const char* key, size_t key_length) {
    for (size_t i = 0; i < key_length; i++)
        if ((unsigned char)key[i] < 33 || (unsigned char)key[i] > 126 || key[i] == ':' || key[i] == ';')
            return 0;

    return 1;
}

/* A value may contain CR and LF only as a fold, CRLF followed by WSP, and no
 * NUL: the signer works on C strings, so the value would be signed shorter
 * than it is sent. */
static int __dkim_header_value_valid(const char* value, size_t value_length) {
    for (size_t i = 0; i < value_length; i++) {
        if (value[i] == '\0') return 0;
        if (value[i] == '\r' || value[i] == '\n') {
            if (value[i] != '\r' || i + 2 >= value_length || value[i + 1] != '\n' ||
                (value[i + 2] != ' ' && value[i + 2] != '\t'))
                return 0;
            i++;
        }
    }

    return 1;
}

int dkim_header_add(dkim_t* dkim, const char* key, const size_t key_length, const char* value, const size_t value_length) {
    if (dkim == NULL) return 0;
    if (key == NULL) return 0;
    if (value == NULL) return 0;
    if (key[0] == 0) return 0;
    if (value[0] == 0) return 0;
    /* Anything else is signed as one field and sent as another. */
    if (!__dkim_header_name_valid(key, key_length)) return 0;
    if (!__dkim_header_value_valid(value, value_length)) return 0;

    mail_header_t* header = mail_header_create(key, key_length, value, value_length);
    if (header == NULL) return 0;
    if (header->key == NULL || header->value == NULL) {
        mail_header_free(header);
        return 0;
    }

    if (dkim->header == NULL)
        dkim->header = header;

    if (dkim->last_header != NULL)
        dkim->last_header->next = header;

    dkim->last_header = header;

    return 1;
}

void dkim_set_private_key(dkim_t* dkim, const char* private_key) {
    dkim->private_key = private_key;
}

void dkim_set_domain(dkim_t* dkim, const char* domain) {
    dkim->domain = domain;
}

void dkim_set_selector(dkim_t* dkim, const char* selector) {
    dkim->selector = selector;
}

void dkim_set_timestamp(dkim_t* dkim, const time_t timestamp) {
    dkim->timestamp = timestamp;
}

/**
 * http://tools.ietf.org/html/rfc4871
 */
char* dkim_create_sign(dkim_t* dkim, const char* body) {
    if (dkim == NULL || body == NULL)
        return NULL;
    if (dkim->private_key == NULL || dkim->selector == NULL || dkim->domain == NULL)
        return NULL;

    if (!__dkim_relaxed_header_canon(dkim))
        return NULL;

    char* data = NULL;
    char* folded = NULL;
    char* canonical = NULL;
    char* headers_string = NULL;
    char* sign = NULL;
    char* full_dkim = NULL;
    int canon_body_length = 0;
    char* base64_hash = __dkim_base64_encode_sha1(body, &canon_body_length);
    if (base64_hash == NULL)
        return NULL;

    int header_list_length = 0;
    char* header_list = __dkim_header_list_create(dkim, &header_list_length);
    if (header_list == NULL)
        goto failed;

    /* create DKIM header */
    const char* template = "v=1; a=rsa-sha1; s=%s; d=%s; l=%d; t=%lld; c=relaxed/relaxed; h=%s; bh=%s; b=";
    data = malloc(strlen(template) + strlen(dkim->selector) + strlen(dkim->domain) + 16 + 16 + header_list_length + strlen(base64_hash) + 1);
    if (data == NULL)
        goto failed;

    const size_t data_length = sprintf(data, template, dkim->selector, dkim->domain, canon_body_length, (long long)dkim->timestamp, header_list, base64_hash);

    /* The field is signed as a verifier will see it: folded the way it is
     * sent, then canonicalized (relaxed), with b= still empty. Signing the
     * unfolded text instead breaks the signature wherever a fold falls
     * outside existing whitespace. */
    folded = __dkim_wrap(data, data_length);
    if (folded == NULL)
        goto failed;

    size_t canonical_length = 0;
    canonical = __dkim_relaxed_value(folded, strlen(folded), &canonical_length);
    if (canonical == NULL)
        goto failed;

    const char* h_dkim_sign = "dkim-signature";
    if (!dkim_header_add(dkim, h_dkim_sign, strlen(h_dkim_sign), canonical, canonical_length))
        goto failed;

    int headers_string_length = 0;
    headers_string = __dkim_make_headers_string(dkim, &headers_string_length);
    if (headers_string == NULL)
        goto failed;

    /* RSA-SHA1 over the canonicalized headers (sha1 applied once, inside the
     * signer). Do NOT pre-hash: feeding a digest to EVP_DigestSign* hashes it
     * a second time and yields an unverifiable signature. */
    int sign_length = 0;
    sign = __dkim_sign_create((const unsigned char*)headers_string, headers_string_length, dkim->private_key, &sign_length);
    if (sign == NULL)
        goto failed;

    full_dkim = __dkim_add_sign_to_dkim(data, data_length, sign, sign_length);
    if (full_dkim == NULL)
        goto failed;

    failed:

    if (base64_hash != NULL) free(base64_hash);
    if (header_list != NULL)free(header_list);
    if (data != NULL) free(data);
    free(folded);
    free(canonical);
    if (headers_string != NULL) free(headers_string);
    if (sign != NULL) free(sign);

    return full_dkim;
}

void dkim_free(dkim_t* dkim) {
    mail_header_t* header = dkim->header;
    while (header) {
        mail_header_t* next = header->next;
        mail_header_free(header);
        header = next;
    }

    free(dkim);
}
