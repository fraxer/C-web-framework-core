#include "framework.h"
#include "mail.h"
#include "mailheader.h"
#include "smtprequest.h"
#include "dkim.h"
#include "base64.h"
#include "appconfig.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The internal helpers are not declared in mail.h; redeclare them here so the
 * pure string/date/content/header builders can be unit-tested in isolation.
 * (The network/TLS/MX paths — mail_is_real, __mail_connect, __mail_init_tls,
 *  send_mail_async — are not covered here; they need a live server.) */
void __mail_free(mail_t* instance);
const char* __mail_domain_from_email(const char* email);
int __mail_set_from(mail_t* instance, const char* email, const char* sender_name);
int __mail_set_to(mail_t* instance, const char* email);
int __mail_set_subject(mail_t* instance, const char* subject);
int __mail_set_date(mail_t* instance, time_t* rawtime);
int __mail_set_message_id(mail_t* instance, time_t* rawtime);
int __mail_set_content(mail_t* instance, const char* body);
int __mail_header_add(mail_t* instance, const char* key, const char* value);
size_t __mail_calc_content_length(mail_t* instance);
int __mail_data_append(char* data, size_t* pos, const char* string, const size_t length);
int __mail_build_content(mail_t* instance);

/* -------------------------------------------------------------------------- */
/* Test helpers                                                               */
/* -------------------------------------------------------------------------- */

/* Generate a fresh RSA-2048 keypair and serialize the private key to a
 * NUL-terminated PEM string. Caller frees both the PEM and the pkey. Mirrors
 * the helper in test_dkim.c. */
static EVP_PKEY* mail_test_generate_keypair(void) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) pkey = NULL;

done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static char* mail_test_private_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) return NULL;

    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return NULL;
    }

    BUF_MEM* bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);

    char* pem = malloc(bptr->length + 1);
    if (pem != NULL) {
        memcpy(pem, bptr->data, bptr->length);
        pem[bptr->length] = '\0';
    }

    BIO_free(bio);
    return pem;
}

/* Populate the mail config fields that the date/message-id/build paths read.
 * The runner's env() returns a calloc'd appconfig, so these are NULL until set. */
static void mail_test_env_setup(const char* host, const char* selector, const char* pem) {
    env()->mail.host = (char*)host;
    env()->mail.dkim_selector = (char*)selector;
    env()->mail.dkim_private = (char*)pem;
}

/* Pointer to the token after the last space in s (i.e. the trailing timezone
 * offset of a Date: header), or s itself if there is no space. */
static const char* mail_test_tail_token(const char* s) {
    const char* tail = s;
    for (const char* p = s; *p; p++)
        if (*p == ' ')
            tail = p + 1;
    return tail;
}

/* True iff s is a valid RFC 5322 numeric offset: sign + exactly 4 digits. */
static int mail_test_is_numeric_offset(const char* s) {
    if (s == NULL) return 0;
    if (*s != '+' && *s != '-') return 0;
    if (strlen(s) != 5) return 0;
    for (int i = 1; i < 5; i++)
        if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

/* Substring search over a buffer that may NOT be NUL-terminated (the assembled
 * mail content is malloc'd to exactly content_size bytes). Uses explicit
 * lengths so it never reads past the allocation. */
static int mail_test_contains(const char* hay, size_t hay_len, const char* needle) {
    const size_t nl = strlen(needle);
    if (nl == 0 || nl > hay_len) return 0;
    for (size_t i = 0; i + nl <= hay_len; i++)
        if (memcmp(hay + i, needle, nl) == 0) return 1;
    return 0;
}

/* Decode the RFC 2047 "=?UTF-8?B?...?= " payload inside `encoded` back to the
 * original bytes. Heap-allocated, caller frees; NULL on malformed input. */
static char* mail_test_decode_word(const char* encoded) {
    const char* start = strstr(encoded, "=?UTF-8?B?");
    if (start == NULL) start = strstr(encoded, "=?utf-8?B?");
    if (start == NULL) return NULL;
    start += strlen("=?UTF-8?B?");

    const char* end = strstr(start, "?=");
    if (end == NULL) return NULL;

    size_t b64_len = (size_t)(end - start);
    char* b64 = malloc(b64_len + 1);
    if (b64 == NULL) return NULL;
    memcpy(b64, start, b64_len);
    b64[b64_len] = '\0';

    int cap = base64_decode_len(b64);
    char* plain = malloc(cap > 0 ? (size_t)cap : 1);
    if (plain == NULL) {
        free(b64);
        return NULL;
    }
    int n = base64_decode(plain, b64);
    plain[n > 0 ? n : 0] = '\0';

    free(b64);
    return plain;
}

/* -------------------------------------------------------------------------- */
/* __mail_domain_from_email                                                   */
/* -------------------------------------------------------------------------- */

TEST(test_mail_domain_from_email_basic) {
    TEST_CASE("extracts the domain after '@'");

    TEST_ASSERT_STR_EQUAL("example.com", __mail_domain_from_email("user@example.com"), "simple domain");
    TEST_ASSERT_STR_EQUAL("sub.example.com", __mail_domain_from_email("user@sub.example.com"), "multi-label domain");
}

TEST(test_mail_domain_from_email_guards) {
    TEST_CASE("returns NULL for NULL input or missing '@'");

    TEST_ASSERT_NULL(__mail_domain_from_email(NULL), "NULL email does not crash");
    TEST_ASSERT_NULL(__mail_domain_from_email("noatsign"), "no '@' returns NULL");
    TEST_ASSERT_NULL(__mail_domain_from_email(""), "empty string returns NULL");
}

TEST(test_mail_domain_from_email_edge_local_part) {
    TEST_CASE("empty local part still yields the domain");

    TEST_ASSERT_STR_EQUAL("example.com", __mail_domain_from_email("@example.com"), "leading '@'");
}

/* -------------------------------------------------------------------------- */
/* __mail_set_from / set_to / set_subject                                     */
/* -------------------------------------------------------------------------- */

TEST(test_mail_set_from_structure) {
    TEST_CASE("From wraps the sender name in RFC 2047 base64 and frames the address");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    int ok = __mail_set_from(m, "alice@example.com", "Alice");
    TEST_ASSERT_EQUAL(1, ok, "set_from returns 1");
    TEST_ASSERT_NOT_NULL(m->from_with_name.value, "from_with_name allocated");
    TEST_ASSERT(m->from_with_name.length > 0, "from_with_name length positive");

    /* RFC 2047 word + framed address both present */
    TEST_ASSERT(strstr(m->from_with_name.value, "=?UTF-8?B?") != NULL, "contains encoded-word marker");
    TEST_ASSERT(strstr(m->from_with_name.value, "<alice@example.com>") != NULL, "contains framed address");

    /* The base64 payload decodes back to the original sender name */
    char* plain = mail_test_decode_word(m->from_with_name.value);
    TEST_REQUIRE_NOT_NULL(plain, "encoded word decodes");
    TEST_ASSERT_STR_EQUAL("Alice", plain, "sender name round-trips through base64");
    free(plain);

    /* Bare From: is just the framed address */
    TEST_ASSERT_NOT_NULL(m->from.value, "from allocated");
    TEST_ASSERT_STR_EQUAL("<alice@example.com>", m->from.value, "bare from is framed address");

    __mail_free(m);
}

TEST(test_mail_set_from_rejects_null) {
    TEST_CASE("set_from rejects NULL email / sender_name");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(0, __mail_set_from(m, NULL, "Alice"), "NULL email");
    TEST_ASSERT_EQUAL(0, __mail_set_from(m, "a@b.c", NULL), "NULL sender_name");
    TEST_ASSERT_NULL(m->from.value, "nothing allocated on rejection");

    __mail_free(m);
}

TEST(test_mail_set_to_structure) {
    TEST_CASE("To frames the address");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(1, __mail_set_to(m, "bob@example.com"), "set_to returns 1");
    TEST_ASSERT_STR_EQUAL("<bob@example.com>", m->to.value, "to is framed address");
    TEST_ASSERT_EQUAL((int)strlen("<bob@example.com>"), (int)m->to.length, "to length matches");

    TEST_ASSERT_EQUAL(0, __mail_set_to(m, NULL), "NULL email rejected");

    __mail_free(m);
}

TEST(test_mail_set_subject_structure) {
    TEST_CASE("Subject is wrapped as an RFC 2047 base64 encoded word");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(1, __mail_set_subject(m, "Hello World"), "set_subject returns 1");
    TEST_ASSERT(strstr(m->subject.value, "=?UTF-8?B?") != NULL, "subject is an encoded word");
    TEST_ASSERT(strstr(m->subject.value, "?=") != NULL, "encoded word is terminated");

    char* plain = mail_test_decode_word(m->subject.value);
    TEST_REQUIRE_NOT_NULL(plain, "subject decodes");
    TEST_ASSERT_STR_EQUAL("Hello World", plain, "subject round-trips through base64");
    free(plain);

    TEST_ASSERT_EQUAL(0, __mail_set_subject(m, NULL), "NULL subject rejected");

    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* __mail_set_date (the timezone regression)                                  */
/* -------------------------------------------------------------------------- */

TEST(test_mail_set_date_format_valid) {
    TEST_CASE("Date header ends in a valid numeric +HHMM / -HHMM offset");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    time_t rawtime = 1700000000; /* fixed instant */
    TEST_ASSERT_EQUAL(1, __mail_set_date(m, &rawtime), "set_date returns 1");
    TEST_ASSERT_NOT_NULL(m->date.value, "date allocated");
    TEST_ASSERT(m->date.length > 0, "date length positive");

    /* Weekday and month tokens render (non-empty), and the trailing offset is
     * a sign + 4 digits. The buggy implementation emits "-0-500" here, which
     * fails the numeric-offset check. */
    const char* tail = mail_test_tail_token(m->date.value);
    TEST_ASSERT(mail_test_is_numeric_offset(tail), "trailing token is a numeric offset");

    __mail_free(m);
}

TEST(test_mail_set_date_negative_offset_regression) {
    TEST_CASE("negative timezone renders -0500, not -0-500, regardless of host TZ");

    /* Force a negative offset (EST = UTC-5) so the regression is exercised
     * deterministically on any host. timezone_offset() reads localtime(), which
     * honors TZ after tzset(). */
    const char* saved_tz = getenv("TZ");
    setenv("TZ", "EST5", 1);
    tzset();

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(1, __mail_set_date(m, &rawtime), "set_date returns 1 under EST");

    const char* tail = mail_test_tail_token(m->date.value);
    TEST_ASSERT_STR_EQUAL("-0500", tail, "EST renders as -0500 (regression: was -0-500)");

    __mail_free(m);

    /* Restore the process timezone. */
    if (saved_tz != NULL) setenv("TZ", saved_tz, 1);
    else unsetenv("TZ");
    tzset();
}

TEST(test_mail_set_date_guards) {
    TEST_CASE("set_date rejects NULL instance / rawtime");

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(0, __mail_set_date(NULL, &rawtime), "NULL instance");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");
    TEST_ASSERT_EQUAL(0, __mail_set_date(m, NULL), "NULL rawtime");
    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* __mail_set_message_id                                                      */
/* -------------------------------------------------------------------------- */

TEST(test_mail_set_message_id_structure) {
    TEST_CASE("Message-Id is <digits@host>");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    mail_test_env_setup("example.com", "selector", NULL);

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(1, __mail_set_message_id(m, &rawtime), "set_message_id returns 1");
    TEST_ASSERT_NOT_NULL(m->message_id.value, "message_id allocated");

    /* Shaped as <...@example.com> */
    TEST_ASSERT_EQUAL('<', m->message_id.value[0], "starts with '<'");
    TEST_ASSERT(strstr(m->message_id.value, "@example.com>") != NULL, "ends with @host>");

    /* The part between '<' and '@' is all digits (the timestamp). */
    const char* at = strchr(m->message_id.value, '@');
    TEST_ASSERT_NOT_NULL(at, "has an '@'");
    int all_digits = 1;
    for (const char* p = m->message_id.value + 1; p < at; p++)
        if (*p < '0' || *p > '9') { all_digits = 0; break; }
    TEST_ASSERT(all_digits, "local part is the timestamp digits");

    __mail_free(m);
}

TEST(test_mail_set_message_id_guards) {
    TEST_CASE("set_message_id rejects NULL instance / rawtime");

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(0, __mail_set_message_id(NULL, &rawtime), "NULL instance");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");
    TEST_ASSERT_EQUAL(0, __mail_set_message_id(m, NULL), "NULL rawtime");
    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* __mail_set_content                                                         */
/* -------------------------------------------------------------------------- */

TEST(test_mail_set_content_null_guard) {
    TEST_CASE("NULL body is rejected without dereferencing");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(0, __mail_set_content(m, NULL), "NULL body returns 0 (no crash)");
    TEST_ASSERT_NULL(m->data, "nothing allocated on NULL body");
    TEST_ASSERT_EQUAL(0, (int)m->data_size, "data_size stays 0");

    __mail_free(m);
}

TEST(test_mail_set_content_encodes_body) {
    TEST_CASE("body is base64-encoded with a positive data_size");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    const char* body = "Hello, mail body!";
    TEST_ASSERT_EQUAL(1, __mail_set_content(m, body), "set_content returns 1");
    TEST_ASSERT_NOT_NULL(m->data, "data allocated");
    TEST_ASSERT(m->data_size > 0, "data_size positive");

    /* base64 of a non-empty body is non-empty and contains only base64 chars /
     * newlines (the wrapped variant). Decoding round-trips to the body. */
    char* plain = malloc(base64_decode_len(m->data) > 0 ? (size_t)base64_decode_len(m->data) : 1);
    TEST_REQUIRE_NOT_NULL(plain, "decode buffer");
    int n = base64_decode(plain, m->data);
    plain[n > 0 ? n : 0] = '\0';
    TEST_ASSERT_STR_EQUAL(body, plain, "body round-trips through base64");
    free(plain);

    __mail_free(m);
}

TEST(test_mail_set_content_replaces_previous) {
    TEST_CASE("calling set_content twice frees the previous buffer (no leak)");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(1, __mail_set_content(m, "first body"), "first set");
    TEST_ASSERT_EQUAL(1, __mail_set_content(m, "second body, longer"), "second set");

    /* That the *old* buffer is gone is the leak detector's job (ASan/LSan), not
     * an assertion we can make here: comparing the new pointer against the freed
     * one reads a dangling value and assumes the allocator will not hand the
     * same address back — which it does under TSan's allocator. What is
     * actually guaranteed is that the second body replaced the first. */
    const char* expected = "second body, longer";
    char* plain = malloc(strlen(expected) + 4);
    TEST_REQUIRE_NOT_NULL(plain, "decode buffer");

    const int n = base64_decode(plain, m->data);
    plain[n > 0 ? n : 0] = '\0';
    TEST_ASSERT_STR_EQUAL(expected, plain, "buffer holds the second body");
    free(plain);

    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* __mail_header_add / calc_content_length / data_append                      */
/* -------------------------------------------------------------------------- */

TEST(test_mail_header_add_chain) {
    TEST_CASE("headers form an ordered chain");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(1, __mail_header_add(m, "From", "a@b.c"), "add From");
    TEST_ASSERT_EQUAL(1, __mail_header_add(m, "Subject", "Hi"), "add Subject");
    TEST_ASSERT_EQUAL(0, __mail_header_add(m, "", "x"), "empty key rejected");
    TEST_ASSERT_EQUAL(0, __mail_header_add(m, "X", ""), "empty value rejected");
    TEST_ASSERT_EQUAL(0, __mail_header_add(m, NULL, "x"), "NULL key rejected");

    mail_header_t* h = m->_header;
    TEST_ASSERT_STR_EQUAL("From", h->key, "first header key");
    h = h->next;
    TEST_ASSERT_STR_EQUAL("Subject", h->key, "second header key");
    TEST_ASSERT_NULL(h->next, "chain terminates");

    __mail_free(m);
}

TEST(test_mail_calc_content_length_exact_fit) {
    TEST_CASE("assembling headers + terminator writes exactly content_length bytes");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    __mail_header_add(m, "From", "a@b.c");      /* 4 + 2 + 5 + 2 = 13 */
    __mail_header_add(m, "Subject", "Hi");      /* 7 + 2 + 2 + 2 = 13 */

    const size_t total = __mail_calc_content_length(m);
    /* headers(26) + blank line(2) + body(0) + terminator(5) = 33 */
    TEST_ASSERT_EQUAL(33, (int)total, "content length is the exact byte count");

    char* buf = malloc(total);
    TEST_REQUIRE_NOT_NULL(buf, "allocate buffer");

    /* Reproduce the assembly done in __mail_build_content. */
    size_t pos = 0;
    mail_header_t* h = m->_header;
    while (h) {
        __mail_data_append(buf, &pos, h->key, h->key_length);
        __mail_data_append(buf, &pos, ": ", 2);
        __mail_data_append(buf, &pos, h->value, h->value_length);
        __mail_data_append(buf, &pos, "\r\n", 2);
        h = h->next;
    }
    __mail_data_append(buf, &pos, "\r\n", 2);
    __mail_data_append(buf, &pos, "", 0);            /* zero-length body */
    __mail_data_append(buf, &pos, "\r\n.\r\n", 5);

    /* Writing exactly `total` bytes (no overflow, no shortfall) is what
     * __mail_calc_content_length guarantees; ASan flags any overrun. */
    TEST_ASSERT_EQUAL(total, pos, "bytes written == content_length");

    /* The terminator must be present at the end of the assembled content.
     * buf is not NUL-terminated, so search by explicit length. */
    TEST_ASSERT(mail_test_contains(buf, pos, "\r\n.\r\n"), "content ends with the DATA terminator");

    free(buf);
    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* __mail_build_content (end-to-end header + body + DKIM assembly)            */
/* -------------------------------------------------------------------------- */

TEST(test_mail_build_content_assembles_message) {
    TEST_CASE("build_content produces a complete, terminated MIME message");

    EVP_PKEY* pkey = mail_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = mail_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    mail_test_env_setup("example.com", "selector", pem);

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    /* A request_data is normally created in __mail_connect; for a unit test we
     * allocate it directly. smtprequest_data_create does not deref its
     * connection argument, so NULL is safe here. */
    m->request_data = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(m->request_data, "request_data allocated");

    TEST_ASSERT_EQUAL(1, __mail_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, __mail_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, __mail_set_subject(m, "Hello"), "set_subject");
    TEST_ASSERT_EQUAL(1, __mail_set_content(m, "Hello, body!"), "set_content");

    TEST_ASSERT_EQUAL(1, __mail_build_content(m), "build_content returns 1");

    smtprequest_data_t* rd = m->request_data;
    TEST_ASSERT_NOT_NULL(rd->content, "content buffer allocated");
    TEST_ASSERT(rd->content_size > 0, "content_size positive");

    /* rd->content is malloc'd to exactly content_size bytes (NOT NUL-terminated),
     * so search by explicit length — a plain strstr would read past the buffer. */
    const char* c = rd->content;
    const size_t cs = rd->content_size;

    /* All expected headers are present, in order-agnostic fashion. */
    TEST_ASSERT(mail_test_contains(c, cs, "From:"), "has From header");
    TEST_ASSERT(mail_test_contains(c, cs, "To:"), "has To header");
    TEST_ASSERT(mail_test_contains(c, cs, "Subject:"), "has Subject header");
    TEST_ASSERT(mail_test_contains(c, cs, "Date:"), "has Date header");
    TEST_ASSERT(mail_test_contains(c, cs, "Message-Id:"), "has Message-Id header");
    TEST_ASSERT(mail_test_contains(c, cs, "DKIM-Signature:"), "has DKIM-Signature header");
    TEST_ASSERT(mail_test_contains(c, cs, "MIME-Version:"), "has MIME-Version header");
    TEST_ASSERT(mail_test_contains(c, cs, "Content-Transfer-Encoding: base64"), "has base64 CTE");

    /* Message terminates with the SMTP end-of-data marker. */
    TEST_ASSERT(mail_test_contains(c, cs, "\r\n.\r\n"), "ends with DATA terminator");

    __mail_free(m);
    free(pem);
    EVP_PKEY_free(pkey);
}

TEST(test_mail_build_content_no_leak) {
    TEST_CASE("a full build + free cycle is leak-free under ASan");

    EVP_PKEY* pkey = mail_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = mail_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    mail_test_env_setup("example.com", "selector", pem);

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");
    m->request_data = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(m->request_data, "request_data allocated");

    __mail_set_from(m, "alice@example.com", "Alice");
    __mail_set_to(m, "bob@example.com");
    __mail_set_subject(m, "Hi");
    __mail_set_content(m, "leak check body");
    __mail_build_content(m);

    __mail_free(m);
    free(pem);
    EVP_PKEY_free(pkey);
}

/* -------------------------------------------------------------------------- */
/* __mail_build_content without DKIM (S.6)                                    */
/* -------------------------------------------------------------------------- */

TEST(test_mail_build_content_without_dkim_key) {
    TEST_CASE("an empty DKIM key produces an unsigned message instead of no message");

    /* The regression this covers: dkim_create_sign() returns NULL when the key
     * is unset, __mail_build_content used to treat that as fatal, and every
     * send from a configuration without DKIM failed with "Failed to send mail"
     * — while config.md documented the opposite. */
    mail_test_env_setup("example.com", "", "");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    m->request_data = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(m->request_data, "request_data allocated");

    TEST_ASSERT_EQUAL(1, __mail_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, __mail_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, __mail_set_subject(m, "Hello"), "set_subject");
    TEST_ASSERT_EQUAL(1, __mail_set_content(m, "Hello, body!"), "set_content");

    TEST_ASSERT_EQUAL(1, __mail_build_content(m), "build_content succeeds with no DKIM key");
    TEST_ASSERT_EQUAL(0, m->reseted, "the session is not marked reseted");

    smtprequest_data_t* rd = m->request_data;
    const char* c = rd->content;
    const size_t cs = rd->content_size;

    TEST_ASSERT_NOT_NULL(c, "content buffer allocated");
    TEST_ASSERT_EQUAL(0, mail_test_contains(c, cs, "DKIM-Signature:"), "no DKIM-Signature header");

    /* Everything else is still a complete message. */
    TEST_ASSERT(mail_test_contains(c, cs, "From:"), "has From header");
    TEST_ASSERT(mail_test_contains(c, cs, "To:"), "has To header");
    TEST_ASSERT(mail_test_contains(c, cs, "Subject:"), "has Subject header");
    TEST_ASSERT(mail_test_contains(c, cs, "Date:"), "has Date header");
    TEST_ASSERT(mail_test_contains(c, cs, "Message-Id:"), "has Message-Id header");
    TEST_ASSERT(mail_test_contains(c, cs, "MIME-Version:"), "has MIME-Version header");
    TEST_ASSERT(mail_test_contains(c, cs, "\r\n.\r\n"), "ends with DATA terminator");

    __mail_free(m);
}

TEST(test_mail_build_content_without_dkim_selector) {
    TEST_CASE("a key with no selector also yields an unsigned message");

    EVP_PKEY* pkey = mail_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = mail_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    mail_test_env_setup("example.com", "", pem);

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");
    m->request_data = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(m->request_data, "request_data allocated");

    __mail_set_from(m, "alice@example.com", "Alice");
    __mail_set_to(m, "bob@example.com");
    __mail_set_subject(m, "Hi");
    __mail_set_content(m, "body");

    TEST_ASSERT_EQUAL(1, __mail_build_content(m), "build_content succeeds");
    TEST_ASSERT_EQUAL(0, mail_test_contains(m->request_data->content, m->request_data->content_size, "DKIM-Signature:"),
        "no DKIM-Signature without a selector");

    __mail_free(m);
    free(pem);
    EVP_PKEY_free(pkey);
}

TEST(test_mail_message_id_without_host) {
    TEST_CASE("an unset mail.host still yields a syntactically valid Message-Id");

    /* Relay mode makes this routine: the sender's own domain is often not
     * configured at all, and an empty EHLO argument or "<...@>" is a syntax
     * error rather than a missing nicety. */
    mail_test_env_setup("", "", "");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(1, __mail_set_message_id(m, &rawtime), "set_message_id returns 1");
    TEST_ASSERT(strstr(m->message_id.value, "@") != NULL, "has an '@'");
    TEST_ASSERT(strstr(m->message_id.value, "@>") == NULL, "domain part is not empty");

    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* send_mail_result: why a send failed (S.7)                                   */
/* -------------------------------------------------------------------------- */

TEST(test_mail_result_reports_failure_reason) {
    TEST_CASE("a failed send fills the caller's mail_result_t");

    /* Relay mode against a port nothing listens on: no MX lookup, no DNS, and
     * connect() is refused immediately — which is also what proves the relay
     * path skips mail_is_real() entirely (the recipient domain here has no MX
     * and would have been rejected before a socket was ever opened). */
    mail_test_env_setup("example.com", "", "");

    env_mail_relay_t saved = env()->mail.relay;

    env()->mail.relay.enabled = true;
    env()->mail.relay.host = (char*)"127.0.0.1";
    env()->mail.relay.port = 1;   /* a privileged port nothing binds */
    env()->mail.relay.security = ENV_MAIL_SECURITY_NONE;
    env()->mail.relay.user = NULL;
    env()->mail.relay.password = NULL;
    env()->mail.relay.auth = ENV_MAIL_AUTH_AUTO;
    env()->mail.relay.timeout = 1;
    env()->mail.relay.verify = false;

    mail_payload_t payload = {
        .from = "alice@example.com",
        .from_name = "Alice",
        .to = "bob@invalid.invalid",
        .subject = "Hello",
        .body = "body"
    };

    mail_result_t result;
    memset(&result, 0xAA, sizeof(result));   /* the callee must fill every field */

    TEST_ASSERT_EQUAL(0, send_mail_result(&payload, &result), "send fails against a closed port");

    /* No reply ever arrived, so the code is 0 (as opposed to a 4xx/5xx the
     * caller could act on) and the text says which step gave up. */
    TEST_ASSERT_EQUAL(0, result.status, "no SMTP reply code when the connect fails");
    TEST_ASSERT_STR_EQUAL("Failed to connect", result.error, "the failing step is named");

    /* Plain send_mail() is the same call with no reporting, and must not fall
     * over on the NULL result. */
    TEST_ASSERT_EQUAL(0, send_mail(&payload), "send_mail() behaves identically");

    env()->mail.relay = saved;
}

TEST(test_mail_result_survives_a_second_send) {
    TEST_CASE("the answer belongs to the caller: a later send does not overwrite it");

    /* This is what the thread-local version could not do — its values were
     * valid only until the next send in the same thread. */
    mail_test_env_setup("example.com", "", "");

    env_mail_relay_t saved = env()->mail.relay;

    env()->mail.relay.enabled = true;
    env()->mail.relay.host = (char*)"127.0.0.1";
    env()->mail.relay.port = 1;
    env()->mail.relay.security = ENV_MAIL_SECURITY_NONE;
    env()->mail.relay.user = NULL;
    env()->mail.relay.password = NULL;
    env()->mail.relay.auth = ENV_MAIL_AUTH_AUTO;
    env()->mail.relay.timeout = 1;
    env()->mail.relay.verify = false;

    mail_payload_t payload = {
        .from = "alice@example.com",
        .from_name = "Alice",
        .to = "bob@invalid.invalid",
        .subject = "Hello",
        .body = "body"
    };

    mail_result_t first;
    TEST_ASSERT_EQUAL(0, send_mail_result(&payload, &first), "first send fails");

    mail_result_t second;
    TEST_ASSERT_EQUAL(0, send_mail_result(&payload, &second), "second send fails");

    TEST_ASSERT_STR_EQUAL("Failed to connect", first.error, "the first answer is still intact");
    TEST_ASSERT_EQUAL(0, first.status, "the first status is still intact");

    env()->mail.relay = saved;
}

TEST(test_mail_result_guards) {
    TEST_CASE("a rejected argument still leaves a usable result, and NULL is accepted");

    mail_result_t result;
    memset(&result, 0xAA, sizeof(result));

    TEST_ASSERT_EQUAL(0, send_mail_result(NULL, &result), "NULL payload returns 0");
    TEST_ASSERT_EQUAL(0, result.status, "status cleared");
    TEST_ASSERT_EQUAL(0, result.error[0], "error cleared, not left uninitialised");

    TEST_ASSERT_EQUAL(0, send_mail_result(NULL, NULL), "a NULL result is not dereferenced");
    TEST_ASSERT_EQUAL(0, send_mail(NULL), "send_mail(NULL) returns 0");
}

TEST(test_mail_set_error_trims_and_clears) {
    TEST_CASE("mail_set_error stores the reason on the session, trimming the reply CRLF");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(0, m->last_status, "a new session has no recorded status");
    TEST_ASSERT_EQUAL(0, m->last_error[0], "a new session has no recorded error");

    mail_set_error(m, 535, "535 5.7.8 Error: authentication failed\r\n");
    TEST_ASSERT_EQUAL(535, m->last_status, "status stored");
    TEST_ASSERT_STR_EQUAL("535 5.7.8 Error: authentication failed", m->last_error, "CRLF trimmed");

    mail_set_error(m, 0, NULL);
    TEST_ASSERT_EQUAL(0, m->last_status, "status cleared");
    TEST_ASSERT_EQUAL(0, m->last_error[0], "a NULL message clears the text");

    mail_set_error(NULL, 500, "ignored");   /* must not dereference */

    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* Relay: EHLO capabilities, the STARTTLS gate and AUTH (S.3, S.4)            */
/* -------------------------------------------------------------------------- */

/* These drive the real client over an AF_UNIX socketpair, the way
 * test_smtpclienthandlers.c does: the server side of the exchange is staged
 * into the peer end up front, so the client's blocking read always finds its
 * reply waiting. No TLS is involved — "security": "none" is a configured mode,
 * and it is the one that leaves the SMTP dialogue readable.
 *
 * SOCK_SEQPACKET rather than SOCK_STREAM, because the client reads one reply
 * per recv(): over a stream, several staged replies coalesce into a single
 * recv, the parser completes on the first and the rest of the buffer is
 * dropped. A real server never gets ahead of the client like that; the packet
 * boundaries reproduce the one-reply-per-read the client actually sees. */

int __mail_connection_setup(mail_t* instance, const int fd, const unsigned short port);
int __mail_send_hello(mail_t* instance);
int __mail_start_tls(mail_t* instance);
int __mail_auth(mail_t* instance);

typedef struct {
    mail_t* mail;
    int peer_fd;
    env_mail_relay_t saved_relay;
} mail_relay_harness_t;

static void mail_relay_harness_free(mail_relay_harness_t* h) {
    if (h->mail != NULL) {
        h->mail->free(h->mail);   /* closes the client end of the pair */
        h->mail = NULL;
    }
    if (h->peer_fd != -1) {
        close(h->peer_fd);
        h->peer_fd = -1;
    }

    env()->mail.relay = h->saved_relay;
}

/* A connected mail_t whose socket is one end of a socketpair, plus a relay
 * configuration with credentials. The caller stages the server's replies with
 * mail_relay_stage() before each client step. */
static int mail_relay_harness_init(mail_relay_harness_t* h, env_mail_security_e security, env_mail_auth_e auth) {
    memset(h, 0, sizeof *h);
    h->peer_fd = -1;
    h->saved_relay = env()->mail.relay;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0) return 0;

    /* A read that finds nothing staged must fail rather than hang the suite. */
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    h->mail = mail_create();
    if (h->mail == NULL) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    if (!__mail_connection_setup(h->mail, fds[0], 587)) {
        h->mail->free(h->mail);
        h->mail = NULL;
        close(fds[1]);
        return 0;
    }

    h->peer_fd = fds[1];

    env()->mail.relay.enabled = true;
    env()->mail.relay.host = (char*)"relay.example.org";
    env()->mail.relay.port = 587;
    env()->mail.relay.security = security;
    env()->mail.relay.auth = auth;
    env()->mail.relay.user = (char*)"info@example.com";
    env()->mail.relay.password = (char*)"s3cret";
    env()->mail.relay.timeout = 2;
    env()->mail.relay.verify = false;

    return 1;
}

/* One staged reply — one datagram, hence one recv() on the client side. */
static void mail_relay_stage(mail_relay_harness_t* h, const char* reply) {
    const ssize_t n = write(h->peer_fd, reply, strlen(reply));
    (void)n;
}

/* Everything the client has written so far, concatenated and NUL-terminated.
 * Non-blocking, so an empty socket yields "" instead of hanging. */
static size_t mail_relay_sent(mail_relay_harness_t* h, char* out, size_t size) {
    const int flags = fcntl(h->peer_fd, F_GETFL, 0);
    fcntl(h->peer_fd, F_SETFL, flags | O_NONBLOCK);

    size_t total = 0;
    while (total + 1 < size) {
        const ssize_t n = read(h->peer_fd, out + total, size - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
    }
    out[total] = '\0';

    fcntl(h->peer_fd, F_SETFL, flags);
    return total;
}

/* The base64 argument of the client's "AUTH PLAIN <arg>" line, decoded. Returns
 * the decoded length, or -1 when the line is not there. */
static int mail_relay_decode_auth_plain(const char* sent, char* out, size_t size) {
    const char* start = strstr(sent, "AUTH PLAIN ");
    if (start == NULL) return -1;
    start += strlen("AUTH PLAIN ");

    const char* end = strstr(start, "\r\n");
    if (end == NULL) return -1;

    char b64[512];
    const size_t length = (size_t)(end - start);
    if (length >= sizeof(b64)) return -1;
    memcpy(b64, start, length);
    b64[length] = '\0';

    const int decoded = base64_decode(out, b64);
    if (decoded < 0 || (size_t)decoded >= size) return -1;

    return decoded;
}

TEST(test_mail_relay_auth_plain) {
    TEST_SUITE("Mail relay - AUTH");
    TEST_CASE("AUTH PLAIN sends base64(\\0user\\0password) and accepts 235");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250-SIZE 10240000\r\n"
        "250-AUTH PLAIN LOGIN\r\n"
        "250 HELP\r\n");
    mail_relay_stage(&h, "235 2.7.0 Authentication successful\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "AUTH succeeds");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));

    TEST_ASSERT(strstr(sent, "EHLO ") != NULL, "EHLO was sent");
    TEST_ASSERT(strstr(sent, "AUTH PLAIN ") != NULL, "PLAIN was chosen over LOGIN");
    TEST_ASSERT_NULL(strstr(sent, "s3cret"), "the password never appears in the clear");

    /* RFC 4616: an empty authorization identity, the login and the password,
     * NUL-separated. */
    char decoded[256];
    const int decoded_length = mail_relay_decode_auth_plain(sent, decoded, sizeof(decoded));
    const char expected[] = "\0info@example.com\0s3cret";

    TEST_ASSERT_EQUAL((int)sizeof(expected) - 1, decoded_length, "decoded credential has the expected length");
    if (decoded_length == (int)sizeof(expected) - 1)
        TEST_ASSERT_EQUAL(0, memcmp(decoded, expected, sizeof(expected) - 1), "decodes to \\0user\\0password");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_login) {
    TEST_CASE("AUTH LOGIN answers both 334 challenges with base64 of user and password");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    /* Only LOGIN is offered, so "auto" has to fall back to it. */
    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH LOGIN\r\n");
    mail_relay_stage(&h, "334 VXNlcm5hbWU6\r\n");
    mail_relay_stage(&h, "334 UGFzc3dvcmQ6\r\n");
    mail_relay_stage(&h, "235 2.7.0 Authentication successful\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "AUTH succeeds");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));

    TEST_ASSERT(strstr(sent, "AUTH LOGIN\r\n") != NULL, "LOGIN was chosen when PLAIN is not offered");
    TEST_ASSERT_NULL(strstr(sent, "AUTH PLAIN"), "PLAIN was not attempted");
    TEST_ASSERT_NULL(strstr(sent, "s3cret"), "the password never appears in the clear");

    /* base64("info@example.com") and base64("s3cret"), each on its own line. */
    TEST_ASSERT(strstr(sent, "aW5mb0BleGFtcGxlLmNvbQ==\r\n") != NULL, "login sent as base64");
    TEST_ASSERT(strstr(sent, "czNjcmV0\r\n") != NULL, "password sent as base64");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_bad_credentials) {
    TEST_CASE("a 535 reply fails the send instead of continuing unauthenticated");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_PLAIN), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH PLAIN LOGIN\r\n");
    mail_relay_stage(&h, "535 5.7.8 Error: authentication failed\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "AUTH fails on 535");
    TEST_ASSERT_EQUAL(1, h.mail->reseted, "the session is marked unusable");

    /* A manually driven sequence gets the reason too, without going through
     * send_mail() -- which is what putting the state on mail_t is for. */
    TEST_ASSERT_EQUAL(535, h.mail->last_status, "the reply code is on the session");
    TEST_ASSERT_STR_EQUAL("535 5.7.8 Error: authentication failed", h.mail->last_error,
        "the server's own words, CRLF trimmed");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_mechanism_not_offered) {
    TEST_CASE("an explicitly configured mechanism the server does not offer is an error, not a fallback");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_PLAIN), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH LOGIN\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "auth: plain against a LOGIN-only server fails");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no AUTH command was attempted");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_not_offered_at_all) {
    TEST_CASE("a server announcing no AUTH is an error rather than a silent skip");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 SIZE 10240000\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "AUTH refused when unannounced");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_refuses_plaintext) {
    TEST_CASE("credentials are not sent in the clear unless security is \"none\"");

    /* security: "starttls" with no TLS on the socket is the dangerous case: it
     * means the upgrade did not happen and the password would go out readable. */
    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_STARTTLS, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH PLAIN LOGIN\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "AUTH refused over an unencrypted socket");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no credentials left the process");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_skipped_without_credentials) {
    TEST_CASE("no user configured means no AUTH — an open internal relay is a valid setup");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    env()->mail.relay.user = NULL;
    env()->mail.relay.password = NULL;

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH PLAIN LOGIN\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "auth is a no-op without credentials");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no AUTH command sent");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_skipped_in_direct_mode) {
    TEST_CASE("direct delivery never authenticates, whatever else is configured");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    env()->mail.relay.enabled = false;

    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "auth is a no-op in direct mode");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no AUTH command sent");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_starttls_requires_announcement) {
    TEST_CASE("STARTTLS is not sent to a server that did not announce it");

    /* Before the EHLO reply was parsed this was decided by the reply code to a
     * STARTTLS sent blind. */
    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_STARTTLS, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 SIZE 10240000\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_start_tls(h.mail), "start_tls refuses without the announcement");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "STARTTLS"), "no STARTTLS command was written");

    /* Not described by the latest reply, which is the EHLO's own 250: the step
     * has to name its own reason. */
    TEST_ASSERT_EQUAL(0, h.mail->last_status, "no reply code -- nothing was rejected");
    TEST_ASSERT_STR_EQUAL("Server does not offer STARTTLS", h.mail->last_error, "the step names itself");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_ehlo_rejection_is_an_error) {
    TEST_CASE("a non-250 EHLO reply fails instead of leaving stale capabilities");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h, "502 5.5.1 Command not implemented\r\n");

    TEST_ASSERT_EQUAL(0, __mail_send_hello(h.mail), "EHLO rejection is reported");
    TEST_ASSERT_EQUAL(1, h.mail->reseted, "the session is marked unusable");
    TEST_ASSERT_EQUAL(502, h.mail->last_status, "the rejection code is on the session");

    mail_relay_harness_free(&h);
}
