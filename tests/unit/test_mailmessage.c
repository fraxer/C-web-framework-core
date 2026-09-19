#define _GNU_SOURCE
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>

#include "framework.h"
#include "appconfig.h"
#include "base64.h"
#include "mailmessage.h"

/* env() runner'а — calloc'd appconfig; выставляем только то, что читает сборка */
static void mailmessage_test_env(const char* host) {
    env()->mail.host = (char*)host;
    env()->mail.dkim_private = NULL;
    env()->mail.dkim_selector = NULL;
}

static void mailmessage_test_fixed_clock(void) {
    setenv("TZ", "UTC", 1);
    tzset();
    setlocale(LC_ALL, "C");
}

TEST(test_mailmessage_build_golden_no_attachments) {
    TEST_SUITE("mailmessage");
    TEST_CASE("без вложений письмо собирается байт-в-байт как раньше");

    mailmessage_test_fixed_clock();
    mailmessage_test_env("example.com");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "создание");

    TEST_REQUIRE(mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_REQUIRE(mail_message_set_to(m, "bob@example.org"), "set_to");
    TEST_REQUIRE(mail_message_set_subject(m, "Subject"), "set_subject");
    mail_message_set_body(m, "<html>body</html>");

    TEST_REQUIRE(mail_message_build(m, (time_t)1760000000), "сборка");

    /* base64-полезные нагрузки считаем библиотекой (они фиксируются отдельными
     * тестами), а порядок и формат строк — жёстко. */
    char name_b64[64];
    base64_encode(name_b64, "Alice", 5);

    char expected[2048];
    snprintf(expected, sizeof(expected),
        "From: =?UTF-8?B?%s?= <alice@example.com>\r\n"
        "To: <bob@example.org>\r\n"
        "Subject: =?UTF-8?B?U3ViamVjdA==?=\r\n"
        "Date: Thu, 09 Oct 2025 08:53:20 +0000\r\n"
        "Message-Id: <20251009085320@example.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "PGh0bWw+Ym9keTwvaHRtbD4="
        "\r\n.\r\n",
        name_b64);

    TEST_ASSERT_EQUAL(strlen(expected), m->data_size, "размер буфера");
    TEST_ASSERT_EQUAL(0, memcmp(expected, m->data, m->data_size), "байты совпадают");

    mail_message_free(m);
}

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
 * mail content is malloc'd to exactly data_size bytes). Uses explicit
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
/* mail_message_set_from / set_to / set_subject                               */
/* -------------------------------------------------------------------------- */

TEST(test_mailmessage_set_from_structure) {
    TEST_CASE("From wraps the sender name in RFC 2047 base64 and frames the address");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    int ok = mail_message_set_from(m, "alice@example.com", "Alice");
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

    mail_message_free(m);
}

TEST(test_mailmessage_set_from_rejects_null) {
    TEST_CASE("set_from rejects NULL email / sender_name");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(0, mail_message_set_from(m, NULL, "Alice"), "NULL email");
    TEST_ASSERT_EQUAL(0, mail_message_set_from(m, "a@b.c", NULL), "NULL sender_name");
    TEST_ASSERT_NULL(m->from.value, "nothing allocated on rejection");

    mail_message_free(m);
}

TEST(test_mailmessage_set_to_structure) {
    TEST_CASE("To frames the address");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to returns 1");
    TEST_ASSERT_STR_EQUAL("<bob@example.com>", m->to.value, "to is framed address");
    TEST_ASSERT_EQUAL((int)strlen("<bob@example.com>"), (int)m->to.length, "to length matches");

    TEST_ASSERT_EQUAL(0, mail_message_set_to(m, NULL), "NULL email rejected");

    mail_message_free(m);
}

TEST(test_mailmessage_set_subject_structure) {
    TEST_CASE("Subject is wrapped as an RFC 2047 base64 encoded word");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello World"), "set_subject returns 1");
    TEST_ASSERT(strstr(m->subject.value, "=?UTF-8?B?") != NULL, "subject is an encoded word");
    TEST_ASSERT(strstr(m->subject.value, "?=") != NULL, "encoded word is terminated");

    char* plain = mail_test_decode_word(m->subject.value);
    TEST_REQUIRE_NOT_NULL(plain, "subject decodes");
    TEST_ASSERT_STR_EQUAL("Hello World", plain, "subject round-trips through base64");
    free(plain);

    TEST_ASSERT_EQUAL(0, mail_message_set_subject(m, NULL), "NULL subject rejected");

    mail_message_free(m);
}

/* -------------------------------------------------------------------------- */
/* Date (the timezone regression); reachable through build                    */
/* -------------------------------------------------------------------------- */

TEST(test_mailmessage_set_date_format_valid) {
    TEST_CASE("Date header ends in a valid numeric +HHMM / -HHMM offset");

    mail_test_env_setup("", "", "");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, "body");
    time_t rawtime = 1700000000; /* fixed instant */
    TEST_ASSERT_EQUAL(1, mail_message_build(m, rawtime), "build returns 1");
    TEST_ASSERT_NOT_NULL(m->date.value, "date allocated");
    TEST_ASSERT(m->date.length > 0, "date length positive");

    /* Weekday and month tokens render (non-empty), and the trailing offset is
     * a sign + 4 digits. The buggy implementation emits "-0-500" here, which
     * fails the numeric-offset check. */
    const char* tail = mail_test_tail_token(m->date.value);
    TEST_ASSERT(mail_test_is_numeric_offset(tail), "trailing token is a numeric offset");

    mail_message_free(m);
}

TEST(test_mailmessage_set_date_negative_offset_regression) {
    TEST_CASE("negative timezone renders -0500, not -0-500, regardless of host TZ");

    /* Force a negative offset (EST = UTC-5) so the regression is exercised
     * deterministically on any host. timezone_offset() reads localtime(), which
     * honors TZ after tzset(). */
    const char* saved_tz = getenv("TZ");
    setenv("TZ", "EST5", 1);
    tzset();

    mail_test_env_setup("", "", "");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, "body");
    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(1, mail_message_build(m, rawtime), "build returns 1 under EST");

    const char* tail = mail_test_tail_token(m->date.value);
    TEST_ASSERT_STR_EQUAL("-0500", tail, "EST renders as -0500 (regression: was -0-500)");

    mail_message_free(m);

    /* Restore the process timezone. */
    if (saved_tz != NULL) setenv("TZ", saved_tz, 1);
    else unsetenv("TZ");
    tzset();
}

TEST(test_mailmessage_set_date_guards) {
    TEST_CASE("set_date is internal now; the reachable guard is build(NULL)");

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(0, mail_message_build(NULL, rawtime), "NULL message");
}

/* -------------------------------------------------------------------------- */
/* Message-Id; reachable through build                                        */
/* -------------------------------------------------------------------------- */

TEST(test_mailmessage_set_message_id_structure) {
    TEST_CASE("Message-Id is <digits@host>");

    mail_test_env_setup("example.com", "selector", NULL);

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, "body");
    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(1, mail_message_build(m, rawtime), "build returns 1");
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

    mail_message_free(m);
}

TEST(test_mailmessage_set_message_id_guards) {
    TEST_CASE("set_message_id is internal now; the reachable guard is build(NULL)");

    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(0, mail_message_build(NULL, rawtime), "NULL message");
}

TEST(test_mailmessage_message_id_without_host) {
    TEST_CASE("an unset mail.host still yields a syntactically valid Message-Id");

    /* Relay mode makes this routine: the sender's own domain is often not
     * configured at all, and an empty EHLO argument or "<...@>" is a syntax
     * error rather than a missing nicety. */
    mail_test_env_setup("", "", "");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, "body");
    time_t rawtime = 1700000000;
    TEST_ASSERT_EQUAL(1, mail_message_build(m, rawtime), "build returns 1");
    TEST_ASSERT(strstr(m->message_id.value, "@") != NULL, "has an '@'");
    TEST_ASSERT(strstr(m->message_id.value, "@>") == NULL, "domain part is not empty");

    mail_message_free(m);
}

/* -------------------------------------------------------------------------- */
/* body encoding (the old __mail_set_content)                                 */
/* -------------------------------------------------------------------------- */

TEST(test_mailmessage_build_null_body) {
    TEST_CASE("build rejects a NULL body without dereferencing it (the setter just assigns)");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    mail_message_set_body(m, NULL);
    TEST_ASSERT_EQUAL(0, mail_message_build(m, time(0)), "NULL body returns 0 (no crash)");
    TEST_ASSERT_NULL(m->body_data, "nothing allocated on NULL body");
    TEST_ASSERT_EQUAL(0, (int)m->body_size, "body_size stays 0");

    mail_message_free(m);
}

TEST(test_mailmessage_build_encodes_body) {
    TEST_CASE("body is base64-encoded (wrapped at 76) into body_data");

    mail_test_env_setup("", "", "");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    const char* body = "Hello, mail body!";
    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, body);
    TEST_ASSERT_EQUAL(1, mail_message_build(m, time(0)), "build returns 1");
    TEST_ASSERT_NOT_NULL(m->body_data, "body_data allocated");
    TEST_ASSERT(m->body_size > 0, "body_size positive");

    /* base64 of a non-empty body is non-empty and contains only base64 chars /
     * newlines (the wrapped variant). Decoding round-trips to the body. */
    char* plain = malloc(base64_decode_len(m->body_data) > 0 ? (size_t)base64_decode_len(m->body_data) : 1);
    TEST_REQUIRE_NOT_NULL(plain, "decode buffer");
    int n = base64_decode(plain, m->body_data);
    plain[n > 0 ? n : 0] = '\0';
    TEST_ASSERT_STR_EQUAL(body, plain, "body round-trips through base64");
    free(plain);

    mail_message_free(m);
}

/* -------------------------------------------------------------------------- */
/* mail_message_build (end-to-end header + body + DKIM assembly)              */
/* -------------------------------------------------------------------------- */

TEST(test_mailmessage_build_with_dkim) {
    TEST_CASE("build produces a complete, terminated MIME message");

    EVP_PKEY* pkey = mail_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = mail_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    mail_test_env_setup("example.com", "selector", pem);

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, "Hello, body!");

    TEST_ASSERT_EQUAL(1, mail_message_build(m, time(0)), "build returns 1");

    TEST_ASSERT_NOT_NULL(m->data, "data buffer allocated");
    TEST_ASSERT(m->data_size > 0, "data_size positive");

    /* m->data is malloc'd to exactly data_size bytes (NOT NUL-terminated),
     * so search by explicit length — a plain strstr would read past the buffer. */
    const char* c = m->data;
    const size_t cs = m->data_size;

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

    mail_message_free(m);
    free(pem);
    EVP_PKEY_free(pkey);
}

TEST(test_mailmessage_build_no_leak) {
    TEST_CASE("a full build + free cycle is leak-free under ASan");

    EVP_PKEY* pkey = mail_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = mail_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    mail_test_env_setup("example.com", "selector", pem);

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    mail_message_set_from(m, "alice@example.com", "Alice");
    mail_message_set_to(m, "bob@example.com");
    mail_message_set_subject(m, "Hi");
    mail_message_set_body(m, "leak check body");
    mail_message_build(m, time(0));

    mail_message_free(m);
    free(pem);
    EVP_PKEY_free(pkey);
}

/* -------------------------------------------------------------------------- */
/* mail_message_build without DKIM (S.6)                                      */
/* -------------------------------------------------------------------------- */

TEST(test_mailmessage_build_without_dkim_key) {
    TEST_CASE("an empty DKIM key produces an unsigned message instead of no message");

    /* The regression this covers: dkim_create_sign() returns NULL when the key
     * is unset, the build used to treat that as fatal, and every send from a
     * configuration without DKIM failed with "Failed to send mail" — while
     * config.md documented the opposite. */
    mail_test_env_setup("example.com", "", "");

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    TEST_ASSERT_EQUAL(1, mail_message_set_from(m, "alice@example.com", "Alice"), "set_from");
    TEST_ASSERT_EQUAL(1, mail_message_set_to(m, "bob@example.com"), "set_to");
    TEST_ASSERT_EQUAL(1, mail_message_set_subject(m, "Hello"), "set_subject");
    mail_message_set_body(m, "Hello, body!");

    TEST_ASSERT_EQUAL(1, mail_message_build(m, time(0)), "build succeeds with no DKIM key");

    const char* c = m->data;
    const size_t cs = m->data_size;

    TEST_ASSERT_NOT_NULL(c, "data buffer allocated");
    TEST_ASSERT_EQUAL(0, mail_test_contains(c, cs, "DKIM-Signature:"), "no DKIM-Signature header");

    /* Everything else is still a complete message. */
    TEST_ASSERT(mail_test_contains(c, cs, "From:"), "has From header");
    TEST_ASSERT(mail_test_contains(c, cs, "To:"), "has To header");
    TEST_ASSERT(mail_test_contains(c, cs, "Subject:"), "has Subject header");
    TEST_ASSERT(mail_test_contains(c, cs, "Date:"), "has Date header");
    TEST_ASSERT(mail_test_contains(c, cs, "Message-Id:"), "has Message-Id header");
    TEST_ASSERT(mail_test_contains(c, cs, "MIME-Version:"), "has MIME-Version header");
    TEST_ASSERT(mail_test_contains(c, cs, "\r\n.\r\n"), "ends with DATA terminator");

    mail_message_free(m);
}

TEST(test_mailmessage_build_without_dkim_selector) {
    TEST_CASE("a key with no selector also yields an unsigned message");

    EVP_PKEY* pkey = mail_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = mail_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    mail_test_env_setup("example.com", "", pem);

    mail_message_t* m = mail_message_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_message_create should succeed");

    mail_message_set_from(m, "alice@example.com", "Alice");
    mail_message_set_to(m, "bob@example.com");
    mail_message_set_subject(m, "Hi");
    mail_message_set_body(m, "body");

    TEST_ASSERT_EQUAL(1, mail_message_build(m, time(0)), "build succeeds");
    TEST_ASSERT_EQUAL(0, mail_test_contains(m->data, m->data_size, "DKIM-Signature:"),
        "no DKIM-Signature without a selector");

    mail_message_free(m);
    free(pem);
    EVP_PKEY_free(pkey);
}
