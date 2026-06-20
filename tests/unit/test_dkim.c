#include "framework.h"
#include "dkim.h"
#include "base64.h"

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <string.h>
#include <stdlib.h>

/* The internal helpers are not declared in dkim.h; redeclare them here so the
 * canonicalization / wrapping / signing primitives can be unit-tested in
 * isolation as well as through the public dkim_create_sign() flow. */
char* __dkim_relaxed_body_canon(const char* body);
char* __dkim_wrap(char* str, size_t len);
char* __dkim_header_list_create(dkim_t* dkim, int* header_list_length);
char* __dkim_make_headers_string(dkim_t* dkim, int* headers_string_length);
char* __dkim_base64_encode_sha1(const char* body, int* canon_body_length);

/* -------------------------------------------------------------------------- */
/* Test helpers                                                               */
/* -------------------------------------------------------------------------- */

/* Generate a fresh RSA-2048 keypair. Returns an EVP_PKEY the caller frees. */
static EVP_PKEY* dkim_test_generate_keypair(void) {
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

/* Serialize the private key to a NUL-terminated PEM string (heap-allocated). */
static char* dkim_test_private_pem(EVP_PKEY* pkey) {
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

/* Extract a public-only key (simulating a verifier that never saw the private
 * key). Caller frees. */
static EVP_PKEY* dkim_test_public_key(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) return NULL;

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        BIO_free(bio);
        return NULL;
    }

    /* BIO_reset() on a memory BIO is version-dependent (it can clear the
     * buffer). Read back through a fresh read-only mem BIO over the written
     * bytes instead. */
    BUF_MEM* bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);

    BIO* rbio = BIO_new_mem_buf(bptr->data, (int)bptr->length);
    EVP_PKEY* pub = (rbio != NULL) ? PEM_read_bio_PUBKEY(rbio, NULL, NULL, NULL) : NULL;

    BIO_free(rbio);
    BIO_free(bio);
    return pub;
}

/* DKIM header folding inserts "\r\n\t" continuations. Removing every such
 * triple reconstructs the unfolded value (data + signature). Heap-allocated. */
static char* dkim_test_unfold(const char* folded) {
    size_t n = strlen(folded);
    char* out = malloc(n + 1);
    if (out == NULL) return NULL;

    size_t o = 0;
    for (size_t i = 0; i < n;) {
        if (i + 2 < n && folded[i] == '\r' && folded[i + 1] == '\n' && folded[i + 2] == '\t') {
            i += 3;
        } else {
            out[o++] = folded[i++];
        }
    }
    out[o] = '\0';
    return out;
}

/* Locate the value of a tag in an unfolded DKIM-Signature value. Tag must be
 * given as the full "name=" (e.g. "bh=", "b="). Returns a pointer into `value`
 * at the start of the tag's content, or NULL if not found. The content runs up
 * to the next ';' or end of string. Writes the content length to *out_len. */
static const char* dkim_test_tag_value(const char* value, const char* tag, int* out_len) {
    *out_len = 0;
    const char* p = strstr(value, tag);
    if (p == NULL) return NULL;

    const char* content = p + strlen(tag);
    const char* end = strchr(content, ';');
    size_t len = (end != NULL) ? (size_t)(end - content) : strlen(content);
    *out_len = (int)len;
    return content;
}

/* Build a dkim object preloaded with the standard mail headers (From/To/Subject)
 * and a selector/domain/timestamp. Caller frees with dkim_free. */
static dkim_t* dkim_test_build(const char* private_key) {
    dkim_t* dkim = dkim_create();
    if (dkim == NULL) return NULL;

    dkim_set_private_key(dkim, private_key);
    dkim_set_domain(dkim, "example.com");
    dkim_set_selector(dkim, "selector");
    dkim_set_timestamp(dkim, 1700000000);

    dkim_header_add(dkim, "From", 4, "Alice <alice@example.com>", 25);
    dkim_header_add(dkim, "To", 2, "bob@example.com", 16);
    dkim_header_add(dkim, "Subject", 7, "Hello DKIM", 10);

    return dkim;
}

/* -------------------------------------------------------------------------- */
/* create / free / header_add                                                  */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_create_initial_state) {
    TEST_CASE("dkim_create returns object with cleared fields");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    TEST_ASSERT_NULL(dkim->private_key, "private_key initially NULL");
    TEST_ASSERT_NULL(dkim->domain, "domain initially NULL");
    TEST_ASSERT_NULL(dkim->selector, "selector initially NULL");
    TEST_ASSERT_NULL(dkim->header, "header initially NULL");
    TEST_ASSERT_NULL(dkim->last_header, "last_header initially NULL");
    TEST_ASSERT_EQUAL(0, dkim->timestamp, "timestamp initially 0");

    dkim_free(dkim);
}

TEST(test_dkim_header_add_single) {
    TEST_CASE("Adding one header links head and tail");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    int ok = dkim_header_add(dkim, "From", 4, "a@b.c", 5);
    TEST_ASSERT_EQUAL(1, ok, "header_add should return 1");
    TEST_ASSERT_NOT_NULL(dkim->header, "head should be set");
    TEST_ASSERT(dkim->header == dkim->last_header, "head == tail for single header");
    TEST_ASSERT_NULL(dkim->header->next, "single header has no next");

    dkim_free(dkim);
}

TEST(test_dkim_header_add_chain_order) {
    TEST_CASE("Multiple headers form an ordered chain");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    dkim_header_add(dkim, "From", 4, "a@b.c", 5);
    dkim_header_add(dkim, "To", 2, "d@e.f", 5);
    dkim_header_add(dkim, "Subject", 7, "Hi", 2);

    mail_header_t* h = dkim->header;
    TEST_ASSERT_NOT_NULL(h, "first header");
    TEST_ASSERT_STR_EQUAL("From", h->key, "first key");
    h = h->next;
    TEST_ASSERT_NOT_NULL(h, "second header");
    TEST_ASSERT_STR_EQUAL("To", h->key, "second key");
    h = h->next;
    TEST_ASSERT_NOT_NULL(h, "third header");
    TEST_ASSERT_STR_EQUAL("Subject", h->key, "third key");
    TEST_ASSERT(dkim->last_header == h, "last_header points to third");
    TEST_ASSERT_NULL(h->next, "third header has no next");

    dkim_free(dkim);
}

TEST(test_dkim_header_add_rejects_bad_input) {
    TEST_CASE("header_add rejects NULL / empty key and value");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    TEST_ASSERT_EQUAL(0, dkim_header_add(NULL, "From", 4, "x", 1), "NULL dkim");
    TEST_ASSERT_EQUAL(0, dkim_header_add(dkim, NULL, 0, "x", 1), "NULL key");
    TEST_ASSERT_EQUAL(0, dkim_header_add(dkim, "From", 4, NULL, 0), "NULL value");
    TEST_ASSERT_EQUAL(0, dkim_header_add(dkim, "", 0, "x", 1), "empty key");
    TEST_ASSERT_EQUAL(0, dkim_header_add(dkim, "From", 4, "", 0), "empty value");
    TEST_ASSERT_NULL(dkim->header, "no header added on rejection");

    dkim_free(dkim);
}

/* -------------------------------------------------------------------------- */
/* relaxed body canonicalization                                              */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_relaxed_body_canon_strips_and_normalizes) {
    TEST_CASE("relaxed body canon collapses WSP and trims empty trailing lines");

    /* "Hello  world \n\n"  ->  "Hello world\r\n"
     * - double space collapses to one
     * - trailing whitespace before newline removed
     * - trailing empty lines removed, single CRLF terminator added */
    char* canon = __dkim_relaxed_body_canon("Hello  world \n\n");
    TEST_REQUIRE_NOT_NULL(canon, "canon should succeed");

    TEST_ASSERT_STR_EQUAL("Hello world\r\n", canon, "relaxed canonical form");
    free(canon);
}

TEST(test_dkim_relaxed_body_canon_simple) {
    TEST_CASE("relaxed body canon of a plain body appends a single CRLF");

    char* canon = __dkim_relaxed_body_canon("Hello");
    TEST_REQUIRE_NOT_NULL(canon, "canon should succeed");

    TEST_ASSERT_STR_EQUAL("Hello\r\n", canon, "plain body gets a CRLF terminator");
    free(canon);
}

/* -------------------------------------------------------------------------- */
/* header list (h= tag)                                                       */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_header_list_create) {
    TEST_CASE("header list is colon-joined lowercased keys");

    dkim_t* dkim = dkim_test_build("unused");
    TEST_REQUIRE_NOT_NULL(dkim, "build should succeed");

    int length = -1;
    char* list = __dkim_header_list_create(dkim, &length);
    TEST_REQUIRE_NOT_NULL(list, "header_list_create should succeed");
    /* Direct call does not canonicalize; keys keep their original case. The
     * lowercase form ("from:to:subject") only appears once relaxed header
     * canonicalization runs inside dkim_create_sign(). */
    TEST_ASSERT_EQUAL((int)strlen("From:To:Subject"), length, "length excludes NUL and equals joined keys");
    TEST_ASSERT_STR_EQUAL("From:To:Subject", list, "h= list content");

    free(list);
    dkim_free(dkim);
}

TEST(test_dkim_header_list_create_empty) {
    TEST_CASE("header list with zero headers yields empty string, not a crash");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    int length = 999;
    char* list = __dkim_header_list_create(dkim, &length);
    TEST_REQUIRE_NOT_NULL(list, "empty header list should still allocate");
    TEST_ASSERT_EQUAL(0, length, "length is 0 with no headers");
    TEST_ASSERT_STR_EQUAL("", list, "empty header list is the empty string");

    free(list);
    dkim_free(dkim);
}

/* -------------------------------------------------------------------------- */
/* make_headers_string                                                        */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_make_headers_string_content) {
    TEST_CASE("headers string is key:value pairs joined with CRLF");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    dkim_header_add(dkim, "From", 4, "a@b.c", 5);
    dkim_header_add(dkim, "To", 2, "d@e.f", 5);

    int length = 0;
    char* str = __dkim_make_headers_string(dkim, &length);
    TEST_REQUIRE_NOT_NULL(str, "make_headers_string should succeed");

    /* relaxed header canon is not applied on a direct call, so keys keep case */
    TEST_ASSERT_STR_EQUAL("From:a@b.c\r\nTo:d@e.f", str, "joined headers");
    TEST_ASSERT_EQUAL((int)strlen("From:a@b.c\r\nTo:d@e.f"), length, "length matches content");

    free(str);
    dkim_free(dkim);
}

TEST(test_dkim_make_headers_string_long_values) {
    TEST_CASE("many long headers do not overflow the pre-sized buffer");

    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");

    char big[400];
    memset(big, 'X', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    for (int i = 0; i < 8; i++)
        dkim_header_add(dkim, "X-Long", 6, big, sizeof(big) - 1);

    int length = 0;
    char* str = __dkim_make_headers_string(dkim, &length);
    TEST_REQUIRE_NOT_NULL(str, "make_headers_string should succeed");

    /* Buffer must be exactly sized and NUL-terminated (ASan guards overflow). */
    TEST_ASSERT_EQUAL('\0', str[length], "NUL terminator at reported length");

    free(str);
    dkim_free(dkim);
}

/* -------------------------------------------------------------------------- */
/* line folding (__dkim_wrap)                                                 */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_wrap_roundtrips) {
    TEST_CASE("folding preserves content when fold markers are removed");

    const char* input = "v=1; a=rsa-sha1; s=selector; d=example.com; b=AAABBBCCCDDDEEEFFFGGG";
    size_t in_len = strlen(input);

    char* wrapped = __dkim_wrap((char*)input, in_len);
    TEST_REQUIRE_NOT_NULL(wrapped, "wrap should succeed");
    TEST_ASSERT_EQUAL('\0', wrapped[strlen(wrapped)], "wrapped output is NUL-terminated");

    char* unfolded = dkim_test_unfold(wrapped);
    TEST_REQUIRE_NOT_NULL(unfolded, "unfold should succeed");
    TEST_ASSERT_STR_EQUAL(input, unfolded, "unfolding reconstructs the original");

    free(wrapped);
    free(unfolded);
}

TEST(test_dkim_wrap_no_overflow) {
    TEST_CASE("wrapping a long base64-like string stays within its allocation");

    char input[600];
    memset(input, 'M', sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    char* wrapped = __dkim_wrap(input, sizeof(input) - 1);
    TEST_REQUIRE_NOT_NULL(wrapped, "wrap should succeed");
    TEST_ASSERT_EQUAL('\0', wrapped[strlen(wrapped)], "NUL-terminated");

    char* unfolded = dkim_test_unfold(wrapped);
    TEST_REQUIRE_NOT_NULL(unfolded, "unfold should succeed");
    TEST_ASSERT_STR_EQUAL(input, unfolded, "long input round-trips through folding");

    free(wrapped);
    free(unfolded);
}

/* -------------------------------------------------------------------------- */
/* dkim_create_sign: NULL guards                                              */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_create_sign_null_guard) {
    TEST_CASE("dkim_create_sign returns NULL for missing inputs");

    EVP_PKEY* pkey = dkim_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = dkim_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    TEST_ASSERT_NULL(dkim_create_sign(NULL, "body"), "NULL dkim");
    TEST_ASSERT_NULL(dkim_create_sign((dkim_t*)1, NULL), "NULL body");

    /* private_key / selector / domain missing -> NULL, no deref */
    dkim_t* dkim = dkim_create();
    TEST_REQUIRE_NOT_NULL(dkim, "dkim_create should succeed");
    dkim_set_domain(dkim, "example.com");
    dkim_set_selector(dkim, "selector");
    dkim_header_add(dkim, "From", 4, "a@b.c", 5);
    TEST_ASSERT_NULL(dkim_create_sign(dkim, "body"), "missing private_key returns NULL");
    dkim_free(dkim);

    free(pem);
    EVP_PKEY_free(pkey);
}

/* -------------------------------------------------------------------------- */
/* dkim_create_sign: structure & body hash                                    */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_create_sign_structure) {
    TEST_CASE("produced signature contains all required DKIM tags");

    EVP_PKEY* pkey = dkim_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = dkim_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    dkim_t* dkim = dkim_test_build(pem);
    TEST_REQUIRE_NOT_NULL(dkim, "build should succeed");

    const char* body = "Hello, DKIM!\r\nThis is a signed test body.\r\n";
    char* sign = dkim_create_sign(dkim, body);
    TEST_REQUIRE_NOT_NULL(sign, "create_sign should succeed");

    char* unfolded = dkim_test_unfold(sign);
    TEST_REQUIRE_NOT_NULL(unfolded, "unfold should succeed");

    TEST_ASSERT(strstr(unfolded, "v=1;") != NULL, "contains v=1");
    TEST_ASSERT(strstr(unfolded, "a=rsa-sha1;") != NULL, "contains a=rsa-sha1");
    TEST_ASSERT(strstr(unfolded, "c=relaxed/relaxed;") != NULL, "contains c=relaxed/relaxed");
    TEST_ASSERT(strstr(unfolded, "s=selector;") != NULL, "contains selector");
    TEST_ASSERT(strstr(unfolded, "d=example.com;") != NULL, "contains domain");
    TEST_ASSERT(strstr(unfolded, "h=from:to:subject;") != NULL, "h= lists signed headers");

    /* bh= must be present and non-empty */
    int bh_len = 0;
    const char* bh = dkim_test_tag_value(unfolded, "bh=", &bh_len);
    TEST_ASSERT(bh != NULL, "bh= tag present");
    TEST_ASSERT(bh_len > 0, "bh= value non-empty");

    /* b= must be present and non-empty (the RSA signature) */
    int b_len = 0;
    const char* b = dkim_test_tag_value(unfolded, "b=", &b_len);
    TEST_ASSERT(b != NULL, "b= tag present");
    TEST_ASSERT(b_len > 0, "b= value non-empty");

    free(unfolded);
    free(sign);
    dkim_free(dkim);
    free(pem);
    EVP_PKEY_free(pkey);
}

TEST(test_dkim_create_sign_body_hash) {
    TEST_CASE("bh= equals base64(SHA1(relaxed-canon body))");

    EVP_PKEY* pkey = dkim_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = dkim_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    dkim_t* dkim = dkim_test_build(pem);
    TEST_REQUIRE_NOT_NULL(dkim, "build should succeed");

    const char* body = "Hello  world \n\n"; /* canonicalizes to "Hello world\r\n" */
    char* sign = dkim_create_sign(dkim, body);
    TEST_REQUIRE_NOT_NULL(sign, "create_sign should succeed");

    /* Independently compute the expected body hash via the same primitive. */
    int canon_len = 0;
    char* expected_bh = __dkim_base64_encode_sha1(body, &canon_len);
    TEST_REQUIRE_NOT_NULL(expected_bh, "expected bh computation should succeed");
    TEST_ASSERT_EQUAL(13, canon_len, "canonical body length is 13 ('Hello world\\r\\n')");

    char* unfolded = dkim_test_unfold(sign);
    TEST_REQUIRE_NOT_NULL(unfolded, "unfold should succeed");

    int bh_len = 0;
    const char* actual_bh = dkim_test_tag_value(unfolded, "bh=", &bh_len);
    TEST_ASSERT(actual_bh != NULL && bh_len > 0, "bh= present and non-empty");

    char actual_bh_buf[128];
    snprintf(actual_bh_buf, sizeof(actual_bh_buf), "%.*s", bh_len, actual_bh);
    TEST_ASSERT_STR_EQUAL(expected_bh, actual_bh_buf, "bh= matches independent SHA1 of relaxed body");

    free(unfolded);
    free(sign);
    free(expected_bh);
    dkim_free(dkim);
    free(pem);
    EVP_PKEY_free(pkey);
}

/* -------------------------------------------------------------------------- */
/* THE KEY TEST: signature verifies with the public key (single hash)         */
/* -------------------------------------------------------------------------- */

TEST(test_dkim_signature_verifies_with_public_key) {
    TEST_CASE("RSA signature verifies against SHA1(canonical headers) using the public key");

    EVP_PKEY* pkey = dkim_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = dkim_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    /* Public-only key, as a real verifier would have it. */
    EVP_PKEY* pub = dkim_test_public_key(pkey);
    TEST_REQUIRE_NOT_NULL(pub, "public key extraction should succeed");

    dkim_t* dkim = dkim_test_build(pem);
    TEST_REQUIRE_NOT_NULL(dkim, "build should succeed");

    const char* body = "Hello, DKIM!\r\nThis is a signed test body.\r\n";
    char* sign = dkim_create_sign(dkim, body);
    TEST_REQUIRE_NOT_NULL(sign, "create_sign should succeed");

    /* Reconstruct the exact bytes that were signed. dkim_create_sign leaves
     * the (already canonicalized) headers on the object, so make_headers_string
     * reproduces the signing input verbatim, including the DKIM-Signature
     * header with an empty b= tag. */
    int headers_len = 0;
    char* headers_string = __dkim_make_headers_string(dkim, &headers_len);
    TEST_REQUIRE_NOT_NULL(headers_string, "reconstruct headers string");

    /* Extract the base64 b= value and decode it to raw signature bytes. */
    char* unfolded = dkim_test_unfold(sign);
    TEST_REQUIRE_NOT_NULL(unfolded, "unfold should succeed");

    int b_len = 0;
    const char* b_value = dkim_test_tag_value(unfolded, "b=", &b_len);
    TEST_ASSERT(b_value != NULL && b_len > 0, "b= value present");

    char b_buf[1024];
    snprintf(b_buf, sizeof(b_buf), "%.*s", b_len, b_value);

    int raw_cap = base64_decode_len(b_buf);
    TEST_ASSERT(raw_cap > 0, "decoded signature length positive");
    unsigned char* raw = malloc(raw_cap);
    TEST_REQUIRE_NOT_NULL(raw, "allocate raw signature");
    int raw_len = base64_decode((char*)raw, b_buf);
    TEST_ASSERT(raw_len > 0, "base64 decode of signature succeeded");

    /* Verify: RSA-SHA1 over the canonical headers, hashing once. The previous
     * implementation fed a precomputed digest into the signing context, which
     * hashed it a second time; such a signature would FAIL this check. */
    EVP_MD_CTX* vctx = EVP_MD_CTX_new();
    TEST_REQUIRE_NOT_NULL(vctx, "verify context");

    int ok = 0;
    if (EVP_DigestVerifyInit(vctx, NULL, EVP_sha1(), NULL, pub) == 1 &&
        EVP_DigestVerifyUpdate(vctx, headers_string, (size_t)headers_len) == 1) {
        ok = (EVP_DigestVerifyFinal(vctx, raw, (size_t)raw_len) == 1);
    }

    TEST_ASSERT(ok, "signature verifies with public key over SHA1(canonical headers)");

    EVP_MD_CTX_free(vctx);
    free(raw);
    free(unfolded);
    free(headers_string);
    free(sign);
    dkim_free(dkim);
    free(pem);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(pkey);
}

TEST(test_dkim_sign_then_free_no_leak) {
    TEST_CASE("full sign + free cycle is leak-free under ASan");

    EVP_PKEY* pkey = dkim_test_generate_keypair();
    TEST_REQUIRE_NOT_NULL(pkey, "keypair generation should succeed");
    char* pem = dkim_test_private_pem(pkey);
    TEST_REQUIRE_NOT_NULL(pem, "private PEM extraction should succeed");

    dkim_t* dkim = dkim_test_build(pem);
    TEST_REQUIRE_NOT_NULL(dkim, "build should succeed");

    char* sign = dkim_create_sign(dkim, "leak check body\r\n");
    TEST_REQUIRE_NOT_NULL(sign, "create_sign should succeed");
    TEST_ASSERT(strlen(sign) > 0, "signature is non-empty");

    free(sign);
    dkim_free(dkim);
    free(pem);
    EVP_PKEY_free(pkey);
}
