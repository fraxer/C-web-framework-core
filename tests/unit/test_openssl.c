#include "framework.h"
#include "openssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================================
// Test fixtures: a self-signed EC certificate (CN=test.local, expires 2126),
// its matching private key and a second, non-matching key. Embedded so the
// suite needs no network and no openssl CLI; written to a mkdtemp directory
// on first use and removed via atexit.
// ============================================================================

static const char TEST_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBgTCCASegAwIBAgIUB3HxnU9U40dof4dsUolGg9gK0agwCgYIKoZIzj0EAwIw\n"
    "FTETMBEGA1UEAwwKdGVzdC5sb2NhbDAgFw0yNjA3MDcxMzU5MThaGA8yMTI2MDYx\n"
    "MzEzNTkxOFowFTETMBEGA1UEAwwKdGVzdC5sb2NhbDBZMBMGByqGSM49AgEGCCqG\n"
    "SM49AwEHA0IABDmKxsXK3rfN7npjJALi8NpiNETLAtCZOTLh0Q7qHya60kFtogoz\n"
    "ykDiFYwdBRV1dHVmgq1pxzPpcK4wVCxOBuujUzBRMB0GA1UdDgQWBBStH1ElfpS6\n"
    "XLV0xkLuNFX5wo7fFDAfBgNVHSMEGDAWgBStH1ElfpS6XLV0xkLuNFX5wo7fFDAP\n"
    "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIH8zv9wdiZ2oJJaY1hSn\n"
    "6JFmY0RCFRGvClTiVl+8ReSPAiEAipwy4kteiS53D8y7pjJyyTUq8BHJOOKDLYaL\n"
    "aJ1y2BM=\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq8pt3jG3r5/amzX0\n"
    "uu4KPsH8C9MywbIbTyJls2z8sc+hRANCAAQ5isbFyt63ze56YyQC4vDaYjREywLQ\n"
    "mTky4dEO6h8mutJBbaIKM8pA4hWMHQUVdXR1ZoKtaccz6XCuMFQsTgbr\n"
    "-----END PRIVATE KEY-----\n";

static const char TEST_OTHER_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPoyW/j1V8iBzDqmQ\n"
    "PMGpNp3pTg1XUOFM2HDs2AJcceehRANCAAQ0cx1vIDz/RhsttVK1fvojPgY9+brK\n"
    "GlBMrdB3wNA5w39dFqpfDy21OQjoHl1p4PehpiZ5T5i30hTYGjVapGmA\n"
    "-----END PRIVATE KEY-----\n";

#define TEST_CIPHERS_VALID "DEFAULT"
#define TEST_CIPHERS_INVALID "NOT-A-REAL-CIPHER"

static char certs_dir[64];
static char cert_path[128];
static char key_path[128];
static char other_key_path[128];
static int certs_ready = 0;

static void cleanup_certs(void) {
    if (!certs_ready) return;

    unlink(cert_path);
    unlink(key_path);
    unlink(other_key_path);
    rmdir(certs_dir);
    certs_ready = 0;
}

static int write_pem(char* path, size_t path_size, const char* name, const char* content) {
    if (snprintf(path, path_size, "%s/%s", certs_dir, name) >= (int)path_size)
        return 0;

    FILE* file = fopen(path, "w");
    if (file == NULL) return 0;

    const size_t length = strlen(content);
    const size_t written = fwrite(content, 1, length, file);
    fclose(file);

    return written == length;
}

static int ensure_certs(void) {
    if (certs_ready) return 1;

    snprintf(certs_dir, sizeof(certs_dir), "/tmp/openssl_test_XXXXXX");
    if (mkdtemp(certs_dir) == NULL) return 0;

    if (!write_pem(cert_path, sizeof(cert_path), "cert.pem", TEST_CERT_PEM)) return 0;
    if (!write_pem(key_path, sizeof(key_path), "key.pem", TEST_KEY_PEM)) return 0;
    if (!write_pem(other_key_path, sizeof(other_key_path), "otherkey.pem", TEST_OTHER_KEY_PEM)) return 0;

    certs_ready = 1;
    atexit(cleanup_certs);

    return 1;
}

static char* dup_str(const char* source) {
    if (source == NULL) return NULL;

    char* copy = malloc(strlen(source) + 1);
    if (copy != NULL)
        strcpy(copy, source);

    return copy;
}

/* Builds an openssl_t with heap-owned config strings, as
 * __module_loader_tls_load does; NULL arguments leave the field unset. */
static openssl_t* make_openssl(const char* fullchain, const char* private_key, const char* ciphers) {
    openssl_t* openssl = openssl_create();
    if (openssl == NULL) return NULL;

    openssl->fullchain = dup_str(fullchain);
    openssl->private = dup_str(private_key);
    openssl->ciphers = dup_str(ciphers);

    if ((fullchain != NULL && openssl->fullchain == NULL)
        || (private_key != NULL && openssl->private == NULL)
        || (ciphers != NULL && openssl->ciphers == NULL)) {
        openssl_free(openssl);
        return NULL;
    }

    return openssl;
}

// ============================================================================
// openssl_create / openssl_free
// ============================================================================

TEST(test_openssl_create_defaults) {
    TEST_SUITE("openssl: lifecycle");
    TEST_CASE("openssl_create returns zero-initialized object");

    openssl_t* openssl = openssl_create();

    TEST_REQUIRE_NOT_NULL(openssl, "openssl_create should not return NULL");
    TEST_ASSERT_NULL(openssl->fullchain, "fullchain should be NULL after create");
    TEST_ASSERT_NULL(openssl->private, "private should be NULL after create");
    TEST_ASSERT_NULL(openssl->ciphers, "ciphers should be NULL after create");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should be NULL after create");

    openssl_free(openssl);
}

TEST(test_openssl_free_null) {
    TEST_SUITE("openssl: lifecycle");
    TEST_CASE("openssl_free handles NULL");

    openssl_free(NULL);

    TEST_ASSERT(1, "openssl_free(NULL) should not crash");
}

TEST(test_openssl_free_partial) {
    TEST_SUITE("openssl: lifecycle");
    TEST_CASE("openssl_free releases partially filled object");

    openssl_t* openssl = openssl_create();

    TEST_REQUIRE_NOT_NULL(openssl, "openssl_create should not return NULL");

    openssl->fullchain = dup_str("/nonexistent/fullchain.pem");
    openssl_free(openssl);

    TEST_ASSERT(1, "openssl_free with only fullchain set should not crash or leak");
}

// ============================================================================
// openssl_init
// ============================================================================

TEST(test_openssl_init_null) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init rejects NULL");

    TEST_ASSERT_EQUAL(0, openssl_init(NULL), "openssl_init(NULL) should return 0");
}

TEST(test_openssl_init_missing_config) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init rejects object with unset config fields");

    openssl_t* openssl = openssl_create();

    TEST_REQUIRE_NOT_NULL(openssl, "openssl_create should not return NULL");
    TEST_ASSERT_EQUAL(0, openssl_init(openssl), "init without fullchain/private/ciphers should fail");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should stay NULL after failed init");

    openssl_free(openssl);
}

TEST(test_openssl_init_valid) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init succeeds with valid certificate, key and ciphers");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(1, openssl_init(openssl), "init with valid config should return 1");
    TEST_ASSERT_NOT_NULL(openssl->ctx, "ctx should be created after successful init");

    openssl_free(openssl);
}

TEST(test_openssl_init_twice) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init can be called twice without leaking the first ctx");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(1, openssl_init(openssl), "first init should return 1");
    TEST_ASSERT_EQUAL(1, openssl_init(openssl), "second init should return 1");
    TEST_ASSERT_NOT_NULL(openssl->ctx, "ctx should be set after re-init");

    openssl_free(openssl);
}

TEST(test_openssl_init_nonexistent_chain) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init fails on nonexistent chain file");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl("/tmp/openssl_test_no_such_chain.pem", key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(0, openssl_init(openssl), "init with missing chain file should fail");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should be cleaned up after failed init");

    openssl_free(openssl);
}

TEST(test_openssl_init_nonexistent_private) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init fails on nonexistent private key file");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, "/tmp/openssl_test_no_such_key.pem", TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(0, openssl_init(openssl), "init with missing private key should fail");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should be cleaned up after failed init");

    openssl_free(openssl);
}

TEST(test_openssl_init_mismatched_key) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init fails when private key does not match certificate");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, other_key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(0, openssl_init(openssl), "init with mismatched key should fail");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should be cleaned up after failed init");

    openssl_free(openssl);
}

TEST(test_openssl_init_invalid_ciphers) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init fails on invalid cipher list");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, key_path, TEST_CIPHERS_INVALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(0, openssl_init(openssl), "init with invalid cipher list should fail");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should be cleaned up after failed init");

    openssl_free(openssl);
}

TEST(test_openssl_init_swapped_cert_and_key) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init fails when chain and key files are swapped");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(key_path, cert_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_ASSERT_EQUAL(0, openssl_init(openssl), "init with swapped files should fail");
    TEST_ASSERT_NULL(openssl->ctx, "ctx should be cleaned up after failed init");

    openssl_free(openssl);
}

// ============================================================================
// openssl_set_sni_callback
// ============================================================================

static int sni_callback_calls = 0;
static char sni_callback_name[64];

static int test_sni_callback(SSL* ssl, int* alert, void* arg) {
    (void)alert;
    (void)arg;

    sni_callback_calls++;

    const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name != NULL) {
        strncpy(sni_callback_name, name, sizeof(sni_callback_name) - 1);
        sni_callback_name[sizeof(sni_callback_name) - 1] = '\0';
    }

    return SSL_TLSEXT_ERR_OK;
}

TEST(test_openssl_set_sni_callback_null_safe) {
    TEST_SUITE("openssl: sni");
    TEST_CASE("openssl_set_sni_callback handles NULL object and NULL ctx");

    openssl_set_sni_callback(NULL, test_sni_callback);

    openssl_t* openssl = openssl_create();

    TEST_REQUIRE_NOT_NULL(openssl, "openssl_create should not return NULL");

    openssl_set_sni_callback(openssl, test_sni_callback);
    openssl_free(openssl);

    TEST_ASSERT(1, "set_sni_callback on NULL object/ctx should not crash");
}

// ============================================================================
// Handshake, openssl_read / openssl_write over an in-memory BIO pair
// ============================================================================

/* Drives both handshake sides until each reports success; the BIO pair moves
 * TLS records between them, so WANT_READ/WANT_WRITE just means "let the peer
 * run". Any other error is fatal. Returns 1 when both sides finished. */
static int do_handshake(SSL* client, SSL* server) {
    int client_done = 0;
    int server_done = 0;

    for (int i = 0; i < 100 && !(client_done && server_done); i++) {
        if (!client_done) {
            const int result = SSL_do_handshake(client);
            if (result == 1)
                client_done = 1;
            else {
                const int error = SSL_get_error(client, result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return 0;
            }
        }

        if (!server_done) {
            const int result = SSL_do_handshake(server);
            if (result == 1)
                server_done = 1;
            else {
                const int error = SSL_get_error(server, result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return 0;
            }
        }
    }

    return client_done && server_done;
}

typedef struct {
    SSL_CTX* client_ctx;
    SSL* client;
    SSL* server;
} tls_pair_t;

/* Builds a client SSL_CTX plus client/server SSL objects joined by an
 * in-memory BIO pair, ready for do_handshake. Returns 1 on success; on
 * failure everything already allocated is released. */
static int tls_pair_setup(tls_pair_t* pair, SSL_CTX* server_ctx) {
    pair->client_ctx = NULL;
    pair->client = NULL;
    pair->server = NULL;

    pair->client_ctx = SSL_CTX_new(TLS_client_method());
    if (pair->client_ctx == NULL) return 0;

    pair->client = SSL_new(pair->client_ctx);
    pair->server = SSL_new(server_ctx);

    BIO* client_bio = NULL;
    BIO* server_bio = NULL;
    if (pair->client == NULL || pair->server == NULL
        || BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1)
        goto failed;

    /* SSL_set_bio transfers BIO ownership: SSL_free releases them. */
    SSL_set_bio(pair->client, client_bio, client_bio);
    SSL_set_bio(pair->server, server_bio, server_bio);
    SSL_set_connect_state(pair->client);
    SSL_set_accept_state(pair->server);
    SSL_set_tlsext_host_name(pair->client, "test.local");

    return 1;

    failed:

    if (pair->client != NULL) SSL_free(pair->client);
    if (pair->server != NULL) SSL_free(pair->server);
    SSL_CTX_free(pair->client_ctx);
    pair->client_ctx = NULL;
    pair->client = NULL;
    pair->server = NULL;

    return 0;
}

static void tls_pair_free(tls_pair_t* pair) {
    if (pair->client != NULL) SSL_free(pair->client);
    if (pair->server != NULL) SSL_free(pair->server);
    if (pair->client_ctx != NULL) SSL_CTX_free(pair->client_ctx);
}

TEST(test_openssl_handshake_read_write) {
    TEST_SUITE("openssl: io");
    TEST_CASE("TLS handshake with SNI, then openssl_write/openssl_read roundtrip");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_REQUIRE(openssl_init(openssl) == 1, "server context should initialize");

    sni_callback_calls = 0;
    sni_callback_name[0] = '\0';
    openssl_set_sni_callback(openssl, test_sni_callback);

    tls_pair_t pair;
    TEST_REQUIRE_GOTO(tls_pair_setup(&pair, openssl->ctx), "tls pair should be created", done);

    SSL* client = pair.client;
    SSL* server = pair.server;

    TEST_REQUIRE_GOTO(do_handshake(client, server), "handshake should complete", done);

    TEST_ASSERT_EQUAL(1, sni_callback_calls, "sni callback should be invoked exactly once");
    TEST_ASSERT_STR_EQUAL("test.local", sni_callback_name, "sni callback should receive server name");

    const char request[] = "hello over tls";
    const int request_length = (int)(sizeof(request) - 1);
    char buffer[64] = {0};

    TEST_ASSERT_EQUAL(request_length, openssl_write(client, request, sizeof(request) - 1),
                      "openssl_write should send the whole client message");
    TEST_ASSERT_EQUAL(request_length, openssl_read(server, buffer, sizeof(buffer)),
                      "openssl_read should receive the whole client message");
    TEST_ASSERT_STR_EQUAL(request, buffer, "server should read what client wrote");

    const char response[] = "hi";
    memset(buffer, 0, sizeof(buffer));

    TEST_ASSERT_EQUAL(2, openssl_write(server, response, sizeof(response) - 1),
                      "openssl_write should send the server response");
    TEST_ASSERT_EQUAL(2, openssl_read(client, buffer, sizeof(buffer)),
                      "openssl_read should receive the server response");
    TEST_ASSERT_STR_EQUAL(response, buffer, "client should read what server wrote");

    TEST_ASSERT_EQUAL(0, openssl_write(client, request, 0), "zero-length write should return 0");
    TEST_ASSERT_EQUAL(0, openssl_read(client, buffer, 0), "zero-length read should return 0");

    done:

    tls_pair_free(&pair);
    openssl_free(openssl);
}

TEST(test_openssl_init_sets_min_tls_1_2) {
    TEST_SUITE("openssl: init");
    TEST_CASE("openssl_init sets TLS 1.2 as minimum protocol version");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_REQUIRE(openssl_init(openssl) == 1, "server context should initialize");
    TEST_ASSERT_EQUAL(TLS1_2_VERSION, SSL_CTX_get_min_proto_version(openssl->ctx),
                      "minimum protocol version should be TLS 1.2");

    openssl_free(openssl);
}

TEST(test_openssl_handshake_rejects_tls_1_1) {
    TEST_SUITE("openssl: io");
    TEST_CASE("server refuses a client capped at TLS 1.1");

    TEST_REQUIRE(ensure_certs(), "test certificates should be written");

    openssl_t* openssl = make_openssl(cert_path, key_path, TEST_CIPHERS_VALID);

    TEST_REQUIRE_NOT_NULL(openssl, "make_openssl should not return NULL");
    TEST_REQUIRE(openssl_init(openssl) == 1, "server context should initialize");

    tls_pair_t pair;
    TEST_REQUIRE_GOTO(tls_pair_setup(&pair, openssl->ctx), "tls pair should be created", done);

    /* Security level 0 lets the client genuinely offer TLS 1.1, so a failed
     * handshake proves the server-side minimum version, not client policy. */
    SSL_set_security_level(pair.client, 0);
    TEST_REQUIRE_GOTO(SSL_set_max_proto_version(pair.client, TLS1_1_VERSION) == 1,
                      "client should cap its protocol at TLS 1.1", done);

    TEST_ASSERT_EQUAL(0, do_handshake(pair.client, pair.server),
                      "handshake with TLS 1.1 client should fail");

    done:

    tls_pair_free(&pair);
    openssl_free(openssl);
}
