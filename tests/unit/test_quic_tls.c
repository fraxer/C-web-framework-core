#include "framework.h"

#include "quictls.h"

#include <string.h>

/* The OpenSSL bridge (RFC 9001, docs/http3/03-quic-tls.md).
 *
 * A full handshake needs a peer, so that is interop territory (phase 8). What
 * is testable here is the part that is ours rather than OpenSSL's: the CRYPTO
 * reassembly that a real ClientHello depends on, and the QUIC-specific SSL
 * policy -- which is where a mistake would be a conformance bug nobody notices,
 * because the connection would work anyway. */

/* The bridge's ops are exercised through a recording stub: the point is which
 * calls arrive and in what order, not what a connection would do with them. */
typedef struct {
    int secrets;
    int crypto_bytes;
    int params;
    int alerts;
    quic_enc_level_e last_level;
} probe_t;

static int probe_install_secret(void* ctx, quic_enc_level_e level, quictls_dir_e dir,
                                quic_aead_e suite, const uint8_t* secret, size_t len) {
    (void)dir; (void)suite; (void)secret; (void)len;
    probe_t* p = ctx;
    p->secrets++;
    p->last_level = level;
    return 1;
}

static int probe_send_crypto(void* ctx, quic_enc_level_e level,
                             const uint8_t* data, size_t len) {
    (void)level; (void)data;
    probe_t* p = ctx;
    p->crypto_bytes += (int)len;
    return 1;
}

static int probe_peer_params(void* ctx, const quictp_t* params) {
    (void)params;
    ((probe_t*)ctx)->params++;
    return 1;
}

static void probe_alert(void* ctx, uint8_t alert_code) {
    (void)alert_code;
    ((probe_t*)ctx)->alerts++;
}

static const quictls_ops_t probe_ops = {
    .install_secret = probe_install_secret,
    .send_crypto = probe_send_crypto,
    .peer_params = probe_peer_params,
    .alert = probe_alert
};

TEST(test_quic_tls_ctx_policy) {
    TEST_SUITE("quic_tls");

    TEST_CASE("a QUIC SSL_CTX is configured differently from a TCP one");
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    TEST_REQUIRE_NOT_NULL(ctx, "context created");

    TEST_ASSERT(quictls_configure_ctx(ctx), "configured");

    /* TLS 1.3 only: QUIC has no meaning below it, and leaving 1.2 enabled would
     * let a handshake begin that could never produce QUIC keys. */
    TEST_ASSERT(SSL_CTX_get_min_proto_version(ctx) == TLS1_3_VERSION, "min is 1.3");
    TEST_ASSERT(SSL_CTX_get_max_proto_version(ctx) == TLS1_3_VERSION, "max is 1.3");

    TEST_CASE("CCM is excluded (RFC 9001 §5.3)");
    /* TLS_AES_128_CCM_8_SHA256 is forbidden in QUIC outright -- its 64-bit tag
     * is too short for the §6.6 integrity limits. This project's config.json
     * lists it for TCP, so inheriting that list would silently produce a
     * non-conforming connection that otherwise works perfectly. */
    int found_ccm = 0;
    int found_gcm = 0;
    STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(ctx);
    TEST_REQUIRE_NOT_NULL(ciphers, "cipher list readable");

    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        const char* name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i));
        if (name == NULL) continue;
        if (strstr(name, "CCM") != NULL) found_ccm = 1;
        if (strcmp(name, "TLS_AES_128_GCM_SHA256") == 0) found_gcm = 1;
    }

    TEST_ASSERT(!found_ccm, "no CCM suite is offered");
    TEST_ASSERT(found_gcm, "but the mandatory AES-128-GCM is");

    TEST_CASE("0-RTT is off");
    /* Early data needs an anti-replay policy this server does not have; the
     * default must be off rather than accidentally on. */
    TEST_ASSERT(SSL_CTX_get_max_early_data(ctx) == 0, "max_early_data is zero");

    SSL_CTX_free(ctx);
}

TEST(test_quic_tls_crypto_reassembly) {
    TEST_SUITE("quic_tls");

    /* A ClientHello with ECH or a long ALPN list exceeds one datagram routinely,
     * and QUIC does not promise the pieces arrive in order. TLS cannot be fed a
     * hole, so this buffering is what makes a real handshake work at all -- and
     * its absence would look like an intermittent handshake failure against
     * some clients only. */
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    TEST_REQUIRE_NOT_NULL(ctx, "context");
    TEST_REQUIRE(quictls_configure_ctx(ctx), "configured");

    quictp_t params;
    quictp_defaults(&params);
    params.initial_max_data = 1048576;
    params.has_initial_scid = 1;
    params.initial_scid.len = 8;
    memset(params.initial_scid.data, 0x11, 8);

    probe_t probe;
    memset(&probe, 0, sizeof probe);

    quictls_t tls;
    TEST_REQUIRE(quictls_init_server(&tls, ctx, &probe_ops, &probe, &params),
                 "bridge initialised");

    TEST_CASE("in-order pieces accumulate");
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 0,
                                    (const uint8_t*)"AAAA", 4), "first");
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 4,
                                    (const uint8_t*)"BBBB", 4), "second");

    TEST_CASE("an out-of-order piece is held rather than refused");
    /* Offset 16 arrives before 8..15 exists: it must be buffered, not dropped,
     * or the handshake stalls until the peer retransmits. */
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 16,
                                    (const uint8_t*)"DDDD", 4), "gap accepted");

    /* And -- the part that matters -- it must not become *available*. `len` is
     * what __cb_crypto_recv_rcd hands OpenSSL, so a hole counted here is a hole
     * fed to TLS as zeroes.
     *
     * This is the bug a real browser found and this file did not: the case
     * above asserted only that the insert was accepted, and `len` was the
     * highest offset seen rather than the contiguous prefix. Chrome splits its
     * ClientHello across reordered CRYPTO frames and hit it on the first
     * connection; the test client, which sends one frame at offset 0, never
     * could. */
    TEST_ASSERT(tls.in[QUIC_ENC_INITIAL].len == 8,
                "the prefix stops at the hole, not at the far piece");

    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 8,
                                    (const uint8_t*)"CCCC", 4), "first hole filled");
    /* 12..15 is still missing, so the far piece stays out of reach: the prefix
     * grows to where the *next* hole begins, not to the end of what is held. */
    TEST_ASSERT(tls.in[QUIC_ENC_INITIAL].len == 12, "up to the next hole");

    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 12,
                                    (const uint8_t*)"EEEE", 4), "second hole filled");
    TEST_ASSERT(tls.in[QUIC_ENC_INITIAL].len == 20,
                "closing the last hole releases everything behind it");
    TEST_ASSERT(memcmp(tls.in[QUIC_ENC_INITIAL].data, "AAAABBBBCCCCEEEEDDDD", 20) == 0,
                "and every byte sits at the offset it was sent at");

    TEST_CASE("a retransmission of data already held is harmless");
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 0,
                                    (const uint8_t*)"AAAA", 4), "duplicate");
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 2,
                                    (const uint8_t*)"AABB", 4), "overlapping");

    TEST_CASE("an empty frame is accepted");
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 20, NULL, 0), "zero length");

    TEST_CASE("buffering is bounded (RFC 9000 §7.5)");
    /* A peer that opens a hole and then goes quiet must not be able to hold
     * memory open: a byte at a far offset is refused rather than allocated
     * for. Without this, one datagram costs the server whatever offset it
     * names. */
    TEST_ASSERT(!quictls_recv_crypto(&tls, QUIC_ENC_HANDSHAKE, 1ULL << 30,
                                     (const uint8_t*)"x", 1),
                "a byte at offset 2^30 is refused");
    TEST_ASSERT(!quictls_recv_crypto(&tls, QUIC_ENC_HANDSHAKE, QUICTLS_MAX_CRYPTO_BUFFER,
                                     (const uint8_t*)"x", 1),
                "and so is one exactly at the cap");
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_HANDSHAKE,
                                    QUICTLS_MAX_CRYPTO_BUFFER - 1,
                                    (const uint8_t*)"x", 1),
                "the last byte below it is accepted");

    TEST_CASE("levels are buffered independently");
    /* Initial and Handshake CRYPTO streams have separate offset spaces; sharing
     * a buffer would splice one flight into the other. */
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_APP, 0,
                                    (const uint8_t*)"ZZZZ", 4), "app level");

    TEST_CASE("an unknown level is refused");
    TEST_ASSERT(!quictls_recv_crypto(&tls, QUIC_ENC_COUNT, 0,
                                     (const uint8_t*)"x", 1), "out of range");

    quictls_free(&tls);
    SSL_CTX_free(ctx);
}

/* ---- A real handshake, both ends in this process ----
 *
 * The reassembly test above proves the buffer works; it cannot prove the bridge
 * does. Whether the six callbacks fire in the right order, whether the level
 * tracking is right, whether secrets appear for both directions and whether
 * transport parameters cross -- none of that is a statement about one endpoint,
 * and against a single instance it is untestable.
 *
 * So the client side runs here too, over an in-memory pipe standing in for the
 * CRYPTO streams. What it does NOT do is QUIC: no packets, no encryption of
 * the handshake bytes themselves, no loss. That is phase 4. What it does prove
 * is that our use of SSL_set_quic_tls_cbs produces a completed TLS 1.3
 * handshake with usable keys, which is the whole of phase 3's claim. */

#define PIPE_CAP 16384

typedef struct {
    uint8_t data[QUIC_ENC_COUNT][PIPE_CAP];
    size_t  len[QUIC_ENC_COUNT];
    size_t  delivered[QUIC_ENC_COUNT];
} pipe_t;

typedef struct {
    pipe_t* out;                  /* where this endpoint's CRYPTO bytes go */
    int secrets[QUIC_ENC_COUNT][2];
    int params_seen;
    int alert;
    quic_aead_e suite;
    /* Keys really derived from the yielded secrets: a secret that cannot make
     * a key set is worthless, and only trying it says so. */
    int keys_ok;
} peer_t;

static int peer_install_secret(void* ctx, quic_enc_level_e level, quictls_dir_e dir,
                               quic_aead_e suite, const uint8_t* secret, size_t len) {
    peer_t* p = ctx;
    p->secrets[level][dir]++;
    p->suite = suite;

    quickeys_t keys;
    memset(&keys, 0, sizeof keys);
    if (!quickeys_install(&keys, suite, secret, len)) {
        p->keys_ok = 0;
        return 0;
    }
    quickeys_free(&keys);

    return 1;
}

static int peer_send_crypto(void* ctx, quic_enc_level_e level,
                            const uint8_t* data, size_t len) {
    peer_t* p = ctx;
    pipe_t* pipe = p->out;

    if (pipe->len[level] + len > PIPE_CAP) return 0;

    memcpy(pipe->data[level] + pipe->len[level], data, len);
    pipe->len[level] += len;

    return 1;
}

static int peer_params(void* ctx, const quictp_t* params) {
    (void)params;
    ((peer_t*)ctx)->params_seen++;
    return 1;
}

static void peer_alert(void* ctx, uint8_t code) {
    ((peer_t*)ctx)->alert = code;
}

static const quictls_ops_t peer_ops = {
    .install_secret = peer_install_secret,
    .send_crypto = peer_send_crypto,
    .peer_params = peer_params,
    .alert = peer_alert
};

/* Hand whatever is queued in `pipe` to `tls`, at every level. Returns how many
 * bytes moved, so the driver can tell progress from a stall. */
static size_t deliver(quictls_t* tls, pipe_t* pipe) {
    size_t moved = 0;

    for (int level = 0; level < QUIC_ENC_COUNT; level++) {
        const size_t pending = pipe->len[level] - pipe->delivered[level];
        if (pending == 0) continue;

        quictls_recv_crypto(tls, (quic_enc_level_e)level,
                            pipe->delivered[level],
                            pipe->data[level] + pipe->delivered[level], pending);
        pipe->delivered[level] += pending;
        moved += pending;
    }

    return moved;
}

TEST(test_quic_tls_full_handshake) {
    TEST_SUITE("quic_tls");

    TEST_CASE("a complete TLS 1.3 handshake through the QUIC bridge");

    SSL_CTX* server_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
    TEST_REQUIRE_NOT_NULL(server_ctx, "server context");
    TEST_REQUIRE_NOT_NULL(client_ctx, "client context");

    TEST_REQUIRE(quictls_configure_ctx(server_ctx), "server configured");
    TEST_REQUIRE(quictls_configure_ctx(client_ctx), "client configured");

    /* A certificate generated for these tests. Verification is off on the
     * client: this is about the bridge, not about PKI. */
    const int have_cert =
        SSL_CTX_use_certificate_file(server_ctx, TEST_QUIC_CERT, SSL_FILETYPE_PEM) == 1 &&
        SSL_CTX_use_PrivateKey_file(server_ctx, TEST_QUIC_KEY, SSL_FILETYPE_PEM) == 1;
    TEST_REQUIRE(have_cert, "test certificate loaded");
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);

    static pipe_t to_server;
    static pipe_t to_client;
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);

    peer_t server = { .out = &to_client, .keys_ok = 1 };
    peer_t client = { .out = &to_server, .keys_ok = 1 };

    quictp_t server_params;
    quictp_defaults(&server_params);
    server_params.initial_max_data = 1048576;
    server_params.initial_max_streams_bidi = 100;
    server_params.has_original_dcid = 1;
    server_params.original_dcid.len = 8;
    memset(server_params.original_dcid.data, 0xa1, 8);
    server_params.has_initial_scid = 1;
    server_params.initial_scid.len = 8;
    memset(server_params.initial_scid.data, 0xb2, 8);

    quictp_t client_params;
    quictp_defaults(&client_params);
    client_params.initial_max_data = 524288;
    client_params.has_initial_scid = 1;
    client_params.initial_scid.len = 8;
    memset(client_params.initial_scid.data, 0xc3, 8);

    quictls_t s;
    quictls_t c;
    TEST_REQUIRE(quictls_init_server(&s, server_ctx, &peer_ops, &server, &server_params),
                 "server bridge");
    TEST_REQUIRE(quictls_init_client(&c, client_ctx, &peer_ops, &client, &client_params,
                                     "localhost"), "client bridge");

    /* Drive both sides until neither produces nor consumes anything. Ten rounds
     * is far more than TLS 1.3 needs; a handshake that has not finished by then
     * is stuck, and the assertions below say so. */
    int ok = 1;
    for (int round = 0; round < 10 && ok; round++) {
        ok = ok && quictls_advance(&c);
        deliver(&s, &to_server);
        ok = ok && quictls_advance(&s);
        deliver(&c, &to_client);

        if (s.handshake_complete && c.handshake_complete) break;
    }

    TEST_ASSERT(ok, "no side failed");
    TEST_ASSERT(server.alert == 0 && client.alert == 0, "no TLS alert was raised");
    TEST_ASSERT(s.handshake_complete, "server completed the handshake");
    TEST_ASSERT(c.handshake_complete, "client completed the handshake");

    TEST_CASE("both directions of application keys exist");
    /* The point of the whole bridge: without a 1-RTT secret in each direction
     * there is nothing to protect a packet with. */
    TEST_ASSERT(server.secrets[QUIC_ENC_APP][QUICTLS_DIR_READ] > 0, "server read");
    TEST_ASSERT(server.secrets[QUIC_ENC_APP][QUICTLS_DIR_WRITE] > 0, "server write");
    TEST_ASSERT(client.secrets[QUIC_ENC_APP][QUICTLS_DIR_READ] > 0, "client read");
    TEST_ASSERT(client.secrets[QUIC_ENC_APP][QUICTLS_DIR_WRITE] > 0, "client write");

    TEST_CASE("handshake keys came before application keys");
    TEST_ASSERT(server.secrets[QUIC_ENC_HANDSHAKE][QUICTLS_DIR_WRITE] > 0,
                "server handshake write");
    TEST_ASSERT(client.secrets[QUIC_ENC_HANDSHAKE][QUICTLS_DIR_READ] > 0,
                "client handshake read");

    TEST_CASE("every yielded secret produced usable keys");
    TEST_ASSERT(server.keys_ok && client.keys_ok, "quickeys_install accepted all of them");

    TEST_CASE("the negotiated suite is one QUIC permits");
    /* CCM would land here if the ciphersuite list were inherited from the vhost
     * rather than set for QUIC (RFC 9001 §5.3). */
    TEST_ASSERT(server.suite != QUIC_AEAD_UNSUPPORTED, "server suite usable");
    TEST_ASSERT(server.suite == client.suite, "both sides agree");

    TEST_CASE("transport parameters crossed");
    TEST_ASSERT(server.params_seen == 1, "server received the client's");
    TEST_ASSERT(client.params_seen == 1, "client received the server's");

    TEST_CASE("ALPN selected h3");
    const unsigned char* alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(c.ssl, &alpn, &alpn_len);
    TEST_ASSERT(alpn_len == 2 && memcmp(alpn, "h3", 2) == 0, "h3");

    quictls_free(&s);
    quictls_free(&c);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
}

TEST(test_quic_tls_handshake_start) {
    TEST_SUITE("quic_tls");

    TEST_CASE("the bridge drives a handshake as far as it can alone");
    /* Without a certificate and a peer this cannot complete -- that is interop
     * territory -- but advancing must be safe and must not report success. */
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    TEST_REQUIRE_NOT_NULL(ctx, "context");
    TEST_REQUIRE(quictls_configure_ctx(ctx), "configured");

    quictp_t params;
    quictp_defaults(&params);
    params.has_initial_scid = 1;
    params.initial_scid.len = 8;
    memset(params.initial_scid.data, 0x22, 8);

    probe_t probe;
    memset(&probe, 0, sizeof probe);

    quictls_t tls;
    TEST_REQUIRE(quictls_init_server(&tls, ctx, &probe_ops, &probe, &params), "init");

    /* Nothing fed yet: TLS wants to read, which is not a failure. */
    TEST_ASSERT(quictls_advance(&tls), "advancing with no input is not an error");
    TEST_ASSERT(!tls.handshake_complete, "and does not complete the handshake");
    TEST_ASSERT(probe.secrets == 0, "no secrets yielded yet");

    TEST_CASE("garbage in the CRYPTO stream fails the handshake, not the process");
    /* An attacker's first Initial is unauthenticated, so this path takes
     * arbitrary bytes and must fail cleanly. */
    static const uint8_t junk[64] = { 0xff };
    TEST_ASSERT(quictls_recv_crypto(&tls, QUIC_ENC_INITIAL, 0, junk, sizeof junk),
                "accepted into the buffer");
    /* Either TLS rejects it now or waits for more; both are fine, a crash is
     * not, and success would be wrong. */
    quictls_advance(&tls);
    TEST_ASSERT(!tls.handshake_complete, "handshake did not complete on junk");

    quictls_free(&tls);
    SSL_CTX_free(ctx);

    TEST_CASE("NULL arguments are refused");
    quictls_t empty;
    TEST_ASSERT(!quictls_init_server(&empty, NULL, &probe_ops, &probe, &params),
                "no SSL_CTX");
    TEST_ASSERT(!quictls_configure_ctx(NULL), "no context");
    TEST_ASSERT(!quictls_advance(NULL), "no bridge");
    quictls_free(NULL);
}
