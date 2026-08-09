#ifndef __QUICTLS__
#define __QUICTLS__

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

#include "quic.h"
#include "quiccrypto.h"
#include "quictp.h"

/* The bridge between OpenSSL's TLS 1.3 handshake and our QUIC transport
 * (RFC 9001, docs/http3/03-quic-tls.md).
 *
 * OpenSSL 3.5 added SSL_set_quic_tls_cbs, which puts an SSL into a mode where
 * it produces no records and touches no BIO: handshake bytes come and go
 * through callbacks, and each encryption level's secret is handed out as it is
 * derived. That is exactly the division of labour this project needs -- the
 * library does TLS, we do QUIC.
 *
 * The interface is kept deliberately narrow (six callbacks, one struct) so that
 * a backend for a different library -- BoringSSL's SSL_QUIC_METHOD, say -- could
 * be written under it without the transport noticing.
 *
 * ## Ordering
 *
 * The handshake is driven by feeding CRYPTO frames in and taking CRYPTO bytes
 * out; keys appear as a side effect partway through. A server sees roughly:
 *
 *   client Initial CRYPTO  -> quictls_recv_crypto(INITIAL)
 *   quictls_advance()      -> handshake secrets yielded, ServerHello queued
 *                          -> transport parameters arrive from the client
 *   client Handshake CRYPTO-> quictls_recv_crypto(HANDSHAKE)
 *   quictls_advance()      -> application secrets yielded, handshake complete
 */

struct quicconn;

/* Where a secret belongs. Mirrors OpenSSL's direction argument. */
typedef enum {
    QUICTLS_DIR_READ = 0,   /* decrypt what the peer sends */
    QUICTLS_DIR_WRITE
} quictls_dir_e;

/* What the bridge does with the pieces it produces. Supplied by the connection
 * layer (phase 4); keeping it a vtable is what stops this module from having to
 * know what a connection is.
 *
 * Every callback runs inside quictls_advance or quictls_recv_crypto, on the
 * thread that called them, with the connection lock already held. */
typedef struct quictls_ops {
    /* A secret for one level and direction is ready. The implementation derives
     * keys from it (quickeys_install) and installs them. Return 0 to fail the
     * connection. */
    int (*install_secret)(void* ctx, quic_enc_level_e level, quictls_dir_e dir,
                          quic_aead_e suite, const uint8_t* secret, size_t len);

    /* Handshake bytes to be sent at this level, as CRYPTO frames. The transport
     * copies them into its own send buffer; the pointer does not outlive the
     * call. */
    int (*send_crypto)(void* ctx, quic_enc_level_e level,
                       const uint8_t* data, size_t len);

    /* The peer's transport parameters, already decoded and validated. */
    int (*peer_params)(void* ctx, const quictp_t* params);

    /* TLS wants the connection closed with CRYPTO_ERROR(alert). */
    void (*alert)(void* ctx, uint8_t alert_code);
} quictls_ops_t;

/* Incoming CRYPTO data for one level, reassembled.
 *
 * A ClientHello with a large extension list -- ECH, a long ALPN list, post
 * quantum key shares -- exceeds one datagram routinely, and the pieces can
 * arrive out of order. TLS cannot be fed a hole, so the bytes are buffered
 * here until a contiguous prefix exists. */
/* Received pieces past the contiguous prefix are tracked as ranges. A flight
 * arrives in a handful of frames, so the list is small and fixed; a peer that
 * manufactures more disjoint pieces than this is fragmenting to make us work,
 * and is refused rather than accommodated. */
#define QUICTLS_CRYPTO_MAX_RANGES 32

typedef struct quictls_crypto_range {
    size_t start;
    size_t end;        /* exclusive */
} quictls_crypto_range_t;

typedef struct quictls_crypto_in {
    uint8_t* data;     /* data[i] is stream offset i for this level */
    /* Length of the *contiguous* prefix, which is all TLS may ever be handed.
     * This used to be the highest offset seen, and the difference is not
     * academic: a hole was zero-filled and passed to OpenSSL as if it were
     * real, which a peer that splits its ClientHello across reordered CRYPTO
     * frames -- every browser -- triggers on the first connection. */
    size_t   len;
    size_t   cap;
    size_t   consumed; /* how much of data OpenSSL has taken */

    quictls_crypto_range_t ranges[QUICTLS_CRYPTO_MAX_RANGES];
    size_t   range_count;
} quictls_crypto_in_t;

typedef struct quictls {
    SSL* ssl;

    const quictls_ops_t* ops;
    void* ctx;                  /* passed back to every op */

    quictls_crypto_in_t in[QUIC_ENC_COUNT];

    /* The level OpenSSL is currently reading at. Tracked from the read secrets
     * it has yielded: it never reads at a level whose keys it has not derived. */
    quic_enc_level_e read_level;
    /* The level its output belongs to, from the write secrets. */
    quic_enc_level_e write_level;

    quic_aead_e suite;

    /* Our encoded transport parameters.
     *
     * They live here, for the lifetime of the SSL, because
     * SSL_set_quic_tls_transport_params() does NOT copy what it is given -- it
     * keeps the pointer and reads it later, when the extension is written into
     * the handshake. Passing a local buffer compiles, passes a round-trip test
     * and then reads freed stack during the handshake; ASan caught it here as a
     * stack-use-after-return, but only with detect_stack_use_after_return
     * enabled, which the project's usual profiling setting turns off. */
    uint8_t  params[512];
    size_t   params_len;

    int is_server;
    int handshake_complete;
    int alert_raised;
    uint8_t alert_code;

    /* A QUIC transport error code the connection must close with, set when the
     * TLS stack's own way of failing would name the wrong thing. Refusing a
     * transport parameter can only be done by failing the handshake, and that
     * reaches the peer as a bare close_notify -- which says nothing about which
     * parameter, or even that a parameter was the reason. §18.2 asks for
     * TRANSPORT_PARAMETER_ERROR, so the code travels out of here and the
     * connection layer sends it. 0 when unset. */
    uint64_t transport_error;
} quictls_t;

/* Cap on buffered CRYPTO data per level. A peer that sends a hole and then
 * nothing must not be able to hold memory open indefinitely; exceeding this is
 * CRYPTO_BUFFER_EXCEEDED (RFC 9000 §7.5). */
#define QUICTLS_MAX_CRYPTO_BUFFER 65536

/* Build the server side of a handshake. `params` is encoded and handed to TLS
 * for the quic_transport_parameters extension. Returns 1 on success. */
int quictls_init_server(quictls_t* tls, SSL_CTX* ssl_ctx,
                        const quictls_ops_t* ops, void* ctx,
                        const quictp_t* params);

/* The client side of the same bridge.
 *
 * This server has no use for a QUIC client, and phase 4 will not call it. It
 * exists so the bridge can be tested against a real TLS 1.3 peer rather than
 * against itself: without a second endpoint, "the six callbacks fire in the
 * right order with the right levels" is not a testable statement, and the
 * alternative is discovering it during interop. The same function becomes the
 * basis of the deterministic test client of docs/http3/08-testing.md §2. */
int quictls_init_client(quictls_t* tls, SSL_CTX* ssl_ctx,
                        const quictls_ops_t* ops, void* ctx,
                        const quictp_t* params, const char* server_name);

void quictls_free(quictls_t* tls);

/* Feed a CRYPTO frame. Data may arrive out of order and overlap. */
int quictls_recv_crypto(quictls_t* tls, quic_enc_level_e level,
                        uint64_t offset, const uint8_t* data, size_t len);

/* Drive the handshake as far as it will go with what has been fed.
 *
 * Returns 1 while the handshake is progressing or complete, 0 on failure -- in
 * which case ops->alert has usually already reported why. Safe to call when
 * nothing has changed; it is a no-op then. */
int quictls_advance(quictls_t* tls);

/* Configure an SSL_CTX for QUIC.
 *
 * Not the same configuration as TCP, and the difference is load-bearing:
 *
 *  - TLS 1.3 only. QUIC has no meaning below it.
 *  - ALPN offers h3 alone. A QUIC connection that negotiated h2 would be a
 *    protocol error, and the vhost's TCP callback offers exactly that.
 *  - The ciphersuite list excludes CCM. RFC 9001 §5.3 forbids
 *    TLS_AES_128_CCM_8_SHA256 in QUIC outright -- and this project's config.json
 *    lists it, so inheriting the vhost list would silently produce a
 *    non-conforming connection.
 *
 * The certificate, key and SNI arrangement are shared with TCP; only the
 * protocol policy differs. */
int quictls_configure_ctx(SSL_CTX* ssl_ctx);

/* Whether the handshake settled on `hq-interop` rather than h3. Always 0 unless
 * the interop shim was built in, which is what keeps the caller's branch honest
 * without it having to know about the flag. */
int quictls_alpn_is_hq(const quictls_t* tls);

#endif
