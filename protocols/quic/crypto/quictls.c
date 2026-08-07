#include <openssl/core_dispatch.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "quictls.h"

/* OpenSSL's protection levels, mapped onto ours. They agree on order but not on
 * spelling, and the numbers are part of the ABI. */
static quic_enc_level_e __level_of(uint32_t prot_level) {
    switch (prot_level) {
    case OSSL_RECORD_PROTECTION_LEVEL_NONE:      return QUIC_ENC_INITIAL;
    case OSSL_RECORD_PROTECTION_LEVEL_EARLY:     return QUIC_ENC_EARLY;
    case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE: return QUIC_ENC_HANDSHAKE;
    default:                                     return QUIC_ENC_APP;
    }
}

/* ---- CRYPTO reassembly ---- */

static void __crypto_in_free(quictls_crypto_in_t* in) {
    free(in->data);
    in->data = NULL;
    in->len = 0;
    in->cap = 0;
}

/* Insert at `offset`, growing as needed. Only a contiguous prefix is ever
 * handed to TLS, so out-of-order pieces simply sit until the gap is filled. */
static int __crypto_in_insert(quictls_crypto_in_t* in, uint64_t offset,
                              const uint8_t* data, size_t len) {
    if (len == 0) return 1;

    /* Entirely behind what OpenSSL has already taken: a retransmission of data
     * that has served its purpose. */
    if (offset + len <= in->base) return 1;

    /* Overlapping the consumed part: trim the front rather than rejecting, as
     * a retransmission may legitimately start earlier than where we are. */
    if (offset < in->base) {
        const uint64_t skip = in->base - offset;
        if (skip >= len) return 1;
        data += skip;
        len -= (size_t)skip;
        offset = in->base;
    }

    const uint64_t end = offset + len;
    if (end > in->max_offset) in->max_offset = end;

    /* §7.5: bound what an incomplete handshake can hold open. */
    if (end - in->base > QUICTLS_MAX_CRYPTO_BUFFER) return 0;

    const size_t need = (size_t)(end - in->base);
    if (need > in->cap) {
        size_t cap = in->cap == 0 ? 4096 : in->cap;
        while (cap < need) cap *= 2;
        if (cap > QUICTLS_MAX_CRYPTO_BUFFER) cap = QUICTLS_MAX_CRYPTO_BUFFER;

        uint8_t* grown = realloc(in->data, cap);
        if (grown == NULL) return 0;

        /* Zero the new region: a hole must read as something deterministic,
         * even though nothing should read it before it is filled. */
        memset(grown + in->cap, 0, cap - in->cap);
        in->data = grown;
        in->cap = cap;
    }

    memcpy(in->data + (offset - in->base), data, len);

    if (need > in->len) in->len = need;

    return 1;
}

/* ---- OpenSSL callbacks ---- */

static int __cb_crypto_send(SSL* ssl, const unsigned char* buf, size_t buf_len,
                            size_t* consumed, void* arg) {
    (void)ssl;
    quictls_t* tls = arg;

    if (tls->ops->send_crypto(tls->ctx, tls->write_level, buf, buf_len) != 1)
        return 0;

    /* All of it, always: the transport copies into its own send buffer, which
     * grows, so there is no reason to hold any back. */
    *consumed = buf_len;

    return 1;
}

static int __cb_crypto_recv_rcd(SSL* ssl, const unsigned char** buf,
                                size_t* bytes_read, void* arg) {
    (void)ssl;
    quictls_t* tls = arg;
    quictls_crypto_in_t* in = &tls->in[tls->read_level];

    /* Only the contiguous prefix. Handing over bytes past a hole would feed TLS
     * a spliced message. */
    const size_t available = in->len - in->consumed;

    *buf = in->data != NULL ? in->data + in->consumed : NULL;
    *bytes_read = available;

    /* Zero is not an error: it means "nothing more yet", and OpenSSL will ask
     * again after the next quictls_advance. */
    return 1;
}

static int __cb_crypto_release_rcd(SSL* ssl, size_t bytes_read, void* arg) {
    (void)ssl;
    quictls_t* tls = arg;
    quictls_crypto_in_t* in = &tls->in[tls->read_level];

    if (bytes_read > in->len - in->consumed) return 0;

    in->consumed += bytes_read;

    /* Once everything held has been taken, reclaim the buffer rather than let
     * it creep: a handshake makes a handful of these calls in total. */
    if (in->consumed == in->len) {
        in->base += in->len;
        in->len = 0;
        in->consumed = 0;
    }

    return 1;
}

static int __cb_yield_secret(SSL* ssl, uint32_t prot_level, int direction,
                             const unsigned char* secret, size_t secret_len,
                             void* arg) {
    quictls_t* tls = arg;
    const quic_enc_level_e level = __level_of(prot_level);
    const quictls_dir_e dir = direction ? QUICTLS_DIR_WRITE : QUICTLS_DIR_READ;

    /* The suite is only knowable once the handshake has chosen it, which is
     * exactly when the first non-Initial secret appears. */
    if (tls->suite == QUIC_AEAD_UNSUPPORTED) {
        tls->suite = quiccrypto_suite_of(SSL_get_current_cipher(ssl));
        if (tls->suite == QUIC_AEAD_UNSUPPORTED) {
            log_error("quictls: negotiated cipher suite is not usable with QUIC\n");
            return 0;
        }
    }

    /* Track where OpenSSL now reads and writes: the callbacks above have no
     * other way to know which level their bytes belong to. */
    if (dir == QUICTLS_DIR_READ) tls->read_level = level;
    else tls->write_level = level;

    return tls->ops->install_secret(tls->ctx, level, dir, tls->suite,
                                    secret, secret_len);
}

static int __cb_got_transport_params(SSL* ssl, const unsigned char* params,
                                     size_t params_len, void* arg) {
    (void)ssl;
    quictls_t* tls = arg;

    quictp_t tp;
    quictp_defaults(&tp);

    /* Which asymmetric parameters are legal depends on who sent them: a server
     * peer may send original_destination_connection_id and friends, a client
     * peer may not (§18.2). Getting this backwards would either reject every
     * conforming server or accept a client impersonating one. */
    if (quictp_decode(params, params_len, tls->is_server, &tp) != QUICTP_OK) {
        log_error("quictls: peer transport parameters rejected\n");
        return 0;
    }

    return tls->ops->peer_params(tls->ctx, &tp);
}

static int __cb_alert(SSL* ssl, unsigned char alert_code, void* arg) {
    (void)ssl;
    quictls_t* tls = arg;

    tls->alert_raised = 1;
    tls->alert_code = alert_code;
    tls->ops->alert(tls->ctx, alert_code);

    return 1;
}

static const OSSL_DISPATCH __quic_tls_dispatch[] = {
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,          (void (*)(void))__cb_crypto_send },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,      (void (*)(void))__cb_crypto_recv_rcd },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,   (void (*)(void))__cb_crypto_release_rcd },
    { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,         (void (*)(void))__cb_yield_secret },
    { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))__cb_got_transport_params },
    { OSSL_FUNC_SSL_QUIC_TLS_ALERT,                (void (*)(void))__cb_alert },
    OSSL_DISPATCH_END
};

/* ---- ALPN ---- */

/* QUIC offers h3 and nothing else. The vhost's TCP callback offers h2 and
 * http/1.1, and a QUIC connection that negotiated either would be a protocol
 * error -- so this callback replaces it on QUIC SSLs rather than extending it. */
static int __alpn_select_h3(SSL* ssl, const unsigned char** out,
                            unsigned char* outlen,
                            const unsigned char* in, unsigned int inlen,
                            void* arg) {
    (void)ssl;
    (void)arg;

    static const unsigned char h3[] = { 'h', '3' };

    for (unsigned int i = 0; i + 1 <= inlen; ) {
        const unsigned int len = in[i];
        if (len == 0 || i + 1 + len > inlen) break;

        if (len == sizeof h3 && memcmp(in + i + 1, h3, len) == 0) {
            *out = in + i + 1;
            *outlen = (unsigned char)len;
            return SSL_TLSEXT_ERR_OK;
        }

        i += 1 + len;
    }

    /* No h3 on offer. Unlike TCP, where falling back to http/1.1 is sensible,
     * there is nothing else this connection could be for. */
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int quictls_configure_ctx(SSL_CTX* ssl_ctx) {
    if (ssl_ctx == NULL) return 0;

    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) return 0;
    if (SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) return 0;

    /* RFC 9001 §5.3 forbids TLS_AES_128_CCM_8_SHA256 in QUIC: its 64-bit tag is
     * too short for the integrity limits of §6.6. Plain CCM is left out too --
     * see quiccrypto.h. This must be set here rather than inherited, because
     * this project's config.json lists CCM_8 for TCP. */
    if (SSL_CTX_set_ciphersuites(ssl_ctx,
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256") != 1)
        return 0;

    SSL_CTX_set_alpn_select_cb(ssl_ctx, __alpn_select_h3, NULL);

    /* 0-RTT is phase 9: accepting early data needs an anti-replay policy this
     * server does not have yet, and the default must be off rather than
     * accidentally on. */
    SSL_CTX_set_max_early_data(ssl_ctx, 0);

    return 1;
}

/* ---- Lifecycle ---- */

static int __init(quictls_t* tls, SSL_CTX* ssl_ctx,
                  const quictls_ops_t* ops, void* ctx,
                  const quictp_t* params, int is_server, const char* server_name) {
    if (tls == NULL || ssl_ctx == NULL || ops == NULL || params == NULL) return 0;

    memset(tls, 0, sizeof * tls);
    tls->ops = ops;
    tls->ctx = ctx;
    tls->is_server = is_server;
    tls->suite = QUIC_AEAD_UNSUPPORTED;
    tls->read_level = QUIC_ENC_INITIAL;
    tls->write_level = QUIC_ENC_INITIAL;

    tls->ssl = SSL_new(ssl_ctx);
    if (tls->ssl == NULL) return 0;

    if (is_server) {
        SSL_set_accept_state(tls->ssl);
    }
    else {
        SSL_set_connect_state(tls->ssl);

        if (server_name != NULL) {
            SSL_set_tlsext_host_name(tls->ssl, server_name);

            static const unsigned char alpn_h3[] = { 2, 'h', '3' };
            SSL_set_alpn_protos(tls->ssl, alpn_h3, sizeof alpn_h3);
        }
    }

    if (SSL_set_quic_tls_cbs(tls->ssl, __quic_tls_dispatch, tls) != 1) {
        log_error("quictls: SSL_set_quic_tls_cbs failed\n");
        goto failed;
    }

    /* Encoded into the struct, not onto the stack: OpenSSL keeps the pointer
     * rather than copying (see quictls.h). */
    tls->params_len = quictp_encode(tls->params, sizeof tls->params, params);
    if (tls->params_len == 0) {
        log_error("quictls: cannot encode transport parameters\n");
        goto failed;
    }

    if (SSL_set_quic_tls_transport_params(tls->ssl, tls->params, tls->params_len) != 1) {
        log_error("quictls: SSL_set_quic_tls_transport_params failed\n");
        goto failed;
    }

    return 1;

    failed:

    SSL_free(tls->ssl);
    tls->ssl = NULL;

    return 0;
}

int quictls_init_server(quictls_t* tls, SSL_CTX* ssl_ctx,
                        const quictls_ops_t* ops, void* ctx,
                        const quictp_t* params) {
    return __init(tls, ssl_ctx, ops, ctx, params, 1, NULL);
}

int quictls_init_client(quictls_t* tls, SSL_CTX* ssl_ctx,
                        const quictls_ops_t* ops, void* ctx,
                        const quictp_t* params, const char* server_name) {
    return __init(tls, ssl_ctx, ops, ctx, params, 0, server_name);
}

void quictls_free(quictls_t* tls) {
    if (tls == NULL) return;

    SSL_free(tls->ssl);
    tls->ssl = NULL;

    for (int i = 0; i < QUIC_ENC_COUNT; i++)
        __crypto_in_free(&tls->in[i]);
}

int quictls_recv_crypto(quictls_t* tls, quic_enc_level_e level,
                        uint64_t offset, const uint8_t* data, size_t len) {
    if (tls == NULL || level >= QUIC_ENC_COUNT) return 0;

    return __crypto_in_insert(&tls->in[level], offset, data, len);
}

int quictls_advance(quictls_t* tls) {
    if (tls == NULL || tls->ssl == NULL) return 0;
    if (tls->alert_raised) return 0;
    if (tls->handshake_complete) return 1;

    const int r = SSL_do_handshake(tls->ssl);
    if (r == 1) {
        tls->handshake_complete = 1;
        return 1;
    }

    const int err = SSL_get_error(tls->ssl, r);

    /* WANT_READ is the normal state between flights: TLS has consumed what it
     * was given and is waiting for the peer. */
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 1;

    /* Anything else is fatal. __cb_alert has usually already told the
     * connection which alert to report. */
    if (!tls->alert_raised)
        log_error("quictls: handshake failed (SSL error %d)\n", err);

    return 0;
}
