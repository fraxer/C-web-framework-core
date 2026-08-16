#ifndef __OPENSSL__
#define __OPENSSL__

#include <openssl/ssl.h>
#include <openssl/err.h>

#define TLS_ERROR_ALLOC_SSL "Tls error: can't allocate a new ssl object\n"
#define TLS_ERROR_SET_SSL_FD "Tls error: can't attach fd to ssl\n"

/* Классификация возврата SSL_read/SSL_write. errno неприменим к SSL:
 * причина «не готово» (WANT_READ/WANT_WRITE) читается только через SSL_get_error. */
typedef enum {
    OPENSSL_IO_OK,          /* ret > 0: данные переданы */
    OPENSSL_IO_WANT_READ,   /* повторить при EPOLLIN */
    OPENSSL_IO_WANT_WRITE,  /* повторить при EPOLLOUT */
    OPENSSL_IO_CLOSED,      /* peer корректно закрыл соединение */
    OPENSSL_IO_ERROR        /* фатальная ошибка */
} openssl_io_status_e;

typedef struct openssl {
    char* fullchain;
    char* private;
    char* ciphers;
    SSL_CTX* ctx;

    /* A second context for QUIC, from the same certificate and key.
     *
     * Not an optimisation to share one: the protocol policy genuinely differs.
     * QUIC is TLS 1.3 only, offers `h3` alone in ALPN, and must not offer
     * TLS_AES_128_CCM_8_SHA256, which RFC 9001 §5.3 forbids and which this
     * project's config.json lists for TCP. A single context cannot be both,
     * and SNI makes the difference load-bearing: the callback switches
     * contexts mid-handshake, so a QUIC connection that landed on the TCP
     * context would silently negotiate h2 over QUIC, or a forbidden cipher.
     *
     * NULL when the build has no HTTP/3. */
    SSL_CTX* quic_ctx;
} openssl_t;

/* Split a configured cipher string into the TLS 1.2-and-below list and the
 * TLS 1.3 suite list. OpenSSL keeps the two apart — SSL_CTX_set_cipher_list has
 * no effect on TLS 1.3 and SSL_CTX_set_ciphersuites none below it — so one
 * config field has to be routed to both. TLS 1.3 suite names are exactly those
 * starting with "TLS_".
 *
 * Both outputs are malloc'd ':'-joined lists, or NULL when that group has no
 * tokens: the caller must then leave OpenSSL's defaults for that version alone
 * rather than install an empty list, which would turn the version off outright.
 * Returns 0 only on allocation failure. Exposed for unit tests. */
int openssl_split_ciphers(const char* ciphers, char** out_tls12, char** out_tls13);

int openssl_init(openssl_t* openssl);
openssl_t* openssl_create(void);
void openssl_free(openssl_t* openssl);
void openssl_set_sni_callback(openssl_t* openssl, int (*callback)(SSL*, int*, void*));
int openssl_read(SSL*, void*, size_t);
void openssl_set_read_ahead(SSL*, int);
/* Non-zero when decrypted or unprocessed bytes are waiting inside the library,
 * where epoll cannot see them. Must be checked by any reader that leaves its
 * loop before SSL_read reports WANT_READ. */
int openssl_pending(SSL*);
int openssl_write(SSL*, const void*, size_t);
openssl_io_status_e openssl_io_status(SSL*, int ret);

/* Is the negotiated cipher suite acceptable for HTTP/2 (RFC 9113 §9.2.2)?
 *
 * §9.2.2 forbids the suites listed in Appendix A — some 250 of them. Rather
 * than carry that table, this applies the rule that *generates* it: every suite
 * in Appendix A either is not an AEAD, or does not use an ephemeral key
 * exchange. Checking those two properties is equivalent, stays correct if the
 * list ever grows, and asks OpenSSL questions it can answer directly.
 *
 * TLS 1.3 suites are all AEAD with ephemeral exchange by construction, so they
 * pass without a special case beyond their key-exchange NID being "any". */
int openssl_cipher_ok_for_http2(SSL* ssl);

#endif