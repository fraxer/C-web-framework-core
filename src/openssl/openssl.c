#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "log.h"
#include "openssl.h"

#ifdef CWFR_HTTP3
#include "quictls.h"
#endif

#define OPENSSL_ERROR_CHAIN_FILE "Openssl error: can't load chain file\n"
#define OPENSSL_ERROR_PRIVATE_FILE "Openssl error: can't load private file\n"
#define OPENSSL_ERROR_CHECK_PRIVATE_FILE "Openssl error: private file check failed\n"
#define OPENSSL_ERROR_CIPHER_LIST "Openssl error: cipher list is invalid\n"
#define OPENSSL_ERROR_CIPHERSUITES "Openssl error: TLS 1.3 ciphersuites are invalid\n"
#define OPENSSL_ERROR_MIN_PROTO "Openssl error: can't set minimum protocol version\n"
#define OPENSSL_ERROR_CONFIG "Openssl error: fullchain, private or ciphers not set\n"

static int openssl_context_init(openssl_t*);

/* ALPN (RFC 7301): клиент присылает список {len, proto}*; сервер выбирает один.
 * Приоритет сервера — h2 предпочтительнее http/1.1 (см. docs/http2/04 §2). */
static int __openssl_alpn_select_cb(SSL* ssl, const unsigned char** out,
                                    unsigned char* outlen,
                                    const unsigned char* in, unsigned int inlen,
                                    void* arg) {
    (void)ssl;
    (void)arg;

    static const unsigned char h2_proto[] = { 'h', '2' };
    static const unsigned char http11_proto[] = { 'h','t','t','p','/','1','.','1' };

    for (unsigned int i = 0; i + 1 <= inlen; ) {
        const unsigned int len = in[i];
        if (len == 0 || i + 1 + len > inlen) break;
        if (len == sizeof h2_proto && memcmp(in + i + 1, h2_proto, len) == 0) {
            *out = in + i + 1;
            *outlen = (unsigned char)len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + len;
    }

    for (unsigned int i = 0; i + 1 <= inlen; ) {
        const unsigned int len = in[i];
        if (len == 0 || i + 1 + len > inlen) break;
        if (len == sizeof http11_proto && memcmp(in + i + 1, http11_proto, len) == 0) {
            *out = in + i + 1;
            *outlen = (unsigned char)len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + len;
    }

    /* Нет пересечения — ALPN не выбирается, соединение продолжается как h1.1. */
    return SSL_TLSEXT_ERR_NOACK;
}

/* A cipher token belongs to TLS 1.3 iff it is one of the suite names the
 * standard defines, and those all start with "TLS_" — no cipher name from 1.2
 * or below does. */
static int __is_tls13_suite(const char* token, size_t len) {
    return len > 4 && memcmp(token, "TLS_", 4) == 0;
}

/* See openssl.h. ciphers(1) accepts ':', ',' and whitespace as separators, so
 * tokenizing on all three is lossless: the TLS 1.2 control syntax (!aNULL,
 * @STRENGTH, -MD5, ALL) is copied through untouched and order is preserved
 * within each group. */
int openssl_split_ciphers(const char* ciphers, char** out_tls12, char** out_tls13) {
    *out_tls12 = NULL;
    *out_tls13 = NULL;

    if (ciphers == NULL) return 1;

    /* Each token costs its own length plus one joining ':', and the input
     * already spends at least one byte separating them, so neither group can
     * outgrow the input. */
    const size_t len = strlen(ciphers);
    char* tls12 = malloc(len + 1);
    char* tls13 = malloc(len + 1);
    if (tls12 == NULL || tls13 == NULL) {
        free(tls12);
        free(tls13);
        return 0;
    }

    size_t len12 = 0;
    size_t len13 = 0;

    for (const char* p = ciphers; *p != '\0'; ) {
        while (*p == ':' || *p == ',' || *p == ' ' || *p == '\t') p++;

        const char* token = p;
        while (*p != '\0' && *p != ':' && *p != ',' && *p != ' ' && *p != '\t') p++;

        const size_t token_len = (size_t)(p - token);
        if (token_len == 0) continue; /* trailing separators */

        const int tls13_suite = __is_tls13_suite(token, token_len);
        char* dst = tls13_suite ? tls13 : tls12;
        size_t* dst_len = tls13_suite ? &len13 : &len12;

        if (*dst_len > 0) dst[(*dst_len)++] = ':';

        memcpy(dst + *dst_len, token, token_len);
        *dst_len += token_len;
    }

    tls12[len12] = '\0';
    tls13[len13] = '\0';

    if (len12 > 0) *out_tls12 = tls12; else free(tls12);
    if (len13 > 0) *out_tls13 = tls13; else free(tls13);

    return 1;
}

/* Install the configured ciphers, routing each group to its own OpenSSL API.
 * A group with no tokens is left at OpenSSL's defaults: a config that names
 * only 1.2 ciphers must not disable TLS 1.3, and vice versa. */
static int openssl_apply_ciphers(openssl_t* openssl) {
    char* tls12 = NULL;
    char* tls13 = NULL;

    if (!openssl_split_ciphers(openssl->ciphers, &tls12, &tls13)) {
        log_error(OPENSSL_ERROR_CIPHER_LIST);
        return 0;
    }

    /* Nothing usable at all (empty string, or only separators) — the same
     * failure an empty list gave before. */
    if (tls12 == NULL && tls13 == NULL) {
        log_error(OPENSSL_ERROR_CIPHER_LIST);
        return 0;
    }

    const int ok12 = tls12 == NULL || SSL_CTX_set_cipher_list(openssl->ctx, tls12) == 1;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    const int ok13 = tls13 == NULL || SSL_CTX_set_ciphersuites(openssl->ctx, tls13) == 1;
#else
    /* TLS 1.3 itself arrived in 1.1.1; naming its suites on an older library
     * cannot be honoured, and silently dropping them is the bug this function
     * exists to fix. */
    const int ok13 = tls13 == NULL;
    if (tls13 != NULL)
        log_error("Openssl error: TLS 1.3 ciphersuites need OpenSSL 1.1.1 or newer\n");
#endif

    free(tls12);
    free(tls13);

    if (!ok12) log_error(OPENSSL_ERROR_CIPHER_LIST);
    if (!ok13) log_error(OPENSSL_ERROR_CIPHERSUITES);

    return ok12 && ok13;
}

/* No manual library init: TLS_server_method() already requires
 * OpenSSL >= 1.1.0, which self-initializes thread-safely on first use. */
int openssl_init(openssl_t* openssl) {
    if (openssl == NULL) return 0;

    if (openssl_context_init(openssl) == -1) return 0;

    return 1;
}

static int openssl_context_init(openssl_t* openssl) {
    int result = -1;

    if (openssl->fullchain == NULL || openssl->private == NULL || openssl->ciphers == NULL) {
        log_error(OPENSSL_ERROR_CONFIG);
        return -1;
    }

    if (openssl->ctx != NULL) {
        SSL_CTX_free(openssl->ctx);
        openssl->ctx = NULL;
    }

    openssl->ctx = SSL_CTX_new(TLS_server_method());
    if (openssl->ctx == NULL) return -1;

    if (SSL_CTX_use_certificate_chain_file(openssl->ctx, openssl->fullchain) != 1) {
        log_error(OPENSSL_ERROR_CHAIN_FILE);
        goto failed;
    }
    
    if (SSL_CTX_use_PrivateKey_file(openssl->ctx, openssl->private, SSL_FILETYPE_PEM) != 1) {
        log_error(OPENSSL_ERROR_PRIVATE_FILE);
        goto failed;
    }

    if (!SSL_CTX_check_private_key(openssl->ctx)) {
        log_error(OPENSSL_ERROR_CHECK_PRIVATE_FILE);
        goto failed;
    }

    SSL_CTX_set_options(openssl->ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_quiet_shutdown(openssl->ctx, 1);

    if (SSL_CTX_set_min_proto_version(openssl->ctx, TLS1_2_VERSION) != 1) {
        log_error(OPENSSL_ERROR_MIN_PROTO);
        goto failed;
    }

    if (!openssl_apply_ciphers(openssl)) goto failed;

    /* ALPN: рекламируем h2 и http/1.1 на каждом серверном контексте. SNI меняет
     * ssl_ctx до выбора ALPN, поэтому callback срабатывает уже для нужного vhost. */
    SSL_CTX_set_alpn_select_cb(openssl->ctx, __openssl_alpn_select_cb, NULL);

#ifdef CWFR_HTTP3
    /* The QUIC twin: same certificate and key, different protocol policy.
     * Built here rather than lazily so that a configuration error shows up at
     * load time, next to every other one, instead of on the first handshake. */
    if (openssl->quic_ctx != NULL) {
        SSL_CTX_free(openssl->quic_ctx);
        openssl->quic_ctx = NULL;
    }

    openssl->quic_ctx = SSL_CTX_new(TLS_server_method());
    if (openssl->quic_ctx == NULL) goto failed;

    if (SSL_CTX_use_certificate_chain_file(openssl->quic_ctx, openssl->fullchain) != 1 ||
        SSL_CTX_use_PrivateKey_file(openssl->quic_ctx, openssl->private, SSL_FILETYPE_PEM) != 1 ||
        !SSL_CTX_check_private_key(openssl->quic_ctx)) {
        log_error("Openssl error: can't build the QUIC context\n");
        goto failed;
    }

    /* TLS 1.3 only, h3-only ALPN, and a ciphersuite list without CCM. */
    if (!quictls_configure_ctx(openssl->quic_ctx)) {
        log_error("Openssl error: can't configure the QUIC context\n");
        goto failed;
    }
#endif

    result = 0;

    failed:

    if (result == -1) {
        if (openssl->ctx != NULL) {
            SSL_CTX_free(openssl->ctx);
            openssl->ctx = NULL;
        }
        if (openssl->quic_ctx != NULL) {
            SSL_CTX_free(openssl->quic_ctx);
            openssl->quic_ctx = NULL;
        }
    }

    return result;
}

openssl_t* openssl_create(void) {
    openssl_t* openssl = malloc(sizeof * openssl);
    if (openssl == NULL) return NULL;

    openssl->fullchain = NULL;
    openssl->private = NULL;
    openssl->ciphers = NULL;
    openssl->ctx = NULL;
    openssl->quic_ctx = NULL;

    return openssl;
}

void openssl_free(openssl_t* openssl) {
    if (openssl == NULL) return;

    if (openssl->fullchain != NULL)
        free(openssl->fullchain);

    if (openssl->private != NULL)
        free(openssl->private);

    if (openssl->ciphers != NULL)
        free(openssl->ciphers);

    if (openssl->ctx != NULL)
        SSL_CTX_free(openssl->ctx);

    if (openssl->quic_ctx != NULL)
        SSL_CTX_free(openssl->quic_ctx);

    free(openssl);
}

void openssl_set_sni_callback(openssl_t* openssl, int (*callback)(SSL*, int*, void*)) {
    if (openssl == NULL || openssl->ctx == NULL) return;

    SSL_CTX_set_tlsext_servername_callback(openssl->ctx, callback);
}

/* SSL_read/SSL_write take int and their behavior with num=0 is undefined,
 * so clamp oversized buffers to INT_MAX (callers handle partial I/O) and
 * short-circuit empty ones. */
int openssl_read(SSL* ssl, void* buffer, size_t num) {
    if (num == 0) return 0;
    if (num > INT_MAX) num = INT_MAX;

    return SSL_read(ssl, buffer, (int)num);
}

/* Let the library take more than one TLS record from the socket per read.
 *
 * Without it every record costs two reads -- five bytes of length, then the
 * body -- and that showed as 1,5 reads per request against nginx's 0,16
 * (docs/http2/10 §7).
 *
 * The caller must drain: with read ahead the bytes sit in the library's buffer,
 * where epoll cannot see them, so a reader that stops before SSL_read says
 * WANT_READ leaves them unnoticed until the peer happens to send more. Only
 * enable it where the read loop runs to WANT_READ unconditionally. */
void openssl_set_read_ahead(SSL* ssl, int on) {
    if (ssl == NULL) return;

    SSL_set_read_ahead(ssl, on);
}

int openssl_write(SSL* ssl, const void* buffer, size_t num) {
    if (num == 0) return 0;
    if (num > INT_MAX) num = INT_MAX;

    const int result = SSL_write(ssl, buffer, (int)num);

#ifdef DEBUG
    if (result < 0)
        log_error("openssl_write: errno %d\n", errno);
#endif

    return result;
}

/* Классификация возврата SSL_read/SSL_write для неблокирующего I/O.
 * Вызывающий код передаёт ret (≤ 0 при ошибке); причина — через SSL_get_error,
 * поскольку errno для SSL_ERROR_WANT_READ/WANT_WRITE не определён. */
openssl_io_status_e openssl_io_status(SSL* ssl, int ret) {
    if (ret > 0)
        return OPENSSL_IO_OK;

    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
        return OPENSSL_IO_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
        return OPENSSL_IO_WANT_WRITE;
    case SSL_ERROR_ZERO_RETURN:
        /* peer послал close_notify — корректное закрытие. */
        return OPENSSL_IO_CLOSED;
    case SSL_ERROR_SYSCALL:
        /* ret == 0 → чистый EOF; ret < 0 → I/O-ошибка (см. errno). */
        return ret == 0 ? OPENSSL_IO_CLOSED : OPENSSL_IO_ERROR;
    case SSL_ERROR_SSL:
    default:
        return OPENSSL_IO_ERROR;
    }
}

int openssl_cipher_ok_for_http2(SSL* ssl) {
    if (ssl == NULL) return 0;

    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher == NULL) return 0;

    /* Not an AEAD: every CBC and RC4 suite of Appendix A fails here. */
    if (!SSL_CIPHER_is_aead(cipher)) return 0;

    /* Static RSA and static DH key exchange — the rest of Appendix A. TLS 1.3
     * reports NID_kx_any because the exchange is not part of the suite there;
     * it is always ephemeral, so it is accepted. */
    switch (SSL_CIPHER_get_kx_nid(cipher)) {
    case NID_kx_ecdhe:
    case NID_kx_dhe:
    case NID_kx_ecdhe_psk:
    case NID_kx_dhe_psk:
    case NID_kx_any:
        return 1;
    default:
        return 0;
    }
}
