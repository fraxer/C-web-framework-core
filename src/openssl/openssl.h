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
int openssl_write(SSL*, const void*, size_t);
openssl_io_status_e openssl_io_status(SSL*, int ret);

#endif