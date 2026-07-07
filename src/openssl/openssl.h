#ifndef __OPENSSL__
#define __OPENSSL__

#include <openssl/ssl.h>
#include <openssl/err.h>

#define TLS_ERROR_ALLOC_SSL "Tls error: can't allocate a new ssl object\n"
#define TLS_ERROR_SET_SSL_FD "Tls error: can't attach fd to ssl\n"

typedef struct openssl {
    char* fullchain;
    char* private;
    char* ciphers;
    SSL_CTX* ctx;
} openssl_t;

int openssl_init(openssl_t* openssl);
openssl_t* openssl_create(void);
void openssl_free(openssl_t* openssl);
void openssl_set_sni_callback(openssl_t* openssl, int (*callback)(SSL*, int*, void*));
int openssl_read(SSL*, void*, size_t);
int openssl_write(SSL*, const void*, size_t);

#endif