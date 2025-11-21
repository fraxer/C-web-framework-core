#ifndef __HTTPCLIENT__
#define __HTTPCLIENT__

#include <stddef.h>
#include <openssl/ssl.h>

#include "route.h"
#include "connection_c.h"
#include "httpcommon.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "httpclientparser.h"

#define BUF_SIZE 16384

typedef enum client_redirect {
    CLIENTREDIRECT_NONE = 0,
    CLIENTREDIRECT_EXIST,
    CLIENTREDIRECT_ERROR,
    CLIENTREDIRECT_MANY_REDIRECTS
} client_redirect_e;

typedef struct httpclient {
    route_methods_e method;
    unsigned int use_ssl : 1;
    short int redirect_count;
    short int port;
    int timeout;
    char* host;
    SSL_CTX* ssl_ctx;
    connection_t* connection;
    httprequest_t* request;
    httpresponse_t* response;
    httpclientparser_t* parser;
    httpresponse_t*(*send)();
    const char*(*error)(struct httpclient*);
    void(*set_method)(struct httpclient*, route_methods_e);
    int(*set_url)(struct httpclient*, const char*);
    void(*set_timeout)(struct httpclient*, int);
    void(*free)(struct httpclient*);

    char* buffer;
    size_t buffer_size;
} httpclient_t;

httpclient_t* httpclient_init(route_methods_e method, const char* url, int timeout);

#endif