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

// Forward declarations
struct mpxapi;
struct appconfig;

// Async callback typedef
typedef void(*httpclient_callback_t)(httpresponse_t* response, void* userdata);

// Состояния async HTTP клиента
typedef enum httpclient_async_state {
    ASYNC_STATE_INIT = 0,
    ASYNC_STATE_CONNECTING,
    ASYNC_STATE_TLS_HANDSHAKE,
    ASYNC_STATE_WRITING_REQUEST,
    ASYNC_STATE_READING_RESPONSE,
    ASYNC_STATE_COMPLETE,
    ASYNC_STATE_ERROR
} httpclient_async_state_e;

// Контекст для async операций
typedef struct httpclient_async_ctx {
    httpclient_callback_t callback;       // User callback
    void* userdata;                        // User data
    httpclient_async_state_e state;        // Текущее состояние

    struct mpxapi* api;                    // Ссылка на epoll API
    struct appconfig* appconfig;           // Ссылка на appconfig

    int timeout_ms;                        // Таймаут в миллисекундах
    uint64_t start_time_ms;                // Время начала для timeout

    char* write_buffer;                    // Буфер для отправки request
    size_t write_buffer_size;
    size_t write_buffer_pos;

    unsigned int registered_in_epoll:1;    // Зарегистрирован в epoll
    unsigned int write_completed:1;        // Запрос отправлен
    unsigned int read_completed:1;         // Ответ получен
    unsigned int is_self_invocation:1;     // Self-invocation detected
} httpclient_async_ctx_t;

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

    // Async поля
    httpclient_async_ctx_t* async_ctx;    // NULL для синхронного режима
    int(*send_async)(struct httpclient*, httpclient_callback_t, void*, struct mpxapi*, struct appconfig*);
} httpclient_t;

httpclient_t* httpclient_init(route_methods_e method, const char* url, int timeout);

#endif