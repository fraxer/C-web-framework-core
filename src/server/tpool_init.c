/**
 * Thread pool initialization for server.
 * Registers all pool types with their sizes.
 *
 * Call tpool_init_defaults() once at server startup, before creating worker threads.
 * Call tpool_thread_init() at the start of each worker thread.
 * Call tpool_thread_destroy() when thread exits.
 */

#include "threadpool.h"
#include "connection.h"
#include "connection_s.h"
#include "cqueue.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "httpcommon.h"
#include "queryparser.h"

/* Default max cached objects per thread per type */
#define DEFAULT_MAX_CONNECTION           64
#define DEFAULT_MAX_CONNECTION_CTX       64
#define DEFAULT_MAX_CQUEUE              128
#define DEFAULT_MAX_HTTPREQUEST          64
#define DEFAULT_MAX_HTTPRESPONSE         64
#define DEFAULT_MAX_HTTP_HEADER         512   /* Many headers per request */
#define DEFAULT_MAX_CQUEUE_ITEM        1024   /* High frequency */
#define DEFAULT_MAX_QUERY               256
#define DEFAULT_MAX_PAYLOADPART         128
#define DEFAULT_MAX_PAYLOADFIELD        128

void tpool_init_defaults(void) {
    tpool_register(POOL_CONNECTION,
                   sizeof(connection_t),
                   DEFAULT_MAX_CONNECTION);

    tpool_register(POOL_CONNECTION_SERVER_CTX,
                   sizeof(connection_server_ctx_t),
                   DEFAULT_MAX_CONNECTION_CTX);

    tpool_register(POOL_CQUEUE,
                   sizeof(cqueue_t),
                   DEFAULT_MAX_CQUEUE);

    tpool_register(POOL_HTTPREQUEST,
                   sizeof(httprequest_t),
                   DEFAULT_MAX_HTTPREQUEST);

    tpool_register(POOL_HTTPRESPONSE,
                   sizeof(httpresponse_t),
                   DEFAULT_MAX_HTTPRESPONSE);

    tpool_register(POOL_HTTP_HEADER,
                   sizeof(http_header_t),
                   DEFAULT_MAX_HTTP_HEADER);

    tpool_register(POOL_CQUEUE_ITEM,
                   sizeof(cqueue_item_t),
                   DEFAULT_MAX_CQUEUE_ITEM);

    tpool_register(POOL_QUERY,
                   sizeof(query_t),
                   DEFAULT_MAX_QUERY);

    tpool_register(POOL_HTTP_PAYLOADPART,
                   sizeof(http_payloadpart_t),
                   DEFAULT_MAX_PAYLOADPART);

    tpool_register(POOL_HTTP_PAYLOADFIELD,
                   sizeof(http_payloadfield_t),
                   DEFAULT_MAX_PAYLOADFIELD);

    tpool_global_init();
}
