#ifndef __HTTP1REQUESTPARSER__
#define __HTTP1REQUESTPARSER__

#include "connection_s.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "bufferdata.h"

typedef enum httprequestparser_stage {
    HTTP1REQUESTPARSER_METHOD = 0,
    HTTP1REQUESTPARSER_URI,
    HTTP1REQUESTPARSER_PROTOCOL,
    HTTP1REQUESTPARSER_NEWLINE1,
    HTTP1REQUESTPARSER_HEADER_KEY,
    HTTP1REQUESTPARSER_HEADER_SPACE,
    HTTP1REQUESTPARSER_HEADER_VALUE,
    HTTP1REQUESTPARSER_NEWLINE2,
    HTTP1REQUESTPARSER_NEWLINE3,
    HTTP1REQUESTPARSER_PAYLOAD
} httprequestparser_stage_e;

typedef struct httprequestparser {
    requestparser_t base;
    /* Receive deadlines, stamped on the connection's receive clock
     * (connection_recv_stamp) -- the clock __receive_timeout checks them on.
     * Not wall time: request timing reads started_wall_ms instead. */
    uint64_t header_started_ms;
    uint64_t body_started_ms;
    uint64_t body_progress_ms;
    /* Wall time of the request's first byte, for the access log and the slow
     * request threshold (request->started_ms). */
    uint64_t started_wall_ms;
    unsigned timeout_reported;
    timeout_policy_t timeout_policy;
    char* buffer;
    bufferdata_t buf;
    size_t bytes_readed;
    size_t pos_start;
    size_t pos;
    connection_t* connection;
    httprequest_t* request;
    httprequestparser_stage_e stage;
    int host_found;
    int host_header_seen;         // Flag to detect duplicate Host header
    int content_length_found;     // Flag to detect duplicate Content-Length
    int transfer_encoding_found;  // Flag to detect Transfer-Encoding header
    size_t headers_count;         // Counter to limit number of headers
    size_t content_length;
    size_t content_saved_length;
    /* The request headers are in, a body is announced, and the client said it
     * would wait for a 100 (Continue) before sending it (RFC 9110 §10.1.1) —
     * docs/http2/10, T.2. Only a record that the interim response is due: the
     * parser reads bytes, it does not write them. The read path acts on it and
     * clears it. */
    int expect_continue;
} httprequestparser_t;
_Static_assert(offsetof(httprequestparser_t, base) == 0, "parser interface must stay first");

httprequestparser_t* httpparser_create(connection_t* connection);
void httpparser_init(httprequestparser_t* parser, connection_t* connection);
void httpparser_free(void* arg);
void httpparser_reset(httprequestparser_t*);
int httpparser_run(httprequestparser_t* parser);
void httpparser_set_bytes_readed(httprequestparser_t*, size_t);
void httpparser_prepare_continue(httprequestparser_t* parser);
int httpparser_set_uri(httprequest_t*, const char*, size_t);
void httpparser_append_query(httprequest_t*, query_t*);
http_ranges_t* httpparser_parse_range(char*, size_t);
/* Pick the virtual server matching an authority (Host in h1.1, :authority in
 * h2) and store it on the connection context. Returns HTTP1PARSER_CONTINUE on
 * success, HTTP1PARSER_BAD_REQUEST / HTTP1PARSER_HOST_NOT_FOUND otherwise. */
int httpparser_select_server(connection_t* connection, const char* host, size_t host_length);

#endif
