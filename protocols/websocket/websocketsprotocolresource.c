#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "appconfig.h"
#include "websocketsserverhandlers.h"
#include "websocketsprotocolresource.h"
#include "websocketsresponse.h"
#include "websocketsparser.h"
#include "websocketsswitch.h"
#include "queryparser.h"

static const size_t method_max_length = 6;

int websocketsrequest_get_resource(connection_t* connection, websocketsrequest_t* request);
void websockets_protocol_resource_reset(void*);
void websockets_protocol_resource_free(void*);
int websockets_protocol_resource_payload_parse(websocketsparser_t* parser, char* data, size_t size, int unmasking);
const char* websocketsrequest_query(websockets_protocol_resource_t*, const char*, int* ok);
query_t* websocketsrequest_last_query_item(websockets_protocol_resource_t*);
void websocketsrequest_query_free(query_t*);
int websocketsrequest_has_payload(websockets_protocol_resource_t*);
int websocketsparser_parse_method(websockets_protocol_resource_t*, char*, size_t);
int websocketsparser_parse_location(websockets_protocol_resource_t*, char*, size_t);
int websocketsparser_append_uri(websockets_protocol_resource_t*, const char*, size_t);
int websocketsparser_set_path(websockets_protocol_resource_t*, const char*, size_t);
int websocketsparser_set_query(websockets_protocol_resource_t*, const char*, size_t, size_t);
static ratelimiter_t* __ratelimiter_find(server_websockets_t* websockets_config, route_t* route);

websockets_protocol_t* websockets_protocol_resource_create(void) {
    websockets_protocol_resource_t* protocol = malloc(sizeof * protocol);
    if (protocol == NULL) return NULL;

    protocol->base.payload_parse = websockets_protocol_resource_payload_parse;
    protocol->base.get_resource = websocketsrequest_get_resource;
    protocol->base.reset = websockets_protocol_resource_reset;
    protocol->base.free = websockets_protocol_resource_free;
    protocol->get_payload = (char*(*)(websockets_protocol_resource_t*))websocketsrequest_payload;
    protocol->get_payload_file = (file_content_t(*)(websockets_protocol_resource_t*))websocketsrequest_payload_file;
    protocol->get_payload_json = (json_doc_t*(*)(websockets_protocol_resource_t*))websocketsrequest_payload_json;
    protocol->method = ROUTE_NONE;
    protocol->parser_stage = WSPROTRESOURCE_METHOD;
    protocol->uri_length = 0;
    protocol->path_length = 0;
    protocol->uri = NULL;
    protocol->path = NULL;
    protocol->query_ = NULL;
    protocol->get_query = websocketsrequest_query;

    websockets_protocol_init_payload((websockets_protocol_t*)protocol);

    return (websockets_protocol_t*)protocol;
}

void websockets_protocol_resource_reset(void* arg) {
    websockets_protocol_resource_t* protocol = arg;

    protocol->method = ROUTE_NONE;
    protocol->parser_stage = WSPROTRESOURCE_METHOD;
    protocol->uri_length = 0;
    protocol->path_length = 0;

    if (protocol->uri) free((void*)protocol->uri);
    protocol->uri = NULL;

    if (protocol->path) free((void*)protocol->path);
    protocol->path = NULL;

    websocketsrequest_query_free(protocol->query_);
    protocol->query_ = NULL;
}

void websockets_protocol_resource_free(void* arg) {
    websockets_protocol_resource_t* protocol = arg;

    websockets_protocol_resource_reset(protocol);
    free(protocol);
}

int websocketsrequest_get_resource(connection_t* connection, websocketsrequest_t* request) {
    websockets_protocol_resource_t* protocol = (websockets_protocol_resource_t*)request->protocol;

    if (protocol->method == ROUTE_NONE) return 0;
    if (protocol->path == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    for (route_t* route = ctx->server->websockets.route; route; route = route->next) {
        ratelimiter_t* ratelimiter = __ratelimiter_find(&ctx->server->websockets, route);

        if (route->is_primitive && route_compare_primitive(route, protocol->path, protocol->path_length)) {
            if (route->handler[protocol->method] == NULL) continue;

            if (!websockets_deferred_handler(connection, request, websockets_queue_request_handler, route->handler[protocol->method], websockets_queue_data_request_create, ratelimiter))
                return 0;

            return 1;
        }

        int vector_size = route->params_count > 0 ? route->params_count * 6 : 20 * 6;
        int vector[vector_size];

        // find resource by template
        int matches_count = pcre_exec(route->location, NULL, protocol->path, protocol->path_length, 0, 0, vector, vector_size);

        if (matches_count > 1) {
            /* Skip the route before materializing its params: a matching
             * route without a handler for this method used to append its
             * params to the chain and then continue to the next route,
             * polluting the params the dispatched route sees. */
            if (route->handler[protocol->method] == NULL) continue;

            int i = 1; // escape full string match

            query_t* last_query = websocketsrequest_last_query_item(protocol);

            for (route_param_t* param = route->param; param; param = param->next, i++) {
                size_t substring_length = vector[i * 2 + 1] - vector[i * 2];

                query_t* query = query_create(param->string, param->string_len, &protocol->path[vector[i * 2]], substring_length);

                if (query == NULL || query->key == NULL || query->value == NULL) {
                    query_free(query);
                    return 0;
                }

                /* The chain head must land in protocol->query_: with no query
                 * string in the location last_query starts NULL, and params
                 * linked only through the local tail were invisible to
                 * get_query and leaked (reset frees only protocol->query_). */
                if (last_query)
                    last_query->next = query;
                else
                    protocol->query_ = query;

                last_query = query;
            }

            if (!websockets_deferred_handler(connection, request, websockets_queue_request_handler, route->handler[protocol->method], websockets_queue_data_request_create, ratelimiter))
                return 0;

            return 1;
        }
        else if (matches_count == 1) {
            if (route->handler[protocol->method] == NULL)
                continue;

            if (!websockets_deferred_handler(connection, request, websockets_queue_request_handler, route->handler[protocol->method], websockets_queue_data_request_create, ratelimiter))
                return 0;

            return 1;
        }
    }

    return 0;
}

int websockets_protocol_resource_payload_parse(websocketsparser_t* parser, char* string, size_t length, int unmasking) {
    websocketsrequest_t* request = parser->request;
    websockets_protocol_resource_t* protocol = (websockets_protocol_resource_t*)request->protocol;

    int end_frame = parser->payload_saved_length >= parser->frame.payload_length;
    int end_data = end_frame && parser->frame.fin;

    size_t offset = 0;
    for (size_t i = 0; i < length; i++) {
        if (unmasking)
            string[i] ^= parser->frame.mask[parser->payload_index++ % 4];
        else if (protocol->parser_stage == WSPROTRESOURCE_DATA)
            break;

        char ch = string[i];
        int last_symbol = i + 1 == length;
        int last_data = end_data && last_symbol;

        switch (protocol->parser_stage) {
        case WSPROTRESOURCE_METHOD:
            {
                size_t s = bufferdata_writed(&parser->buf);
                if (s > method_max_length)
                    return 0;

                if (ch != ' ')
                    bufferdata_push(&parser->buf, ch);

                if (ch == ' ' || last_data) {
                    protocol->parser_stage = WSPROTRESOURCE_LOCATION;

                    bufferdata_complete(&parser->buf);

                    char* value = bufferdata_get(&parser->buf);
                    size_t value_length = bufferdata_writed(&parser->buf);
                    if (!websocketsparser_parse_method(protocol, value, value_length))
                        return 0;

                    bufferdata_reset(&parser->buf);
                }

                if (last_data)
                    return 1;
            }
            break;
        case WSPROTRESOURCE_LOCATION:
            {
                if (ch != ' ')
                    bufferdata_push(&parser->buf, ch);

                if (ch == ' ' || last_symbol) {
                    bufferdata_complete(&parser->buf);

                    char* value = bufferdata_get(&parser->buf);
                    size_t value_length = bufferdata_writed(&parser->buf);

                    if (websocketsparser_append_uri(protocol, value, value_length) == -1)
                        return 0;

                    bufferdata_reset(&parser->buf);
                }

                if (ch == ' ' || last_data) {
                    protocol->parser_stage = WSPROTRESOURCE_DATA;
                    offset = i + 1;

                    if (!websocketsparser_parse_location(protocol, protocol->uri, protocol->uri_length))
                        return 0;
                }

                if (last_data)
                    return 1;
            }
            break;
        case WSPROTRESOURCE_DATA:
            break;
        }
    }

    if (protocol->parser_stage == WSPROTRESOURCE_DATA) {
        /* A chunk that ends exactly at the location-terminating space has no
         * payload bytes yet: write(fd, p, 0) returns 0, which the write error
         * check would misread and kill a legitimate fragmented request. */
        const size_t remaining = length - offset;
        if (remaining == 0)
            return 1;

        if (!websocketsrequest_has_payload(protocol))
            return 0;

        if (!websockets_create_tmpfile(request->protocol, env()->main.tmp))
            return 0;

        /* A failed lseek returns -1, which the unsigned comparison below
         * would fold into a passing value and wave past the body-size limit. */
        off_t payloadlength = lseek(request->protocol->payload.fd, 0, SEEK_END);
        if (payloadlength < 0)
            return 0;

        /* Only the payload bytes count against the limit: measuring the whole
         * chunk also billed the method and location prefix on the first chunk. */
        if ((size_t)payloadlength + remaining > env()->main.client_max_body_size)
            return 0;

        /* A single write may legally be short (EINTR, ENOSPC, rlimit);
         * accepting a partial write here silently truncated the message
         * handed to the handler, so write until every byte is on disk. */
        size_t written = 0;
        while (written < remaining) {
            const ssize_t r = write(request->protocol->payload.fd, &string[offset + written], remaining - written);

            if (r < 0) {
                if (errno == EINTR)
                    continue;
                return 0;
            }
            if (r == 0)
                return 0;

            written += (size_t)r;
        }

        lseek(request->protocol->payload.fd, 0, SEEK_SET);
    }

    return 1;
}

const char* websocketsrequest_query(websockets_protocol_resource_t* protocol, const char* key, int* ok) {
    if (ok != NULL)
        *ok = 0;

    if (key == NULL) return NULL;

    query_t* query = protocol->query_;

    while (query) {
        if (strcmp(key, query->key) == 0) {
            if (ok != NULL)
                *ok = 1;
            return query->value;
        }

        query = query->next;
    }

    return NULL;
}

query_t* websocketsrequest_last_query_item(websockets_protocol_resource_t* protocol) {
    query_t* query = protocol->query_;

    while (query) {
        if (query->next == NULL)
            return query;

        query = query->next;
    }

    return NULL;
}

void websocketsrequest_query_free(query_t* query) {
    while (query != NULL) {
        query_t* next = query->next;

        query_free(query);

        query = next;
    }
}

int websocketsparser_parse_method(websockets_protocol_resource_t* protocol, char* string, size_t length) {
    if (length == 3 && string[0] == 'G' && string[1] == 'E' && string[2] == 'T')
        protocol->method = ROUTE_GET;
    else if (length == 4 && string[0] == 'P' && string[1] == 'O' && string[2] == 'S' && string[3] == 'T')
        protocol->method = ROUTE_POST;
    else if (length == 5 && string[0] == 'P' && string[1] == 'A' && string[2] == 'T' && string[3] == 'C' && string[4] == 'H')
        protocol->method = ROUTE_PATCH;
    else if (length == 6 && string[0] == 'D' && string[1] == 'E' && string[2] == 'L' && string[3] == 'E' && string[4] == 'T' && string[5] == 'E')
        protocol->method = ROUTE_DELETE;
    else
        return 0;

    return 1;
}

int websocketsparser_parse_location(websockets_protocol_resource_t* protocol, char* string, size_t length) {
    if (string[0] != '/') return 0;

    size_t path_point_end = 0;
    for (size_t pos = 0; pos < length; pos++) {
        switch (string[pos]) {
        case '?':
            path_point_end = pos;

            /* set_query reports failure as -1; returning it as-is leaked a
             * truthy value to the caller (which only treats 0 as failure), so
             * a failed query parse continued with no path set at all. */
            if (websocketsparser_set_query(protocol, string, length, pos) != 0)
                return 0;

            goto next;
        case '#':
            path_point_end = pos;
            goto next;
        }
    }

    next:

    if (path_point_end == 0) path_point_end = length;

    return websocketsparser_set_path(protocol, string, path_point_end);
}

int websocketsparser_append_uri(websockets_protocol_resource_t* protocol, const char* string, size_t length) {
    /* The caller treats only -1 as an error, so reporting a failed realloc
     * as 0 silently dropped this chunk from the middle of the uri. */
    char* data = realloc(protocol->uri, protocol->uri_length + length + 1);
    if (data == NULL) return -1;

    protocol->uri = data;

    memcpy(&protocol->uri[protocol->uri_length], string, length);

    protocol->uri_length += length;
    protocol->uri[protocol->uri_length] = 0;

    if (protocol->uri[0] != '/') return -1;

    return 0;
}

int websocketsparser_set_path(websockets_protocol_resource_t* protocol, const char* string, size_t length) {
    if (string[0] != '/') return 0;

    size_t decoded_length = length;
    protocol->path = urldecodel(string, length, &decoded_length);
    if (protocol->path == NULL) return 0;

    protocol->path_length = decoded_length;

    if (is_path_traversal(protocol->path, protocol->path_length))
        return 0;

    return 1;
}

int websocketsparser_set_query(websockets_protocol_resource_t* protocol, const char* string, size_t length, size_t pos) {
    query_t* first_query = NULL;
    query_t* last_query = NULL;

    queryparser_result_t result = queryparser_parse(
        string,
        length,
        pos + 1,  // Start after '?'
        NULL,
        NULL,  // No append callback needed for WebSockets
        &first_query,
        &last_query
    );

    if (result != QUERYPARSER_OK)
        return -1;

    protocol->query_ = first_query;

    return 0;
}

int websocketsrequest_has_payload(websockets_protocol_resource_t* protocol) {
    switch (protocol->method) {
    case ROUTE_POST:
    case ROUTE_PATCH:
        return 1;
    default:
        break;
    }

    return 0;
}


int set_websockets_resource(connection_t* connection, void* data) {
    /* Create the replacement parser before touching connection state: the
     * caller (connection_after_write) ignores this function's result, so
     * installing the websocket guards or freeing the old parser first left a
     * connection whose guard read dereferences ctx->parser == NULL. On
     * failure the connection must keep its previous protocol intact. */
    websocketsparser_t* parser = websocketsparser_create(connection, websockets_protocol_resource_create);
    if (parser == NULL)
        return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->parser != NULL) {
        requestparser_t* old_parser = ctx->parser;
        old_parser->free(old_parser);
    }

    ctx->parser = parser;
    connection->read = websockets_guard_read;
    connection->write = websockets_guard_write;

    /* Initialize deflate if negotiated during handshake */
    ws_handshake_data_t* handshake_data = data;
    if (handshake_data != NULL && handshake_data->deflate_enabled) {
        parser->ws_deflate.config = handshake_data->deflate_config;
        if (ws_deflate_start(&parser->ws_deflate)) {
            parser->ws_deflate_enabled = 1;
        }
        else
            /* Degrade, but not silently: the 101 response already advertised
             * permessage-deflate, so every compressed message from this client
             * will now be rejected as a bad request. */
            log_error("set_websockets_resource: ws_deflate_start failed, compressed frames will be rejected\n");
    }

    return 1;
}

ratelimiter_t* __ratelimiter_find(server_websockets_t* websockets_config, route_t* route) {
    if (route->ratelimiter != NULL) return route->ratelimiter;

    return websockets_config->ratelimiter;
}
